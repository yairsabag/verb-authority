"""Fail-closed Pydantic AI 2.35 integration for Verb Authority.

This first adapter is deliberately narrow.  It supports local synchronous
``tool_plain`` functions whose authoritative implementation is registered in a
:class:`verb_authority.Registry`.  Pydantic AI provides schema generation and
argument validation; :class:`verb_authority.GuardedToolRunner` performs the
actual invocation.  The Pydantic execution handler is never called.

The capability covers the Agent's sealed direct function tools. Runtime
toolsets, provider-native tools, and per-run capabilities are rejected before
their setup hooks can execute outside the local capability boundary.
"""

from __future__ import annotations

import ast
import asyncio
import hashlib
import inspect
import json
import math
import threading
import weakref
from collections.abc import Callable, Mapping
from contextlib import AsyncExitStack, asynccontextmanager, contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from types import (
    BuiltinMethodType,
    FunctionType,
    GenericAlias,
    MappingProxyType,
    MethodType,
    SimpleNamespace,
)
from typing import Any, Literal, get_args, get_origin

try:
    import anyio
    import pydantic
    import pydantic_ai
    import pydantic_core
    from pydantic_ai import (
        Agent,
        DeferredToolResults,
        RunContext,
        Tool as PydanticTool,
        ToolApproved,
        ToolDenied,
    )
    from pydantic_ai.agent import _AgentFunctionToolset
    from pydantic_ai._cancel import (
        RunCancellation,
        provide_run_binding,
        take_run_binding,
    )
    from pydantic_ai._agent_graph import (
        CallToolsNode,
        GraphAgentDeps,
        UserPromptNode,
    )
    from pydantic_ai.capabilities import (
        AbstractCapability,
        CapabilityOrdering,
        CombinedCapability,
        ToolSearch,
    )
    from pydantic_ai.capabilities._pending_messages import (
        PendingMessageDrainCapability,
    )
    from pydantic_ai._function_schema import FunctionSchema
    from pydantic_ai.exceptions import (
        ApprovalRequired,
        CallDeferred,
        ToolFailed,
        UserError,
    )
    from pydantic_ai.messages import RetryPromptPart, ToolCallPart, ToolReturnPart
    from pydantic_ai.models import ModelRequestContext
    from pydantic_ai.run import AgentRun
    from pydantic_ai.tool_manager import ToolManager, _ValidationDeferral
    from pydantic_ai.toolsets._tool_search import ToolSearchToolset
    from pydantic_ai.toolsets.combined import CombinedToolset, _CombinedToolsetTool
    from pydantic_ai.toolsets.function import FunctionToolsetTool
    from pydantic_ai.toolsets.prepared import PreparedToolset
    from pydantic_ai.tools import ToolDefinition
    from pydantic.plugin._schema_validator import PluggableSchemaValidator
    from pydantic_core import SchemaValidator
    from pydantic_graph import GraphRun
except ImportError as exc:  # pragma: no cover - exercised by installed-wheel smoke
    raise ImportError(
        "verb_authority_pydantic requires pydantic-ai-slim==2.35.0; "
        "install 'verb-authority[pydantic]'"
    ) from exc

if (
    getattr(pydantic_ai, "__version__", None) != "2.35.0"
    or getattr(pydantic, "__version__", None) != "2.13.4"
    or getattr(pydantic_core, "__version__", None) != "2.46.4"
):
    raise ImportError(
        "verb_authority_pydantic supports only "
        "pydantic-ai-slim==2.35.0, pydantic==2.13.4, and "
        "pydantic-core==2.46.4; found "
        f"pydantic-ai={getattr(pydantic_ai, '__version__', None)!r}, "
        f"pydantic={getattr(pydantic, '__version__', None)!r}, "
        f"pydantic-core={getattr(pydantic_core, '__version__', None)!r}"
    )

import verb_authority as authority
from verb_authority import (
    ConfirmationRequest,
    GuardedToolRunner,
    PolicySet,
    ProvenanceLedger,
    Registry,
    ResolutionStatus,
    TrustedResolver,
)


_ADAPTER_VERSION = 1
_MAX_PENDING_APPROVALS = 256
_MAX_RUN_RETRIES = 256
_MAX_TOOL_CALL_ID_BYTES = 256
_SCHEMA_TOOL_METADATA_KEY = "verb_authority_schema_tool_v1"
_SCHEMA_TOOL_MARKER = object()
_SCHEMA_CALLABLE_MARKER = "__verb_authority_schema_tool_v1__"
_SUPPORTED_SCHEMA_KEYS = frozenset(
    {
        "$defs",
        "additionalProperties",
        "description",
        "properties",
        "required",
        "title",
        "type",
    }
)
_JSON_SCHEMA_TYPES = {
    "array": "array",
    "boolean": "boolean",
    "email": "string",
    "integer": "integer",
    "number": "number",
    "object": "object",
    "string": "string",
    "uri": "string",
}

# These are the executable lifecycle entry points on AbstractCapability in the
# pinned Pydantic AI release.  Instance attributes with any of these names can
# shadow class methods without changing the capability's type, so they are
# always rejected before a capability tree is allowed to run.
_CAPABILITY_HOOK_NAMES = frozenset(
    {
        "apply",
        "get_ordering",
        "for_agent",
        "for_run",
        "_validate_runtime_capabilities",
        "get_instructions",
        "get_description",
        "get_model_settings",
        "get_model",
        "resolve_model_id",
        "get_toolset",
        "get_native_tools",
        "get_wrapper_toolset",
        "prepare_tools",
        "prepare_output_tools",
        "before_run",
        "after_run",
        "wrap_run",
        "on_run_error",
        "before_node_run",
        "after_node_run",
        "wrap_node_run",
        "on_node_run_error",
        "wrap_run_event_stream",
        "before_model_request",
        "after_model_request",
        "wrap_model_request",
        "on_model_request_error",
        "before_tool_validate",
        "after_tool_validate",
        "wrap_tool_validate",
        "on_tool_validate_error",
        "before_tool_execute",
        "after_tool_execute",
        "wrap_tool_execute",
        "on_tool_execute_error",
        "before_output_validate",
        "after_output_validate",
        "wrap_output_validate",
        "on_output_validate_error",
        "before_output_process",
        "after_output_process",
        "wrap_output_process",
        "on_output_process_error",
        "handle_deferred_tool_calls",
        "prefix_tools",
    }
)


def _reject_capability_instance_hooks(value: Any) -> None:
    state = vars(value)
    shadows = sorted(key for key in state if key in _CAPABILITY_HOOK_NAMES)
    if shadows:
        raise PydanticAuthorityConfigurationError(
            "a Pydantic capability gained instance-level lifecycle hooks: "
            + ", ".join(shadows)
        )


def _bounded_tool_call_id(value: Any) -> bool:
    if (
        type(value) is not str
        or not value
        or len(value) > _MAX_TOOL_CALL_ID_BYTES
    ):
        return False
    try:
        return len(value.encode("utf-8")) <= _MAX_TOOL_CALL_ID_BYTES
    except UnicodeEncodeError:
        return False


class PydanticAuthorityConfigurationError(ValueError):
    """The application supplied an unsupported or inconsistent integration."""


class PydanticAuthorityResolutionError(ValueError):
    """A model-selected key did not resolve to one trusted catalog value."""


@dataclass(frozen=True, slots=True, repr=False)
class _SchemaToolWitness:
    """Identity-bound proof created only after the inert Tool exists."""

    secret: object
    tool: Any
    function: FunctionType
    function_schema: FunctionSchema
    validator: Any
    core_validator: SchemaValidator
    baseline: tuple[Any, ...]


_SAFE_ANNOTATION_NAMES = {
    "bool": bool,
    "float": float,
    "int": int,
    "str": str,
    "None": type(None),
}
_LITERAL_ALIAS_TYPE = type(Literal["verb-authority-literal-witness"])


def _literal_scalar(value: Any) -> Any:
    """Return one inert, exact JSON scalar accepted in ``Literal``."""

    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float and math.isfinite(value):
        return value
    raise PydanticAuthorityConfigurationError(
        "Literal schema values must be finite exact JSON scalars"
    )


def _literal_values(values: tuple[Any, ...] | list[Any]) -> tuple[Any, ...]:
    """Validate a non-empty Literal without Python bool/number aliasing."""

    if not values:
        raise PydanticAuthorityConfigurationError(
            "Literal schema annotations cannot be empty"
        )
    accepted: list[Any] = []
    for candidate in values:
        scalar = _literal_scalar(candidate)
        for previous in accepted:
            if scalar == previous:
                if type(scalar) is type(previous):
                    reason = "duplicate values"
                else:
                    reason = "bool/number or numeric equality collisions"
                raise PydanticAuthorityConfigurationError(
                    f"Literal schema annotations cannot contain {reason}"
                )
        accepted.append(scalar)
    return tuple(accepted)


def _literal_annotation(values: tuple[Any, ...] | list[Any]) -> Any:
    """Build a typing Literal only after validating its inert constants."""

    accepted = _literal_values(values)
    return Literal.__getitem__(accepted)


def _literal_ast_scalar(node: ast.AST) -> Any:
    """Read one scalar constant without evaluating future-annotation text."""

    if isinstance(node, ast.Constant):
        return _literal_scalar(node.value)
    if (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, (ast.UAdd, ast.USub))
        and isinstance(node.operand, ast.Constant)
        and type(node.operand.value) in (int, float)
        and type(node.operand.value) is not bool
    ):
        value = node.operand.value
        return _literal_scalar(value if isinstance(node.op, ast.UAdd) else -value)
    raise PydanticAuthorityConfigurationError(
        "Literal schema values must be finite exact JSON scalar constants"
    )


def _is_literal_ast_target(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Name)
        and node.id == "Literal"
    ) or (
        isinstance(node, ast.Attribute)
        and node.attr == "Literal"
        and isinstance(node.value, ast.Name)
        and node.value.id == "typing"
    )


def _safe_annotation_ast(node: ast.AST, *, depth: int = 0) -> Any:
    if depth > 8:
        raise PydanticAuthorityConfigurationError(
            "schema annotations exceed the supported nesting depth"
        )
    if isinstance(node, ast.Name) and node.id in _SAFE_ANNOTATION_NAMES:
        return _SAFE_ANNOTATION_NAMES[node.id]
    if isinstance(node, ast.Constant) and node.value is None:
        return type(None)
    if isinstance(node, ast.Subscript):
        if _is_literal_ast_target(node.value):
            elements = (
                list(node.slice.elts)
                if isinstance(node.slice, ast.Tuple)
                else [node.slice]
            )
            return _literal_annotation(
                [_literal_ast_scalar(element) for element in elements]
            )
        if not isinstance(node.value, ast.Name):
            raise PydanticAuthorityConfigurationError(
                "schema annotations must use only inert built-in containers "
                "or typing.Literal with exact JSON scalar constants"
            )
        if node.value.id == "list":
            return list[_safe_annotation_ast(node.slice, depth=depth + 1)]
        if node.value.id == "dict" and isinstance(node.slice, ast.Tuple):
            if len(node.slice.elts) == 2:
                key = _safe_annotation_ast(node.slice.elts[0], depth=depth + 1)
                value = _safe_annotation_ast(node.slice.elts[1], depth=depth + 1)
                if key is str:
                    return dict[str, value]
    raise PydanticAuthorityConfigurationError(
        "schema annotations must use only str, int, float, bool, Literal[...] "
        "with exact JSON scalars, list[T], or dict[str, T]"
    )


def _safe_schema_annotation(annotation: Any, *, allow_none: bool) -> Any:
    if type(annotation) is str:
        try:
            node = ast.parse(annotation, mode="eval").body
        except (SyntaxError, ValueError) as exc:
            raise PydanticAuthorityConfigurationError(
                "schema annotations must be simple, non-executable type syntax"
            ) from exc
        resolved = _safe_annotation_ast(node)
    elif any(
        annotation is candidate
        for candidate in (str, int, float, bool, type(None), None)
    ):
        resolved = type(None) if annotation is None else annotation
    elif (
        type(annotation) is _LITERAL_ALIAS_TYPE
        and get_origin(annotation) is Literal
    ):
        resolved = _literal_annotation(list(get_args(annotation)))
    elif type(annotation) is GenericAlias:
        origin = get_origin(annotation)
        arguments = get_args(annotation)
        if origin is list and len(arguments) == 1:
            resolved = list[
                _safe_schema_annotation(arguments[0], allow_none=False)
            ]
        elif origin is dict and len(arguments) == 2 and arguments[0] is str:
            resolved = dict[
                str,
                _safe_schema_annotation(arguments[1], allow_none=False),
            ]
        else:
            raise PydanticAuthorityConfigurationError(
                "schema annotations must use only exact plain JSON types; "
                "Literal[...] with exact JSON scalars is supported, while "
                "Annotated validators, unions, models, enums, and custom "
                "classes are unsupported"
            )
    else:
        raise PydanticAuthorityConfigurationError(
            "schema annotations must use only exact plain JSON types; "
            "Literal[...] with exact JSON scalars is supported, while "
            "Annotated validators, unions, models, enums, and custom "
            "classes are unsupported"
        )
    if resolved is type(None) and not allow_none:
        raise PydanticAuthorityConfigurationError(
            "tool parameters cannot use None as their schema type"
        )
    return resolved


def _is_plain_json_default(
    value: Any,
    *,
    depth: int = 0,
    seen: frozenset[int] = frozenset(),
) -> bool:
    del depth, seen
    if value is None or type(value) in (str, bool, int):
        return True
    if type(value) is float:
        return math.isfinite(value)
    # Containers remain mutable aliases inside Pydantic's compiled default
    # validator. Even a detached copy would add an unaudited deepcopy path, so
    # this beta supports immutable JSON scalar defaults only.
    return False


def _schema_only_callable(schema_source: Callable[..., Any]) -> Callable[..., Any]:
    """Copy one plain function's schema without retaining its implementation."""

    if type(schema_source) is not FunctionType:
        raise PydanticAuthorityConfigurationError(
            "pydantic_schema_tool requires a plain Python schema function"
        )
    if inspect.iscoroutinefunction(schema_source) or inspect.isasyncgenfunction(
        schema_source
    ):
        raise PydanticAuthorityConfigurationError(
            "pydantic_schema_tool requires a synchronous schema function"
        )
    try:
        signature = inspect.signature(schema_source)
    except Exception as exc:
        raise PydanticAuthorityConfigurationError(
            "could not resolve the schema function signature"
        ) from exc

    parameters = []
    hints: dict[str, Any] = {}
    for name, parameter in signature.parameters.items():
        if parameter.kind not in (
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        ):
            raise PydanticAuthorityConfigurationError(
                "schema functions cannot use positional-only, variadic, or "
                "keyword-capture parameters"
            )
        if parameter.annotation is inspect.Parameter.empty:
            raise PydanticAuthorityConfigurationError(
                f"schema parameter {name!r} must have an explicit safe annotation"
            )
        annotation = _safe_schema_annotation(
            parameter.annotation,
            allow_none=False,
        )
        if (
            parameter.default is not inspect.Parameter.empty
            and not _is_plain_json_default(parameter.default)
        ):
            raise PydanticAuthorityConfigurationError(
                f"schema parameter {name!r} has an executable or non-JSON "
                "default; FieldInfo and default factories are unsupported"
            )
        hints[name] = annotation
        parameters.append(parameter.replace(annotation=annotation))

    if signature.return_annotation is inspect.Signature.empty:
        return_annotation = inspect.Signature.empty
    else:
        return_annotation = _safe_schema_annotation(
            signature.return_annotation,
            allow_none=True,
        )
        hints["return"] = return_annotation
    copied_signature = signature.replace(
        parameters=parameters,
        return_annotation=return_annotation,
    )
    tool_name = schema_source.__name__
    tool_doc = schema_source.__doc__

    def inert(*args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        raise PydanticAuthorityConfigurationError(
            "Pydantic attempted to execute a schema-only Verb Authority tool; "
            "the protected Registry path is unavailable"
        )

    inert.__name__ = tool_name
    inert.__qualname__ = f"verb_authority_schema_only_{tool_name}"
    inert.__doc__ = tool_doc
    inert.__annotations__ = dict(hints)
    inert.__signature__ = copied_signature  # type: ignore[attr-defined]
    setattr(inert, _SCHEMA_CALLABLE_MARKER, _SCHEMA_TOOL_MARKER)
    return inert


def pydantic_schema_tool(
    schema_source: Callable[..., Any],
    *,
    name: str | None = None,
    description: str | None = None,
    strict: bool | None = None,
    sequential: bool = False,
) -> PydanticTool[Any]:
    """Create an inert Pydantic tool used only for schema generation.

    The returned object never retains ``schema_source``.  Both Pydantic
    execution references point at a fresh fail-closed callable; the actual
    implementation must live only in the Verb Authority Registry.
    """

    if name is not None and (type(name) is not str or not name):
        raise PydanticAuthorityConfigurationError(
            "pydantic_schema_tool name must be a non-empty plain string"
        )
    if description is not None and type(description) is not str:
        raise PydanticAuthorityConfigurationError(
            "pydantic_schema_tool description must be a plain string"
        )
    if strict is not None and type(strict) is not bool:
        raise PydanticAuthorityConfigurationError(
            "pydantic_schema_tool strict must be a plain boolean"
        )
    if type(sequential) is not bool:
        raise PydanticAuthorityConfigurationError(
            "pydantic_schema_tool sequential must be a plain boolean"
        )

    inert = _schema_only_callable(schema_source)
    tool = PydanticTool(
        inert,
        takes_ctx=False,
        name=name,
        description=description,
        prepare=None,
        args_validator=None,
        strict=strict,
        sequential=sequential,
        requires_approval=False,
        metadata={},
        timeout=None,
        defer_loading=False,
        include_return_schema=False,
    )
    function_schema = tool.function_schema
    validator = function_schema.validator
    if type(function_schema) is not FunctionSchema:
        raise PydanticAuthorityConfigurationError(
            "Pydantic did not build the pinned plain schema validator"
        )
    core_validator = _core_schema_validator(validator)
    provisional_witness = _SchemaToolWitness(
        secret=_SCHEMA_TOOL_MARKER,
        tool=tool,
        function=inert,
        function_schema=function_schema,
        validator=validator,
        core_validator=core_validator,
        baseline=(),
    )
    tool.metadata = {_SCHEMA_TOOL_METADATA_KEY: provisional_witness}
    provisional_seal = _pydantic_tool_seal(tool)
    baseline = (provisional_seal[0], *provisional_seal[2:])
    witness = _SchemaToolWitness(
        secret=_SCHEMA_TOOL_MARKER,
        tool=tool,
        function=inert,
        function_schema=function_schema,
        validator=validator,
        core_validator=core_validator,
        baseline=baseline,
    )
    tool.metadata = {_SCHEMA_TOOL_METADATA_KEY: witness}
    if (
        tool.function is not inert
        or function_schema.function is not inert
        or getattr(inert, _SCHEMA_CALLABLE_MARKER, None) is not _SCHEMA_TOOL_MARKER
    ):
        raise PydanticAuthorityConfigurationError(
            "Pydantic did not preserve the inert schema-tool boundary"
        )
    _pydantic_tool_seal(tool)
    return tool


def _is_pydantic_schema_tool(value: Any) -> bool:
    if type(value) is not PydanticTool:
        return False
    metadata = value.metadata
    function = value.function
    function_schema = value.function_schema
    if (
        type(metadata) is not dict
        or len(metadata) != 1
        or type(function) is not FunctionType
        or type(function_schema) is not FunctionSchema
    ):
        return False
    try:
        core_validator = _core_schema_validator(function_schema.validator)
    except PydanticAuthorityConfigurationError:
        return False
    key = next(iter(metadata))
    if type(key) is not str or key != _SCHEMA_TOOL_METADATA_KEY:
        return False
    witness = metadata[key]
    return (
        type(witness) is _SchemaToolWitness
        and witness.secret is _SCHEMA_TOOL_MARKER
        and witness.tool is value
        and witness.function is function
        and witness.function_schema is function_schema
        and witness.validator is function_schema.validator
        and witness.core_validator is core_validator
        and getattr(function, _SCHEMA_CALLABLE_MARKER, None)
        is _SCHEMA_TOOL_MARKER
        and function_schema.function is function
    )


def _canonical_schema(value: Any, *, label: str) -> str:
    try:
        snapshot = authority._snapshot_json_value(value)
        return json.dumps(
            snapshot,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise PydanticAuthorityConfigurationError(
            f"{label} is not bounded plain JSON"
        ) from exc


def _reject_json_constant(token: str) -> None:
    """Reject JSON's non-standard NaN/Infinity spellings without callbacks."""

    del token
    raise ValueError("non-finite JSON constants are unsupported")


def _duplicate_free_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build one plain object while rejecting duplicate names at every depth."""

    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON object key")
        result[name] = value
    return result


def _raw_argument_object(value: Any) -> dict[str, Any]:
    """Decode one raw argument object without losing duplicate-key evidence."""

    try:
        if type(value) is dict:
            decoded = value
        elif type(value) is str:
            decoded = json.loads(
                value,
                object_pairs_hook=_duplicate_free_json_object,
                parse_constant=_reject_json_constant,
            )
        else:
            raise TypeError("raw tool arguments must be a dictionary or JSON string")
        snapshot = authority._snapshot_json_value(decoded)
    except (TypeError, ValueError, RecursionError) as exc:
        raise PydanticAuthorityConfigurationError(
            "selector arguments must be one duplicate-free finite JSON object"
        ) from exc
    if type(snapshot) is not dict:
        raise PydanticAuthorityConfigurationError(
            "selector arguments must decode to one JSON object"
        )
    return snapshot


def _exact_selector_from_arguments(
    arguments: dict[str, Any],
    selector: str,
) -> tuple[bool, str | None]:
    """Return presence plus a type- and signed-zero-exact selector encoding."""

    if selector not in arguments:
        return False, None
    value = arguments[selector]
    if value is not None and type(value) not in (str, bool, int, float):
        raise PydanticAuthorityConfigurationError(
            "selector values must be exact JSON scalars"
        )
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise PydanticAuthorityConfigurationError(
            "selector values must be finite exact JSON scalars"
        ) from exc
    return True, encoded


def _core_schema_validator(value: Any) -> SchemaValidator:
    """Return the exact core validator for either pinned Pydantic shape.

    Pydantic returns the core validator directly when no plugins are loaded.
    When plugins are installed it returns an exact pluggable container; the
    executable-method checks in :func:`_validator_seal` still require that
    container to delegate straight to its exact core without wrappers.
    """

    if type(value) is SchemaValidator:
        return value
    if type(value) is PluggableSchemaValidator:
        core = value._schema_validator
        if type(core) is SchemaValidator:
            return core
    raise PydanticAuthorityConfigurationError(
        "the Pydantic schema validator changed type"
    )


def _validator_seal(value: Any) -> tuple[Any, ...]:
    core = _core_schema_validator(value)
    methods: list[tuple[str, int]] = []
    for name in ("validate_json", "validate_python", "validate_strings"):
        method = getattr(value, name)
        if (
            type(method) is not BuiltinMethodType
            or method.__self__ is not core
            or method.__name__ != name
        ):
            raise PydanticAuthorityConfigurationError(
                "the Pydantic schema validator gained an executable wrapper"
            )
        methods.append((name, id(method.__self__)))
    shape = "core" if value is core else "pluggable"
    return (shape, id(value), id(core), tuple(methods))


def _pydantic_tool_seal(value: Any) -> tuple[Any, ...]:
    if not _is_pydantic_schema_tool(value):
        raise PydanticAuthorityConfigurationError(
            "PydanticAuthorityAgent accepts only exact tools returned by "
            "pydantic_schema_tool"
    )
    metadata = value.metadata
    witness = metadata[_SCHEMA_TOOL_METADATA_KEY]
    core_validator = _core_schema_validator(value.function_schema.validator)
    if (
        type(metadata) is not dict
        or type(witness) is not _SchemaToolWitness
        or witness.secret is not _SCHEMA_TOOL_MARKER
        or witness.tool is not value
        or witness.function is not value.function
        or witness.function_schema is not value.function_schema
        or witness.validator is not value.function_schema.validator
        or witness.core_validator is not core_validator
        or value.takes_ctx is not False
        or value.max_retries is not None
        or value.prepare is not None
        or value.args_validator is not None
        or type(value.docstring_format) is not str
        or value.docstring_format != "auto"
        or value.require_parameter_descriptions is not False
        or value.requires_approval is not False
        or value.timeout is not None
        or value.defer_loading is not False
        or value.include_return_schema is not False
    ):
        raise PydanticAuthorityConfigurationError(
            "a pydantic_schema_tool was mutated or gained an executable "
            "Pydantic callback"
        )
    if (
        type(value.function) is not FunctionType
        or type(value.name) is not str
        or not value.name
        or (value.description is not None and type(value.description) is not str)
        or (value.strict is not None and type(value.strict) is not bool)
        or type(value.sequential) is not bool
    ):
        raise PydanticAuthorityConfigurationError(
            "a pydantic_schema_tool has unsupported public fields"
        )
    function_schema = value.function_schema
    if (
        type(function_schema) is not FunctionSchema
        or function_schema.function is not value.function
        or function_schema.takes_ctx is not False
        or function_schema.is_async is not False
        or getattr(value.function, _SCHEMA_CALLABLE_MARKER, None)
        is not _SCHEMA_TOOL_MARKER
    ):
        raise PydanticAuthorityConfigurationError(
            "a pydantic_schema_tool lost its inert execution function"
        )
    if (
        type(function_schema.name) is not str
        or not function_schema.name
        or function_schema.name != value.name
        or (
            function_schema.description is not None
            and type(function_schema.description) is not str
        )
        or function_schema.description != value.description
        or (
            function_schema.single_arg_name is not None
            and type(function_schema.single_arg_name) is not str
        )
        or type(function_schema.positional_fields) is not list
        or not all(type(item) is str for item in function_schema.positional_fields)
        or (
            function_schema.var_positional_field is not None
            and type(function_schema.var_positional_field) is not str
        )
    ):
        raise PydanticAuthorityConfigurationError(
            "a pydantic_schema_tool function schema was mutated"
        )
    validator_seal = _validator_seal(function_schema.validator)
    seal = (
        tuple(sorted(vars(value))),
        id(witness),
        id(value.function),
        id(value.function.__code__),
        value.name,
        value.description,
        value.strict,
        value.sequential,
        id(function_schema),
        tuple(sorted(vars(function_schema))),
        validator_seal,
        function_schema.name,
        function_schema.description,
        function_schema.single_arg_name,
        tuple(function_schema.positional_fields),
        function_schema.var_positional_field,
        _canonical_schema(
            function_schema.json_schema,
            label="Pydantic function schema",
        ),
        _canonical_schema(
            function_schema.return_schema,
            label="Pydantic return schema",
        ),
    )
    normalized = (seal[0], *seal[2:])
    if witness.baseline and normalized != witness.baseline:
        raise PydanticAuthorityConfigurationError(
            "a pydantic_schema_tool changed from its construction-time seal"
        )
    return seal


def _sealed_tool_from_definition(tool_def: Any) -> PydanticTool[Any]:
    """Resolve and recheck the construction-time tool behind one definition."""

    if type(tool_def) is not ToolDefinition or tool_def.kind != "function":
        raise PydanticAuthorityConfigurationError(
            "Verb Authority rejected an unsupported Pydantic tool definition"
        )
    if type(tool_def.name) is not str or not tool_def.name:
        raise PydanticAuthorityConfigurationError(
            "Verb Authority rejected an invalid Pydantic tool identity"
        )
    metadata = tool_def.metadata
    if type(metadata) is not dict or len(metadata) != 1:
        raise PydanticAuthorityConfigurationError(
            "Verb Authority rejected missing schema-tool evidence"
        )
    metadata_key = next(iter(metadata))
    if type(metadata_key) is not str or metadata_key != _SCHEMA_TOOL_METADATA_KEY:
        raise PydanticAuthorityConfigurationError(
            "Verb Authority rejected invalid schema-tool evidence"
        )
    witness = metadata[metadata_key]
    if (
        type(witness) is not _SchemaToolWitness
        or witness.secret is not _SCHEMA_TOOL_MARKER
    ):
        raise PydanticAuthorityConfigurationError(
            "Verb Authority rejected inconsistent schema-tool evidence"
        )
    _pydantic_tool_seal(witness.tool)
    if type(witness.tool.name) is not str or witness.tool.name != tool_def.name:
        raise PydanticAuthorityConfigurationError(
            "Verb Authority rejected inconsistent schema-tool evidence"
        )
    return witness.tool


def _function_toolset_seal(value: Any) -> tuple[Any, ...]:
    if type(value) is not _AgentFunctionToolset:
        raise PydanticAuthorityConfigurationError(
            "the Pydantic function toolset changed type"
        )
    if value.max_retries is not None or value.timeout is not None:
        raise PydanticAuthorityConfigurationError(
            "the Pydantic function toolset gained unsupported retry or timeout "
            "execution behavior"
        )
    if (
        value.requires_approval is not False
        or value.metadata is not None
        or value._defer_loading is not False
        or value._id is not None
        or type(value.docstring_format) is not str
        or value.docstring_format != "auto"
        or value.require_parameter_descriptions is not False
        or (value.strict is not None and type(value.strict) is not bool)
        or type(value.sequential) is not bool
        or value.sequential is not False
        or value.include_return_schema is not None
        or type(value._instructions) is not list
        or bool(value._instructions)
        or type(value.tools) is not dict
    ):
        raise PydanticAuthorityConfigurationError(
            "the Pydantic function toolset gained unsupported execution behavior"
        )
    return (
        tuple(sorted(vars(value))),
        id(value.output_schema),
        value.docstring_format,
        value.require_parameter_descriptions,
        id(value.schema_generator),
        value.strict,
        value.sequential,
        value.include_return_schema,
        id(value.tools),
    )


@dataclass(frozen=True, slots=True)
class _PendingApproval:
    """Fixed-size commitment to an action awaiting approval."""

    action_id: str
    call_commitment: str

    @staticmethod
    def _call_commitment(tool_name: str, arguments_json: str) -> str:
        if type(tool_name) is not str or not tool_name:
            raise PydanticAuthorityConfigurationError(
                "approval tool name must be a non-empty plain string"
            )
        if type(arguments_json) is not str:
            raise PydanticAuthorityConfigurationError(
                "approval arguments must have a canonical JSON encoding"
            )
        try:
            arguments = json.loads(arguments_json)
            if type(arguments) is not dict:
                raise TypeError("approval arguments must decode to an object")
            canonical_arguments = _canonical_schema(
                arguments,
                label="approval argument commitment",
            )
        except (TypeError, ValueError, RecursionError) as exc:
            raise PydanticAuthorityConfigurationError(
                "approval arguments must have a canonical JSON object encoding"
            ) from exc
        material = json.dumps(
            [tool_name, canonical_arguments],
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(material).hexdigest()

    @classmethod
    def from_request(cls, request: ConfirmationRequest) -> "_PendingApproval":
        return cls(
            action_id=request.action_id,
            call_commitment=cls._call_commitment(
                request.tool_name,
                request.arguments_json,
            ),
        )

    def matches(self, request: ConfirmationRequest) -> bool:
        return self == type(self).from_request(request)

    def matches_call(self, tool_name: str, arguments_json: str) -> bool:
        """Bind a resumed approval before any guarded implementation runs."""

        return self.call_commitment == type(self)._call_commitment(
            tool_name,
            arguments_json,
        )


@dataclass(frozen=True, slots=True)
class _ResumeMarker:
    """One-run commitment proving raw boolean decisions entered first."""

    run_id: str
    decisions: tuple[tuple[str, bool], ...]


@dataclass(frozen=True, slots=True)
class _ToolExecutionPermit:
    """One-use proof that the exact current graph node owns this tool call."""

    run_id: str
    call: ToolCallPart
    tool_name: str
    tool_call_id: str
    raw_args_json: str
    selector: str | None
    approved: bool
    pending_action_id: str | None
    pending_call_commitment: str | None
    validated_args_json: str | None = None


def _plain_nested_mapping(value: Any, *, label: str) -> dict[str, dict[str, Any]]:
    if value is None:
        return {}
    if type(value) is not dict:
        raise TypeError(f"{label} must be a plain dictionary")
    snapshot = authority._snapshot_json_value(value)
    if type(snapshot) is not dict:  # defensive; the input check above is exact
        raise TypeError(f"{label} must be a plain dictionary")
    for tool_name, arguments in snapshot.items():
        if type(tool_name) is not str or not tool_name:
            raise TypeError(f"{label} tool names must be non-empty plain strings")
        if type(arguments) is not dict:
            raise TypeError(f"{label} entries must be plain dictionaries")
        for argument_name in arguments:
            if type(argument_name) is not str or not argument_name:
                raise TypeError(
                    f"{label} argument names must be non-empty plain strings"
                )
    return snapshot


def _resolver_mapping(
    value: Any,
) -> Mapping[str, Mapping[str, TrustedResolver]]:
    if value is None:
        return MappingProxyType({})
    if type(value) is not dict:
        raise TypeError("trusted_choices must be a plain dictionary")
    outer: dict[str, Mapping[str, TrustedResolver]] = {}
    for tool_name, arguments in value.items():
        if type(tool_name) is not str or not tool_name:
            raise TypeError(
                "trusted_choices tool names must be non-empty plain strings"
            )
        if type(arguments) is not dict:
            raise TypeError("trusted_choices entries must be plain dictionaries")
        inner: dict[str, TrustedResolver] = {}
        for argument_name, resolver in arguments.items():
            if type(argument_name) is not str or not argument_name:
                raise TypeError(
                    "trusted_choices argument names must be non-empty plain strings"
                )
            if type(resolver) is not TrustedResolver:
                raise TypeError(
                    "trusted_choices values must be exact TrustedResolver instances"
                )
            inner[argument_name] = resolver
        outer[tool_name] = MappingProxyType(inner)
    return MappingProxyType(outer)


def _confirmation_metadata(
    request: ConfirmationRequest,
    evidence: Mapping[str, str],
) -> dict[str, Any]:
    assessment = request.risk_assessment
    return {
        "verb_authority": {
            "adapter_version": _ADAPTER_VERSION,
            "tool_name": request.tool_name,
            "arguments_json": request.arguments_json,
            "risk": request.risk,
            "risk_assessment": {
                "risk": assessment.risk,
                "source": assessment.source,
                "confidence": assessment.confidence,
                "mutability": assessment.mutability,
                "matched_tokens": list(assessment.matched_tokens),
                "review_required": assessment.review_required,
            },
            "declared_risk": request.declared_risk,
            "risk_conflict": request.risk_conflict,
            "registration_id": request.registration_id,
            "executable_id": request.executable_id,
            "ledger_version": request.ledger_version,
            "action_id": request.action_id,
            "selector": request.selector,
            "selector_value_json": request.selector_value_json,
            "active_args": (
                None
                if request.active_args is None
                else list(request.active_args)
            ),
            "trusted_choice_evidence": dict(evidence),
            "claim_boundary": (
                "per-argument provenance/local constraints + explicit exact "
                "one-selector branch risk/applicability; still not selection "
                "intent, general cross-argument composition, sequence, or "
                "action-instance authorization"
            ),
        }
    }


class PydanticAuthoritySession:
    """Application-owned authority state for one authenticated agent session.

    ``trusted_fixed`` contains canonical values owned by application code.
    ``trusted_choices`` maps a model-visible argument to a closed
    :class:`TrustedResolver`; the model supplies a key and the adapter replaces
    it with the catalog value before the gate and implementation see it.

    Keep this object in ``RunContext.deps`` (or inside an application deps
    object selected by ``session_getter``).  Do not construct it from model or
    tool output.  One session owns one ledger and its pending approvals.
    """

    __slots__ = (
        "_choice_resolvers",
        "_fixed_args",
        "_pending",
        "_pending_lock",
        "_runner",
        "__weakref__",
    )

    def __init__(
        self,
        registry: Registry,
        policy_set: PolicySet | None = None,
        *,
        trusted_fixed: dict[str, dict[str, Any]] | None = None,
        trusted_choices: dict[str, dict[str, TrustedResolver]] | None = None,
        ledger: ProvenanceLedger | None = None,
    ) -> None:
        self._runner = GuardedToolRunner(
            registry,
            policy_set,
            ledger=ledger,
        )
        fixed = _plain_nested_mapping(trusted_fixed, label="trusted_fixed")
        self._fixed_args = MappingProxyType(
            {
                tool_name: MappingProxyType(arguments)
                for tool_name, arguments in fixed.items()
            }
        )
        self._choice_resolvers = _resolver_mapping(trusted_choices)
        self._pending: dict[str, _PendingApproval] = {}
        self._pending_lock = threading.Lock()
        _install_session_registration_seal(self, self._runner)
        self._validate_bindings()

    @property
    def runner(self) -> GuardedToolRunner:
        """Inspection-only runner view; applications must not replace its state."""

        return self._runner

    def _validate_bindings(self) -> None:
        registration = _verify_session_registration_seal(self)
        for tool_name, shapes in registration.selector_case_shapes.items():
            if len(shapes) > 1:
                raise PydanticAuthorityConfigurationError(
                    "the beta.11 Pydantic adapter requires every selector "
                    f"branch for {tool_name!r} to share one model-visible "
                    "active-argument shape; branch-varying active_args are "
                    "supported only by the core/scanner, so split the tool or "
                    "use GuardedToolRunner directly"
                )

        overlap_tools = set(self._fixed_args) & set(self._choice_resolvers)
        for tool_name in overlap_tools:
            overlap = set(self._fixed_args[tool_name]) & set(
                self._choice_resolvers[tool_name]
            )
            if overlap:
                names = ", ".join(sorted(overlap))
                raise PydanticAuthorityConfigurationError(
                    f"arguments cannot be both fixed and trusted choices: {names}"
                )

        known_tools = registration.bundle.policy_set.policy
        for source_name, bindings in (
            ("trusted_fixed", self._fixed_args),
            ("trusted_choices", self._choice_resolvers),
        ):
            for tool_name, arguments in bindings.items():
                if tool_name not in known_tools:
                    raise PydanticAuthorityConfigurationError(
                        f"{source_name} names unknown tool {tool_name!r}"
                    )
                policies = known_tools[tool_name]
                for argument_name in arguments:
                    if argument_name not in policies:
                        raise PydanticAuthorityConfigurationError(
                            f"{source_name} names unknown argument "
                            f"{tool_name}.{argument_name}"
                        )
                    if policies[argument_name] != "trusted_fixed":
                        raise PydanticAuthorityConfigurationError(
                            f"{source_name} may bind only protected arguments; "
                            f"{tool_name}.{argument_name} is "
                            f"{policies[argument_name]!r}"
                        )

        for tool_name, policies in known_tools.items():
            bound = set(self._fixed_args.get(tool_name, {})) | set(
                self._choice_resolvers.get(tool_name, {})
            )
            missing = sorted(
                argument_name
                for argument_name, policy in policies.items()
                if policy == "trusted_fixed" and argument_name not in bound
            )
            if missing:
                names = ", ".join(missing)
                raise PydanticAuthorityConfigurationError(
                    f"protected arguments require an application binding for "
                    f"{tool_name}: {names}"
                )

    def prepare_call(
        self,
        tool_name: str,
        model_args: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any], Mapping[str, str]]:
        if type(tool_name) is not str or not tool_name:
            raise PydanticAuthorityConfigurationError(
                "tool name must be a non-empty plain string"
            )
        if type(model_args) is not dict:
            raise PydanticAuthorityConfigurationError(
                "validated tool arguments must be a plain dictionary"
            )
        try:
            prepared = authority._snapshot_json_value(model_args)
        except Exception as exc:
            raise PydanticAuthorityConfigurationError(
                "validated tool arguments must contain only finite plain JSON values"
            ) from exc

        trusted: dict[str, Any] = {}
        evidence: dict[str, str] = {}
        for argument_name, value in self._fixed_args.get(tool_name, {}).items():
            canonical = authority._snapshot_json_value(value)
            prepared[argument_name] = canonical
            trusted[argument_name] = authority._snapshot_json_value(canonical)
            evidence[argument_name] = "application-owned authenticated session value"

        for argument_name, resolver in self._choice_resolvers.get(
            tool_name, {}
        ).items():
            if argument_name not in prepared:
                raise PydanticAuthorityResolutionError(
                    f"trusted choice for {tool_name}.{argument_name} is missing"
                )
            resolution = resolver.resolve(prepared[argument_name])
            if resolution.status is not ResolutionStatus.RESOLVED:
                raise PydanticAuthorityResolutionError(
                    f"trusted choice for {tool_name}.{argument_name} did not "
                    "resolve uniquely"
                )
            canonical = authority._snapshot_json_value(resolution.value)
            prepared[argument_name] = canonical
            trusted[argument_name] = authority._snapshot_json_value(canonical)
            assert resolution.evidence is not None
            evidence[argument_name] = resolution.evidence

        return prepared, trusted, MappingProxyType(evidence)

    def confirmation_callback(
        self,
        *,
        tool_call_id: str,
        approved: bool,
        evidence: Mapping[str, str],
        captured: list[ConfirmationRequest],
    ) -> Callable[[ConfirmationRequest], bool]:
        if not _bounded_tool_call_id(tool_call_id):
            raise PydanticAuthorityConfigurationError(
                "Pydantic tool calls must carry a bounded non-empty tool_call_id"
            )

        def confirm(request: ConfirmationRequest) -> bool:
            captured.append(request)
            current = _PendingApproval.from_request(request)
            with self._pending_lock:
                previous = self._pending.get(tool_call_id)
                if approved is True and previous is not None and previous.matches(request):
                    # Consume before invocation.  If the implementation is entered and
                    # later fails, the approval cannot be replayed automatically.
                    del self._pending[tool_call_id]
                    return True
                if previous is None and len(self._pending) >= _MAX_PENDING_APPROVALS:
                    raise PydanticAuthorityConfigurationError(
                        "the session pending-approval budget is exhausted"
                    )
                self._pending[tool_call_id] = current
            return False

        return confirm

    def approval_metadata(
        self,
        request: ConfirmationRequest,
        evidence: Mapping[str, str],
    ) -> dict[str, Any]:
        return _confirmation_metadata(request, evidence)

    def discard_pending_approval(self, tool_call_id: str) -> bool:
        """Discard one abandoned or cancelled approval without executing it."""

        if not _bounded_tool_call_id(tool_call_id):
            raise PydanticAuthorityConfigurationError(
                "tool_call_id must be a bounded non-empty plain string"
            )
        with self._pending_lock:
            return self._pending.pop(tool_call_id, None) is not None

    def _reconcile_pending_results(self, messages: list[Any]) -> None:
        """Accept only a denial while a VA approval commitment is pending.

        Pydantic 2.35 flattens approval and externally executed result buckets
        during resume.  A caller can therefore put an approval call ID in the
        external-results bucket (or pass a value of the wrong runtime type in
        the approval bucket).  That creates a tool result without invoking the
        guarded Registry function.  A legitimate approval consumes ``_pending``
        inside ``confirmation_callback`` before invocation, so any remaining
        pending ID with a success, failure, or retry result is type confusion.
        """

        with self._pending_lock:
            pending_ids = set(self._pending)
        if not pending_ids:
            return

        outcomes: dict[str, set[str]] = {}
        retry_ids: set[str] = set()
        for message in messages:
            for part in getattr(message, "parts", ()):
                tool_call_id = getattr(part, "tool_call_id", None)
                if type(tool_call_id) is not str or tool_call_id not in pending_ids:
                    continue
                if isinstance(part, ToolReturnPart):
                    outcomes.setdefault(tool_call_id, set()).add(part.outcome)
                elif isinstance(part, RetryPromptPart):
                    retry_ids.add(tool_call_id)

        with self._pending_lock:
            invalid_ids = sorted(
                tool_call_id
                for tool_call_id, observed in outcomes.items()
                if tool_call_id in self._pending and observed != {"denied"}
            )
            invalid_ids.extend(
                sorted(
                    tool_call_id
                    for tool_call_id in retry_ids
                    if tool_call_id in self._pending
                )
            )
            if invalid_ids:
                names = ", ".join(sorted(set(invalid_ids)))
                raise PydanticAuthorityConfigurationError(
                    "Pydantic supplied a non-denial result for a pending Verb "
                    f"Authority approval: {names}"
                )
            for tool_call_id, observed in outcomes.items():
                if observed == {"denied"}:
                    self._pending.pop(tool_call_id, None)

    def _validate_deferred_results(
        self, results: Any
    ) -> tuple[tuple[str, bool], ...]:
        """Permit only exact boolean decisions for approvals created by VA."""

        if type(results) is not DeferredToolResults:
            raise PydanticAuthorityConfigurationError(
                "deferred results must be an exact Pydantic DeferredToolResults"
            )
        if type(results.calls) is not dict or results.calls:
            raise PydanticAuthorityConfigurationError(
                "Verb Authority rejects externally supplied deferred tool results"
            )
        if type(results.metadata) is not dict or results.metadata:
            raise PydanticAuthorityConfigurationError(
                "Verb Authority rejects caller-supplied deferred metadata"
            )
        if type(results.approvals) is not dict or not results.approvals:
            raise PydanticAuthorityConfigurationError(
                "Verb Authority requires at least one exact boolean approval decision"
            )
        if len(results.approvals) > _MAX_PENDING_APPROVALS:
            raise PydanticAuthorityConfigurationError(
                "Verb Authority rejects oversized approval batches"
            )

        invalid_values = [
            tool_call_id
            for tool_call_id, decision in results.approvals.items()
            if not _bounded_tool_call_id(tool_call_id)
            or type(decision) is not bool
        ]
        if invalid_values:
            raise PydanticAuthorityConfigurationError(
                "Verb Authority approval decisions require bounded string IDs "
                "and exact boolean values"
            )

        with self._pending_lock:
            unknown = sorted(set(results.approvals) - set(self._pending))
        if unknown:
            names = ", ".join(unknown)
            raise PydanticAuthorityConfigurationError(
                "Pydantic supplied approval decisions without matching Verb "
                f"Authority commitments: {names}"
            )
        return tuple(sorted(results.approvals.items()))

    def _validate_resumed_call_results(
        self,
        results: Any,
        metadata: Any,
        messages: list[Any],
        calls: list[Any],
        expected_decisions: tuple[tuple[str, bool], ...],
    ) -> None:
        """Reject graph-driver result injection after raw resume validation."""

        if type(results) is not dict or not results:
            raise PydanticAuthorityConfigurationError(
                "Verb Authority rejects empty or non-plain resumed call results"
            )
        if len(results) > _MAX_PENDING_APPROVALS or len(calls) > _MAX_PENDING_APPROVALS:
            raise PydanticAuthorityConfigurationError(
                "Verb Authority rejects oversized resumed call batches"
            )
        if metadata is not None:
            raise PydanticAuthorityConfigurationError(
                "Verb Authority rejects resumed call-result metadata"
            )

        call_names: dict[str, str] = {}
        duplicate_call_ids: set[str] = set()
        for call in calls:
            tool_call_id = getattr(call, "tool_call_id", None)
            tool_name = getattr(call, "tool_name", None)
            if (
                not _bounded_tool_call_id(tool_call_id)
                or type(tool_name) is not str
                or not tool_name
                or tool_call_id in call_names
            ):
                if type(tool_call_id) is str:
                    duplicate_call_ids.add(tool_call_id)
                else:
                    duplicate_call_ids.add("<invalid>")
                continue
            call_names[tool_call_id] = tool_name
        if duplicate_call_ids or set(results) - set(call_names):
            raise PydanticAuthorityConfigurationError(
                "Verb Authority rejects inconsistent resumed call identities"
            )

        current_calls = set(call_names.items())
        settled: set[tuple[str, str]] = set()
        for message in messages:
            for part in getattr(message, "parts", ()):
                if not isinstance(part, (ToolReturnPart, RetryPromptPart)):
                    continue
                tool_call_id = getattr(part, "tool_call_id", None)
                tool_name = getattr(part, "tool_name", None)
                identity = (tool_call_id, tool_name)
                if identity in current_calls:
                    settled.add(identity)

        with self._pending_lock:
            pending_ids = set(self._pending)

        invalid: list[Any] = []
        observed_decisions: dict[str, bool] = {}
        for tool_call_id, result in results.items():
            if not _bounded_tool_call_id(tool_call_id):
                invalid.append(tool_call_id)
                continue
            if type(result) is ToolApproved:
                if (
                    tool_call_id not in pending_ids
                    or result.kind != "tool-approved"
                    or result.override_args is not None
                ):
                    invalid.append(tool_call_id)
                else:
                    observed_decisions[tool_call_id] = True
            elif type(result) is ToolDenied:
                if (
                    tool_call_id not in pending_ids
                    or result.kind != "tool-denied"
                    or result.message != "The tool call was denied."
                ):
                    invalid.append(tool_call_id)
                else:
                    observed_decisions[tool_call_id] = False
            elif type(result) is str and result == "skip":
                if (
                    tool_call_id in pending_ids
                    or (tool_call_id, call_names[tool_call_id]) not in settled
                ):
                    invalid.append(tool_call_id)
            else:
                invalid.append(tool_call_id)
        if invalid:
            raise PydanticAuthorityConfigurationError(
                "Verb Authority accepts only unmodified approval or denial "
                "decisions in resumed call results"
            )
        if tuple(sorted(observed_decisions.items())) != expected_decisions:
            raise PydanticAuthorityConfigurationError(
                "Pydantic resumed decisions do not match the validated raw "
                "approval transition"
            )



def _default_session_getter(ctx: RunContext[Any]) -> PydanticAuthoritySession:
    deps = ctx.deps
    if type(deps) is not PydanticAuthoritySession:
        raise PydanticAuthorityConfigurationError(
            "RunContext.deps must be an exact PydanticAuthoritySession or the "
            "capability must receive an explicit session_getter"
        )
    return deps


@dataclass
class VerbAuthorityCapability(AbstractCapability[Any]):
    """Pydantic AI capability that routes every local function tool through VA."""

    session_getter: Callable[[RunContext[Any]], PydanticAuthoritySession] = (
        _default_session_getter
    )
    _resume_marker: _ResumeMarker | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _bound_session: PydanticAuthoritySession | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _statically_bound: bool = field(
        default=False,
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        if type(self) is not VerbAuthorityCapability:
            raise TypeError("VerbAuthorityCapability cannot be subclassed")
        if not callable(self.session_getter):
            raise TypeError("session_getter must be callable")
        if self.defer_loading:
            raise PydanticAuthorityConfigurationError(
                "VerbAuthorityCapability must be always-on"
            )

    @classmethod
    def get_serialization_name(cls) -> str | None:
        return None

    def get_ordering(self) -> CapabilityOrdering:
        return CapabilityOrdering(position="innermost")

    def for_agent(self, agent: Any) -> "VerbAuthorityCapability":
        """Bind only as the managed static capability of the sealed Agent."""

        managed = getattr(agent, "_verb_authority_managed_capability", None)
        if (
            type(agent) is not PydanticAuthorityAgent
            or managed is not self
        ):
            raise PydanticAuthorityConfigurationError(
                "VerbAuthorityCapability is managed by PydanticAuthorityAgent; "
                "manual or per-run installation is unsupported"
            )
        self._statically_bound = True
        try:
            root = getattr(agent, "root_capability", None)
            seal = _static_capability_tree_seal(
                root,
                managed=self,
                session_getter=self.session_getter,
            )
            del seal
        except BaseException:
            self._statically_bound = False
            raise
        return self

    @staticmethod
    def _reject_realtime(ctx: RunContext[Any]) -> None:
        if ctx.realtime:
            raise PydanticAuthorityConfigurationError(
                "Pydantic realtime sessions execute outside the audited local "
                "Verb Authority tool boundary and are unsupported in this beta"
            )

    async def for_run(
        self, ctx: RunContext[Any]
    ) -> "VerbAuthorityCapability":
        """Reject realtime before either classic or realtime hooks can run."""

        if not self._statically_bound:
            raise PydanticAuthorityConfigurationError(
                "VerbAuthorityCapability must be installed statically by "
                "PydanticAuthorityAgent"
            )
        self._reject_realtime(ctx)
        capability = VerbAuthorityCapability(
            session_getter=self.session_getter,
            id=self.id,
            description=self.description,
        )
        capability._statically_bound = True
        capability._session(ctx)
        return capability

    def _validate_runtime_capabilities(
        self,
        ctx: RunContext[Any],
        capabilities: Any,
    ) -> None:
        """Reject per-run siblings before Pydantic composes lifecycle wrappers."""

        self._reject_realtime(ctx)
        self._reject_capabilities(capabilities, include_setup=False)

    def _session(self, ctx: RunContext[Any]) -> PydanticAuthoritySession:
        self._reject_realtime(ctx)
        try:
            session = self.session_getter(ctx)
        except PydanticAuthorityConfigurationError:
            raise
        except Exception as exc:
            raise PydanticAuthorityConfigurationError(
                "session_getter failed"
            ) from exc
        if type(session) is not PydanticAuthoritySession:
            raise PydanticAuthorityConfigurationError(
                "session_getter must return an exact PydanticAuthoritySession"
            )
        _verify_session_registration_seal(session)
        if self._bound_session is None:
            self._bound_session = session
        elif session is not self._bound_session:
            raise PydanticAuthorityConfigurationError(
                "session_getter changed PydanticAuthoritySession identity during a run"
            )
        return session

    def _reject_capabilities(
        self,
        capabilities: Any,
        *,
        include_setup: bool,
    ) -> None:
        """Reject middleware that could bypass, replay, or rewrite the boundary.

        Argument-validation hooks run before this capability and are therefore
        rechecked by GuardedToolRunner. A ``before_tool_execute`` hook can skip
        the execution chain entirely, another execution wrapper can invoke this
        capability more than once, and an after/error hook can replace the
        result after the ledger recorded it. This beta refuses all of those
        ambiguous compositions. A model-request wrapper is also unsafe because
        it can replace the request sent to the provider. A toolset wrapper runs
        after ``prepare_tools`` and can replace or rename an already-validated
        tool. This beta rejects all of those boundary-changing hooks.
        """

        unsafe_hooks = (
            "get_toolset",
            "get_wrapper_toolset",
            "prepare_tools",
            "prepare_output_tools",
            "before_run",
            "after_run",
            "wrap_run",
            "on_run_error",
            "before_node_run",
            "after_node_run",
            "wrap_node_run",
            "on_node_run_error",
            "wrap_run_event_stream",
            "before_model_request",
            "after_model_request",
            "wrap_model_request",
            "on_model_request_error",
            "before_tool_validate",
            "before_tool_execute",
            "wrap_tool_validate",
            "after_tool_validate",
            "on_tool_validate_error",
            "wrap_tool_execute",
            "after_tool_execute",
            "on_tool_execute_error",
            "before_output_validate",
            "after_output_validate",
            "wrap_output_validate",
            "on_output_validate_error",
            "before_output_process",
            "after_output_process",
            "wrap_output_process",
            "on_output_process_error",
            "handle_deferred_tool_calls",
            "prefix_tools",
        )
        if include_setup:
            unsafe_hooks = ("for_agent", "for_run", *unsafe_hooks)
        checked: set[int] = set()
        for capability in capabilities:
            _reject_capability_instance_hooks(capability)
            if capability is self or id(capability) in checked:
                continue
            checked.add(id(capability))
            # Pydantic AI 2.35 injects this exact no-op wrapper into every Agent.
            # Deferred/swap-enabled definitions are rejected below, and the final
            # model-request hook rejects any native tool it might surface.
            if type(capability) is ToolSearch:
                state = vars(capability)
                expected_keys = (
                    "id",
                    "description",
                    "defer_loading",
                    "strategy",
                    "max_results",
                    "tool_description",
                    "parameter_description",
                    "_search_fn",
                )
                if (
                    tuple(state) != expected_keys
                    or state["id"] is not None
                    or state["description"] is not None
                    or state["defer_loading"] is not False
                    or state["strategy"] is not None
                    or type(state["max_results"]) is not int
                    or state["max_results"] != 10
                    or state["tool_description"] is not None
                    or state["parameter_description"] is not None
                    or state["_search_fn"] is not None
                ):
                    raise UserError(
                        "Verb Authority rejects mutation of Pydantic's "
                        "auto-injected ToolSearch capability"
                    )
                continue
            if type(capability) is PendingMessageDrainCapability:
                if vars(capability):
                    raise UserError(
                        "Verb Authority rejects mutation of Pydantic's "
                        "pending-message capability"
                    )
                continue
            overridden = [
                hook
                for hook in unsafe_hooks
                if getattr(type(capability), hook)
                is not getattr(AbstractCapability, hook)
            ]
            if overridden:
                capability_name = (
                    f"{type(capability).__module__}."
                    f"{type(capability).__qualname__}"
                )
                raise UserError(
                    "Verb Authority cannot compose with a boundary-transforming "
                    f"capability in this beta: {capability_name} overrides "
                    + ", ".join(overridden)
                )

    def _reject_execution_transformers(self, ctx: RunContext[Any]) -> None:
        """Recheck the resolved capability registry at each guarded hook."""

        root = ctx.root_capability
        if type(root) is not _PinnedRunRoot:
            raise PydanticAuthorityConfigurationError(
                "Pydantic run capability root is not pinned"
            )
        manager = ctx.tool_manager
        if manager is None:
            raise PydanticAuthorityConfigurationError(
                "Pydantic ToolManager is unavailable at a guarded hook"
            )
        _verify_tool_manager(manager)
        _verify_run_context(ctx, root, manager)
        self._reject_capabilities(
            ctx.capabilities.values(),
            include_setup=False,
        )

    @staticmethod
    def _validate_property_schema(
        *,
        tool_name: str,
        registered: Any,
        properties: dict[str, Any],
        choice_names: set[str],
    ) -> None:
        for param in registered.params:
            if param.name not in properties:
                continue
            property_schema = properties[param.name]
            if type(property_schema) is not dict:
                raise UserError(
                    f"Pydantic tool {tool_name!r} has a non-plain schema for "
                    f"{param.name!r}"
                )
            if param.name in choice_names:
                expected_type = "string"
            elif param.type == "enum":
                expected_type = None
                if "enum" in property_schema and "const" not in property_schema:
                    declared = property_schema["enum"]
                elif (
                    "const" in property_schema
                    and "enum" not in property_schema
                ):
                    declared = [property_schema["const"]]
                else:
                    declared = None
                try:
                    expected_enum = authority._snapshot_json_value(
                        param.enum or []
                    )
                    enum_matches = (
                        type(declared) is list
                        and _canonical_schema(
                            declared,
                            label="Pydantic enum declaration",
                        )
                        == _canonical_schema(
                            expected_enum,
                            label="Verb Authority enum registration",
                        )
                    )
                except (TypeError, ValueError, RecursionError):
                    enum_matches = False
                if not enum_matches:
                    raise UserError(
                        f"Pydantic tool {tool_name!r} enum for {param.name!r} "
                        "drifted from the registry"
                    )
            else:
                expected_type = _JSON_SCHEMA_TYPES.get(param.type)
            if expected_type is not None and property_schema.get("type") != expected_type:
                raise UserError(
                    f"Pydantic tool {tool_name!r} type for {param.name!r} "
                    "drifted from the registry"
                )

    async def prepare_tools(
        self,
        ctx: RunContext[Any],
        tool_defs: list[ToolDefinition],
    ) -> list[ToolDefinition]:
        session = self._session(ctx)
        self._reject_execution_transformers(ctx)
        drift = session.runner._configuration_drift()
        if drift is not None:
            raise UserError(drift.reason)

        registry_tools = session.runner.registry.tools
        seen: set[str] = set()
        for tool_def in tool_defs:
            if type(tool_def) is not ToolDefinition:
                raise UserError("Verb Authority requires exact ToolDefinition values")
            name = tool_def.name
            if type(name) is not str or not name:
                raise UserError("Pydantic tool names must be non-empty plain strings")
            if name in seen:
                raise UserError(f"duplicate Pydantic tool {name!r}")
            seen.add(name)
            if name not in registry_tools:
                raise UserError(
                    f"Pydantic tool {name!r} has no Verb Authority registration"
                )
            if tool_def.toolset_id != "<agent>" or tool_def.capability_id is not None:
                raise UserError(
                    f"Pydantic tool {name!r} is not a direct local Agent tool; "
                    "runtime, remote, capability-provided, and MCP toolsets are "
                    "outside the first adapter boundary"
                )
            if tool_def.kind != "function":
                raise UserError(
                    f"Pydantic tool {name!r} has unsupported kind {tool_def.kind!r}; "
                    "the first adapter supports local function tools only"
                )
            metadata = tool_def.metadata
            if type(metadata) is not dict or len(metadata) != 1:
                raise UserError(
                    f"Pydantic tool {name!r} was not created by "
                    "pydantic_schema_tool"
                )
            metadata_key = next(iter(metadata))
            witness = (
                metadata[metadata_key]
                if type(metadata_key) is str
                and metadata_key == _SCHEMA_TOOL_METADATA_KEY
                else None
            )
            if (
                type(witness) is not _SchemaToolWitness
                or witness.secret is not _SCHEMA_TOOL_MARKER
                or witness.tool.name != name
            ):
                raise UserError(
                    f"Pydantic tool {name!r} was not created by "
                    "pydantic_schema_tool"
                )
            _pydantic_tool_seal(witness.tool)
            if (
                tool_def.defer_loading
                or tool_def.unless_native is not None
                or tool_def.with_native is not None
            ):
                raise UserError(
                    f"Pydantic tool {name!r} uses deferred or native swapping; "
                    "the first adapter supports always-visible local tools only"
                )
            if tool_def.timeout is not None:
                raise UserError(
                    f"Pydantic tool {name!r} declares a timeout that would be "
                    "bypassed by the guarded synchronous runner; enforce the "
                    "resource bound inside the registered implementation"
                )
            schema = tool_def.parameters_json_schema
            if type(schema) is not dict:
                raise UserError(f"Pydantic tool {name!r} has a non-plain schema")
            if set(schema) - _SUPPORTED_SCHEMA_KEYS:
                # Unknown top-level schema vocabulary is not necessarily unsafe,
                # but this beta refuses to silently claim it validated a shape it
                # has not audited.
                unknown = ", ".join(sorted(set(schema) - _SUPPORTED_SCHEMA_KEYS))
                raise UserError(
                    f"Pydantic tool {name!r} has unsupported schema keys: {unknown}"
                )
            if schema.get("type") != "object":
                raise UserError(f"Pydantic tool {name!r} must use an object schema")
            if schema.get("additionalProperties") is not False:
                raise UserError(
                    f"Pydantic tool {name!r} must close additional properties"
                )
            properties = schema.get("properties")
            required = schema.get("required", [])
            if type(properties) is not dict or type(required) is not list:
                raise UserError(
                    f"Pydantic tool {name!r} must declare properties and required"
                )
            if not all(type(item) is str for item in required):
                raise UserError(
                    f"Pydantic tool {name!r} has invalid required entries"
                )
            registered = registry_tools[name]
            fixed_names = set(session._fixed_args.get(name, {}))
            choice_names = set(session._choice_resolvers.get(name, {}))
            expected_names = [
                param.name for param in registered.params if param.name not in fixed_names
            ]
            expected_required = [
                param.name
                for param in registered.params
                if param.required and param.name not in fixed_names
            ]
            if set(properties) != set(expected_names):
                raise UserError(
                    f"Pydantic tool {name!r} parameter names drifted from the registry"
                )
            if set(required) != set(expected_required):
                raise UserError(
                    f"Pydantic tool {name!r} required arguments drifted from the registry"
                )
            self._validate_property_schema(
                tool_name=name,
                registered=registered,
                properties=properties,
                choice_names=choice_names,
            )
            implementation = registered.fn
            if implementation is None:
                raise UserError(
                    f"Pydantic tool {name!r} has no registered implementation"
                )
            if inspect.iscoroutinefunction(implementation) or inspect.isasyncgenfunction(
                implementation
            ):
                raise UserError(
                    f"Pydantic tool {name!r} is asynchronous; the first adapter is "
                    "synchronous-only"
                )
        return tool_defs

    async def before_node_run(
        self,
        ctx: RunContext[Any],
        *,
        node: Any,
    ) -> Any:
        """Validate resume input before Pydantic can turn it into tool results."""

        run = _require_guarded_agent_run_transition(
            ctx,
            require_driver_task=True,
        )
        _require_current_agent_node(run, node)
        root = ctx.root_capability
        # Claim the exact node before a session getter, callback, or await can
        # copy the live transition into another task.
        _claim_run_node_start(root, self, run, node)
        session = self._session(ctx)
        self._reject_execution_transformers(ctx)
        if isinstance(node, UserPromptNode):
            _replace_run_resume_marker(root, self, None)
            if type(node) is not UserPromptNode:
                raise PydanticAuthorityConfigurationError(
                    "Verb Authority rejects replaced Pydantic user-prompt nodes"
                )
            if node.deferred_tool_results is not None:
                if not _bounded_tool_call_id(ctx.run_id):
                    raise PydanticAuthorityConfigurationError(
                        "Verb Authority requires a bounded run ID for approval resume"
                    )
                decisions = session._validate_deferred_results(
                    node.deferred_tool_results
                )
                _replace_run_resume_marker(
                    root,
                    self,
                    _ResumeMarker(ctx.run_id, decisions),
                )
        elif isinstance(node, CallToolsNode):
            if type(node) is not CallToolsNode:
                raise PydanticAuthorityConfigurationError(
                    "Verb Authority rejects replaced Pydantic call-tools nodes"
                )
            calls = node.model_response.tool_calls
            if len(calls) > _MAX_PENDING_APPROVALS:
                raise PydanticAuthorityConfigurationError(
                    "Verb Authority rejects oversized tool-call batches"
                )
            expected_call_fields = {
                "tool_name",
                "args",
                "tool_call_id",
                "tool_kind",
                "id",
                "provider_name",
                "provider_details",
                "part_kind",
                "otel_metadata",
            }
            seen_call_ids: set[str] = set()
            for call in calls:
                if type(call) is not ToolCallPart or set(vars(call)) != expected_call_fields:
                    raise PydanticAuthorityConfigurationError(
                        "Verb Authority rejects non-exact model tool-call parts"
                    )
                if (
                    not _bounded_tool_call_id(call.tool_name)
                    or not _bounded_tool_call_id(call.tool_call_id)
                    or call.tool_kind is not None
                    or (
                        call.id is not None
                        and not _bounded_tool_call_id(call.id)
                    )
                    or (
                        call.provider_name is not None
                        and not _bounded_tool_call_id(call.provider_name)
                    )
                    or type(call.part_kind) is not str
                    or call.part_kind != "tool-call"
                    or call.otel_metadata is not None
                ):
                    raise PydanticAuthorityConfigurationError(
                        "Verb Authority rejects malformed model tool-call metadata"
                    )
                if call.tool_call_id in seen_call_ids:
                    raise PydanticAuthorityConfigurationError(
                        "Verb Authority rejects duplicate model tool-call IDs"
                    )
                seen_call_ids.add(call.tool_call_id)
                raw_args = {} if call.args is None else call.args
                if type(raw_args) not in (str, dict):
                    raise PydanticAuthorityConfigurationError(
                        "Verb Authority rejects non-plain model tool arguments"
                    )
                try:
                    plain_args = authority._snapshot_json_value(raw_args)
                    plain_provider_details = (
                        None
                        if call.provider_details is None
                        else authority._snapshot_json_value(call.provider_details)
                    )
                except (TypeError, ValueError, RecursionError) as exc:
                    raise PydanticAuthorityConfigurationError(
                        "Verb Authority rejects non-plain model tool-call data"
                    ) from exc
                if (
                    plain_provider_details is not None
                    and type(plain_provider_details) is not dict
                ):
                    raise PydanticAuthorityConfigurationError(
                        "Verb Authority rejects non-plain provider details"
                    )
                call.args = plain_args
                call.provider_details = plain_provider_details
            approved_call_ids: set[str] | None = None
            if node.tool_call_results is not None:
                marker = _consume_run_resume_marker(root, self)
                if marker is None or marker.run_id != ctx.run_id:
                    raise PydanticAuthorityConfigurationError(
                        "Verb Authority rejects call results without the immediate "
                        "validated raw approval transition"
                    )
                session._validate_resumed_call_results(
                    node.tool_call_results,
                    node.tool_call_metadata,
                    ctx.messages,
                    calls,
                    marker.decisions,
                )
                approved_call_ids = {
                    tool_call_id
                    for tool_call_id, result in node.tool_call_results.items()
                    if type(result) is ToolApproved
                }
            elif _verify_run_tree(root).resume_marker is not None:
                _replace_run_resume_marker(root, self, None)
                raise PydanticAuthorityConfigurationError(
                    "Pydantic lost the validated raw approval transition"
                )
            permits: list[_ToolExecutionPermit] = []
            with session._pending_lock:
                for call in calls:
                    approved = (
                        approved_call_ids is not None
                        and call.tool_call_id in approved_call_ids
                    )
                    # A resumed denial or an already-settled `skip` is not an
                    # executable call and therefore receives no permit.
                    if approved_call_ids is not None and not approved:
                        continue
                    pending_action_id: str | None = None
                    pending_call_commitment: str | None = None
                    if approved:
                        pending = session._pending.get(call.tool_call_id)
                        if pending is None:
                            raise PydanticAuthorityConfigurationError(
                                "Verb Authority lost the approved pending action"
                            )
                        pending_action_id = pending.action_id
                        pending_call_commitment = pending.call_commitment
                    selector = _session_selector(session, call.tool_name)
                    permits.append(
                        _ToolExecutionPermit(
                            run_id=ctx.run_id,
                            call=call,
                            tool_name=call.tool_name,
                            tool_call_id=call.tool_call_id,
                            raw_args_json=_canonical_schema(
                                call.args,
                                label="model tool arguments",
                            ),
                            selector=selector,
                            approved=approved,
                            pending_action_id=pending_action_id,
                            pending_call_commitment=pending_call_commitment,
                        )
                    )
            _replace_run_execution_permits(root, self, tuple(permits))
        return node

    async def prepare_output_tools(
        self,
        ctx: RunContext[Any],
        tool_defs: list[ToolDefinition],
    ) -> list[ToolDefinition]:
        """Reject executable output-tool paths outside the guarded Registry."""

        self._session(ctx)
        self._reject_execution_transformers(ctx)
        if tool_defs:
            raise UserError(
                "Pydantic output tools execute outside the local Verb Authority "
                "runner and are unsupported in the first adapter"
            )
        return tool_defs

    async def before_model_request(
        self,
        ctx: RunContext[Any],
        request_context: ModelRequestContext,
    ) -> ModelRequestContext:
        session = self._session(ctx)
        self._reject_execution_transformers(ctx)
        session._reconcile_pending_results(request_context.messages)
        parameters = request_context.model_request_parameters
        if parameters.native_tools:
            raise UserError(
                "provider-native tools bypass the local Verb Authority runner"
            )
        return request_context

    async def wrap_model_request(
        self,
        ctx: RunContext[Any],
        *,
        request_context: ModelRequestContext,
        handler: Callable[[ModelRequestContext], Any],
    ) -> Any:
        """Make the innermost, final request fail closed on native tools."""

        session = self._session(ctx)
        self._reject_execution_transformers(ctx)
        session._reconcile_pending_results(request_context.messages)
        if request_context.model_request_parameters.native_tools:
            raise UserError(
                "provider-native tools bypass the local Verb Authority runner"
            )
        return await handler(request_context)

    async def wrap_tool_validate(
        self,
        ctx: RunContext[Any],
        *,
        call: Any,
        tool_def: ToolDefinition,
        args: Any,
        handler: Callable[[Any], Any],
    ) -> dict[str, Any]:
        """Forbid validation-time approval and externally supplied results.

        Pydantic converts ``CallDeferred`` raised by an ``args_validator`` into
        its internal ``_ValidationDeferral`` before capability wrappers see it.
        Accepting that path would allow a resumed run to supply a result that
        never passed through ``GuardedToolRunner`` or the provenance ledger.
        The adapter is pinned to 2.35 so this private sentinel is audited as
        part of the exact supported lifecycle and rejected fail closed.
        """

        _require_guarded_agent_run_transition(ctx)
        self._session(ctx)
        self._reject_execution_transformers(ctx)
        _sealed_tool_from_definition(tool_def)
        if type(call) is not ToolCallPart:
            raise ToolFailed("Verb Authority rejected a replaced tool call")
        permit = _run_execution_permit(
            ctx,
            self,
            call,
            require_validated=False,
        )
        if type(args) not in (str, dict):
            raise ToolFailed(
                "Verb Authority rejected non-plain raw tool arguments"
            )
        try:
            plain_args = authority._snapshot_json_value(args)
        except (TypeError, ValueError, RecursionError) as exc:
            raise ToolFailed(
                "Verb Authority rejected non-plain raw tool arguments"
            ) from exc
        if (
            _canonical_schema(plain_args, label="raw tool arguments")
            != permit.raw_args_json
        ):
            raise ToolFailed(
                "Verb Authority rejected tool arguments that changed after the "
                "current graph node was authorized"
            )
        raw_selector: tuple[bool, str | None] | None = None
        if permit.selector is not None:
            try:
                raw_selector = _exact_selector_from_arguments(
                    _raw_argument_object(plain_args),
                    permit.selector,
                )
            except PydanticAuthorityConfigurationError as exc:
                raise ToolFailed(str(exc)) from None
        try:
            validated = await handler(plain_args)
        except (_ValidationDeferral, CallDeferred, ApprovalRequired):
            raise ToolFailed(
                "Verb Authority rejects validation-time approval or external "
                "deferral paths"
            ) from None
        if type(validated) is not dict:
            raise ToolFailed("Verb Authority rejected non-plain validated arguments")
        try:
            snapshot = authority._snapshot_json_value(validated)
        except (TypeError, ValueError, RecursionError) as exc:
            raise ToolFailed(
                "Verb Authority rejected non-plain validated arguments"
            ) from exc
        if type(snapshot) is not dict:  # exact input check above is defensive
            raise ToolFailed("Verb Authority rejected non-plain validated arguments")
        if permit.selector is not None:
            try:
                validated_selector = _exact_selector_from_arguments(
                    snapshot,
                    permit.selector,
                )
            except PydanticAuthorityConfigurationError as exc:
                raise ToolFailed(str(exc)) from None
            if raw_selector != validated_selector:
                raise ToolFailed(
                    "Verb Authority rejected a selector whose presence, type, "
                    "value, or signed zero changed during Pydantic validation"
                )
        _mark_run_execution_permit_validated(
            ctx.root_capability,
            self,
            permit,
            _canonical_schema(snapshot, label="validated tool arguments"),
        )
        return snapshot

    async def wrap_tool_execute(
        self,
        ctx: RunContext[Any],
        *,
        call: Any,
        tool_def: ToolDefinition,
        args: dict[str, Any],
        handler: Callable[[dict[str, Any]], Any],
    ) -> Any:
        # `handler` is intentionally not called.  The exact Registry.fn frozen by
        # GuardedToolRunner is the only executable implementation in this beta.
        del handler
        _require_guarded_agent_run_transition(ctx)
        session = self._session(ctx)
        self._reject_execution_transformers(ctx)
        _sealed_tool_from_definition(tool_def)
        if type(args) is not dict:
            raise ToolFailed("Verb Authority rejected non-plain tool arguments")
        if type(tool_def) is not ToolDefinition or tool_def.kind != "function":
            raise ToolFailed("Verb Authority rejected an unsupported tool kind")
        if type(call.tool_name) is not str or call.tool_name != tool_def.name:
            raise ToolFailed("Verb Authority rejected inconsistent tool identity")
        if (
            not _bounded_tool_call_id(call.tool_call_id)
            or type(ctx.tool_call_id) is not str
            or ctx.tool_call_id != call.tool_call_id
        ):
            raise ToolFailed("Verb Authority rejected inconsistent tool-call identity")

        permit = _run_execution_permit(
            ctx,
            self,
            call,
            require_validated=True,
        )
        if (
            _canonical_schema(args, label="validated tool arguments")
            != permit.validated_args_json
        ):
            raise ToolFailed(
                "Verb Authority rejected tool arguments that changed after validation"
            )
        if permit.approved:
            with session._pending_lock:
                pending = session._pending.get(call.tool_call_id)
                if (
                    pending is None
                    or pending.action_id != permit.pending_action_id
                    or pending.call_commitment
                    != permit.pending_call_commitment
                ):
                    raise PydanticAuthorityConfigurationError(
                        "Verb Authority approved action commitment changed before "
                        "execution"
                    )
        elif (
            permit.pending_action_id is not None
            or permit.pending_call_commitment is not None
        ):
            raise PydanticAuthorityConfigurationError(
                "Verb Authority found an approval commitment on an unapproved call"
            )
        # Consume before trusted resolvers, callbacks, ledger writes, or Registry
        # invocation. Nested execution therefore cannot borrow this permission.
        _consume_run_execution_permit(ctx.root_capability, self, permit)

        try:
            prepared, trusted, evidence = session.prepare_call(tool_def.name, args)
            if permit.approved:
                prepared_json = _canonical_schema(
                    prepared,
                    label="prepared approved tool arguments",
                )
                with session._pending_lock:
                    pending = session._pending.get(call.tool_call_id)
                    if (
                        pending is None
                        or pending.action_id != permit.pending_action_id
                        or pending.call_commitment
                        != permit.pending_call_commitment
                        or not pending.matches_call(tool_def.name, prepared_json)
                    ):
                        session._pending.pop(call.tool_call_id, None)
                        raise PydanticAuthorityConfigurationError(
                            "Verb Authority rejected an approved tool call whose "
                            "tool, arguments, selector branch, or effective risk "
                            "changed before execution"
                        )
            captured: list[ConfirmationRequest] = []
            confirm = session.confirmation_callback(
                tool_call_id=call.tool_call_id,
                approved=ctx.tool_call_approved is True,
                evidence=evidence,
                captured=captured,
            )

            def execute_guarded():
                return session.runner.run(
                    {"name": tool_def.name, "input": prepared},
                    trusted_args=trusted,
                    confirm=confirm,
                )

            execution = await anyio.to_thread.run_sync(execute_guarded)
        except PydanticAuthorityResolutionError as exc:
            raise ToolFailed(str(exc)) from None
        except PydanticAuthorityConfigurationError as exc:
            raise ToolFailed(str(exc)) from None

        if execution.executed:
            return execution.result
        if execution.decision.allow and execution.decision.needs_confirm:
            if not captured:
                raise ToolFailed(
                    "Verb Authority could not construct a safe approval request"
                )
            raise ApprovalRequired(
                metadata=session.approval_metadata(captured[-1], evidence)
            )
        if execution.invoked:
            suffix = (
                f" ({execution.contract_violation})"
                if execution.contract_violation
                else ""
            )
            raise ToolFailed(
                "Verb Authority entered the tool but could not publish a safe "
                f"result{suffix}; do not retry automatically"
            )
        raise ToolFailed(execution.decision.reason)


def _static_capability_tree_seal(
    root: Any,
    *,
    managed: VerbAuthorityCapability,
    session_getter: Callable[[RunContext[Any]], PydanticAuthoritySession],
    expected_children: tuple[AbstractCapability[Any], ...] | None = None,
) -> tuple[Any, ...]:
    """Seal the pinned static tree without dispatching through ``root.apply``.

    A mutable CombinedCapability must never attest to its own contents through
    an overridable instance method.  Read the pinned private layout directly,
    validate every child, and retain the exact list and child identities.
    """

    if type(root) is not CombinedCapability:
        raise PydanticAuthorityConfigurationError(
            "PydanticAuthorityAgent requires the pinned CombinedCapability root"
        )
    _reject_capability_instance_hooks(root)
    root_state = vars(root)
    if (
        set(root_state) != {"id", "description", "defer_loading", "capabilities"}
        or root_state["id"] is not None
        or root_state["description"] is not None
        or root_state["defer_loading"] is not False
        or type(root_state["capabilities"]) is not list
    ):
        raise PydanticAuthorityConfigurationError(
            "PydanticAuthorityAgent rejects mutation of its capability root"
        )
    children = root_state["capabilities"]
    if len(children) != 3:
        raise PydanticAuthorityConfigurationError(
            "PydanticAuthorityAgent capability root requires exactly its three "
            "managed capabilities"
        )
    if expected_children is not None and (
        len(children) != len(expected_children)
        or any(actual is not expected for actual, expected in zip(children, expected_children))
    ):
        raise PydanticAuthorityConfigurationError(
            "PydanticAuthorityAgent rejects mutation of its capability root"
        )

    tool_search, pending_messages, actual_managed = children
    if type(tool_search) is not ToolSearch:
        raise PydanticAuthorityConfigurationError(
            "PydanticAuthorityAgent lost its pinned ToolSearch capability"
        )
    _reject_capability_instance_hooks(tool_search)
    search_state = vars(tool_search)
    if (
        set(search_state)
        != {
            "id",
            "description",
            "defer_loading",
            "strategy",
            "max_results",
            "tool_description",
            "parameter_description",
            "_search_fn",
        }
        or search_state["id"] is not None
        or search_state["description"] is not None
        or search_state["defer_loading"] is not False
        or search_state["strategy"] is not None
        or type(search_state["max_results"]) is not int
        or search_state["max_results"] != 10
        or search_state["tool_description"] is not None
        or search_state["parameter_description"] is not None
        or search_state["_search_fn"] is not None
    ):
        raise PydanticAuthorityConfigurationError(
            "PydanticAuthorityAgent rejects mutation of Pydantic's ToolSearch"
        )

    if type(pending_messages) is not PendingMessageDrainCapability:
        raise PydanticAuthorityConfigurationError(
            "PydanticAuthorityAgent lost its pending-message capability"
        )
    _reject_capability_instance_hooks(pending_messages)
    if vars(pending_messages):
        raise PydanticAuthorityConfigurationError(
            "PydanticAuthorityAgent rejects mutation of Pydantic's "
            "pending-message capability"
        )

    if (
        actual_managed is not managed
        or type(actual_managed) is not VerbAuthorityCapability
    ):
        raise PydanticAuthorityConfigurationError(
            "PydanticAuthorityAgent lost its managed Verb Authority capability"
        )
    _reject_capability_instance_hooks(actual_managed)
    managed_state = vars(actual_managed)
    if (
        set(managed_state)
        != {
            "id",
            "description",
            "defer_loading",
            "session_getter",
            "_statically_bound",
        }
        or managed_state["id"] is not None
        or managed_state["description"] is not None
        or managed_state["defer_loading"] is not False
        or managed_state["session_getter"] is not session_getter
        or managed_state["_statically_bound"] is not True
    ):
        raise PydanticAuthorityConfigurationError(
            "PydanticAuthorityAgent's managed capability seal changed"
        )

    return (
        id(root),
        id(children),
        tuple(id(child) for child in children),
        id(tool_search),
        id(pending_messages),
        id(actual_managed),
        id(session_getter),
    )


_RUN_ROOT_GUARDED_NAMES = _CAPABILITY_HOOK_NAMES | frozenset(
    {"_has_wrap_node_run", "has_wrap_run_event_stream", "has_resolve_model_id"}
)
_TOOL_MANAGER_METHOD_NAMES = frozenset(
    {
        "parallel_execution_mode",
        "for_run_step",
        "tool_defs",
        "get_parallel_execution_mode",
        "is_sequential",
        "get_tool_def",
        "_check_max_retries",
        "_wrap_error_as_retry",
        "_wrap_error_as_failed",
        "_build_tool_context",
        "_validate_tool_args",
        "_run_validate_hooks",
        "_run_execute_hooks",
        "_resolve_tool",
        "_unavailable_reason",
        "_make_validation_success",
        "_make_validation_failure",
        "validate_tool_call",
        "execute_tool_call",
        "validate_output_tool_call",
        "execute_output_tool_call",
        "handle_output_tool_call",
        "_execute_tool_call_impl",
        "_raw_execute",
        "handle_call",
        "resolve_deferred_tool_calls",
        "_resolve_single_deferred",
    }
)


@dataclass(frozen=True, slots=True)
class _RunRootSeal:
    ref: weakref.ReferenceType[Any]
    token: object
    children: tuple[Any, Any, VerbAuthorityCapability]
    session_getter: Any
    session: PydanticAuthoritySession
    user_deps: Any
    capabilities: dict[str, Any]
    capability_items: tuple[tuple[str, Any], ...]
    resume_marker: _ResumeMarker | None
    started_node: Any | None
    execution_permits: tuple[_ToolExecutionPermit, ...]


@dataclass(frozen=True, slots=True)
class _SessionRegistrationSeal:
    """External commitment to the runner's authoritative registration."""

    ref: weakref.ReferenceType[Any]
    runner: GuardedToolRunner
    bundle: Any
    policy_set: Any
    policy_selector: Any
    policy_selector_cases: Any
    registration_id: str
    selectors: Mapping[str, str]
    selector_case_shapes: Mapping[str, frozenset[frozenset[str]]]


@dataclass(frozen=True, slots=True)
class _ToolManagerSeal:
    ref: weakref.ReferenceType[Any]
    token: object
    root: Any
    toolset: Any
    toolset_seal: tuple[Any, ...]
    ctx: Any
    run_deps: Any
    tools: Any
    tools_seal: tuple[Any, ...] | None
    failed_tools: set[str]
    succeeded_tools: set[str]
    availability_refused: set[str]
    default_max_retries: int
    orig_class: Any
    predecessor: Any | None
    committed: bool


@dataclass(frozen=True, slots=True)
class _GraphDepsSeal:
    ref: weakref.ReferenceType[Any]
    token: object
    root: Any
    agent: "PydanticAuthorityAgent"
    session: PydanticAuthoritySession
    user_deps: Any
    capabilities: dict[str, Any]
    capability_items: tuple[tuple[str, Any], ...]
    loaded_capability_ids: set[str]
    discovered_tool_names: set[str]
    native_tools: list[Any]
    native_tool_items: tuple[Any, ...]
    manager: Any
    immutable: tuple[tuple[str, Any], ...]
    orig_class: Any


@dataclass(frozen=True, slots=True)
class _AgentRunSeal:
    ref: weakref.ReferenceType[Any]
    token: object
    graph_run: Any
    graph_type: type[Any]
    deps: Any
    graph_keys: frozenset[str]
    graph_immutable: tuple[tuple[str, Any], ...]
    iterator: Any
    iterator_type: type[Any]
    iterator_keys: frozenset[str]
    iterator_immutable: tuple[tuple[str, Any], ...]
    run_dynamic: tuple[tuple[str, Any], ...]
    graph_dynamic: tuple[tuple[str, Any], ...]
    iterator_dynamic: tuple[tuple[str, Any], ...]


@dataclass(frozen=True, slots=True)
class _AgentSeal:
    ref: weakref.ReferenceType[Any]
    root: Any
    root_seal: tuple[Any, ...]
    leaves: tuple[Any, ...]
    managed: VerbAuthorityCapability
    session_getter: Any
    function_toolset: Any
    function_toolset_seal: tuple[Any, ...]
    mapping: dict[str, Any]
    tools: tuple[tuple[str, PydanticTool[Any], tuple[Any, ...]], ...]
    user_toolsets: list[Any]
    dynamic_toolsets: list[Any]
    cap_toolsets: list[Any]
    override_vars: tuple[tuple[str, Any], ...]
    expected_fields: tuple[tuple[str, Any], ...]


_RUN_ROOT_SEALS: dict[int, _RunRootSeal] = {}
_SESSION_REGISTRATION_SEALS: dict[int, _SessionRegistrationSeal] = {}
_TOOL_MANAGER_SEALS: dict[int, _ToolManagerSeal] = {}
_GRAPH_DEPS_SEALS: dict[int, _GraphDepsSeal] = {}
_AGENT_RUN_SEALS: dict[int, _AgentRunSeal] = {}
_GRAPH_RUN_OWNERS: dict[int, weakref.ReferenceType[Any]] = {}
_AGENT_SEALS: dict[int, _AgentSeal] = {}


def _weak_store(table: dict[int, Any], value: Any, make: Any) -> None:
    key = id(value)

    def cleanup(ref: weakref.ReferenceType[Any]) -> None:
        current = table.get(key)
        if current is not None and current.ref is ref:
            table.pop(key, None)

    ref = weakref.ref(value, cleanup)
    table[key] = make(ref)


def _install_session_registration_seal(
    session: PydanticAuthoritySession,
    runner: GuardedToolRunner,
) -> None:
    """Freeze selector identity outside mutable public inspection aliases."""

    if (
        type(session) is not PydanticAuthoritySession
        or type(runner) is not GuardedToolRunner
    ):
        raise PydanticAuthorityConfigurationError(
            "Verb Authority requires exact session registration objects"
        )
    try:
        bundle = object.__getattribute__(runner, "_bundle")
    except Exception as exc:
        raise PydanticAuthorityConfigurationError(
            "Verb Authority could not seal the runner registration"
        ) from exc
    if type(bundle) is not authority._RegistrationBundle:
        raise PydanticAuthorityConfigurationError(
            "Verb Authority found malformed authoritative registration state"
        )
    policy_set = object.__getattribute__(bundle, "policy_set")
    registration_id = object.__getattribute__(bundle, "registration_id")
    if (
        type(policy_set) is not authority._FrozenPolicySet
        or type(registration_id) is not str
        or not registration_id
    ):
        raise PydanticAuthorityConfigurationError(
            "Verb Authority found malformed authoritative registration state"
        )
    policy_selector = object.__getattribute__(policy_set, "selector")
    policy_selector_cases = object.__getattribute__(
        policy_set,
        "selector_cases",
    )

    selectors: dict[str, str] = {}
    shapes: dict[str, frozenset[frozenset[str]]] = {}
    try:
        for tool_name, selector in policy_selector.items():
            if (
                type(tool_name) is not str
                or not tool_name
                or type(selector) is not str
                or not selector
            ):
                raise TypeError("malformed selector registration")
            selectors[tool_name] = selector
        if set(policy_selector_cases) != set(selectors):
            raise ValueError("selector cases do not match selectors")
        for tool_name, cases in policy_selector_cases.items():
            case_shapes: set[frozenset[str]] = set()
            for case in cases.values():
                active_args = case.active_args
                if type(active_args) is not tuple or any(
                    type(name) is not str or not name
                    for name in active_args
                ):
                    raise TypeError("malformed selector active arguments")
                case_shapes.add(frozenset(active_args))
            if not case_shapes:
                raise ValueError("selector registration has no cases")
            shapes[tool_name] = frozenset(case_shapes)
    except Exception as exc:
        raise PydanticAuthorityConfigurationError(
            "Verb Authority could not snapshot selector registration state"
        ) from exc

    sealed_selectors = MappingProxyType(selectors)
    sealed_shapes = MappingProxyType(shapes)
    _weak_store(
        _SESSION_REGISTRATION_SEALS,
        session,
        lambda ref: _SessionRegistrationSeal(
            ref=ref,
            runner=runner,
            bundle=bundle,
            policy_set=policy_set,
            policy_selector=policy_selector,
            policy_selector_cases=policy_selector_cases,
            registration_id=registration_id,
            selectors=sealed_selectors,
            selector_case_shapes=sealed_shapes,
        ),
    )


def _verify_session_registration_seal(
    session: PydanticAuthoritySession,
) -> _SessionRegistrationSeal:
    """Return the sealed selector map only for its exact frozen runner state."""

    seal = _SESSION_REGISTRATION_SEALS.get(id(session))
    if (
        type(session) is not PydanticAuthoritySession
        or seal is None
        or seal.ref() is not session
    ):
        raise PydanticAuthorityConfigurationError(
            "Verb Authority session registration seal changed"
        )
    try:
        runner = object.__getattribute__(session, "_runner")
    except Exception as exc:
        raise PydanticAuthorityConfigurationError(
            "Verb Authority session registration seal changed"
        ) from exc
    if runner is not seal.runner or type(runner) is not GuardedToolRunner:
        raise PydanticAuthorityConfigurationError(
            "Verb Authority session registration seal changed"
        )
    try:
        bundle = object.__getattribute__(runner, "_bundle")
    except Exception as exc:
        raise PydanticAuthorityConfigurationError(
            "Verb Authority session registration seal changed"
        ) from exc
    if bundle is not seal.bundle:
        raise PydanticAuthorityConfigurationError(
            "Verb Authority session registration seal changed"
        )
    policy_set = object.__getattribute__(bundle, "policy_set")
    if (
        policy_set is not seal.policy_set
        or policy_set.selector is not seal.policy_selector
        or policy_set.selector_cases is not seal.policy_selector_cases
        or bundle.registration_id != seal.registration_id
    ):
        raise PydanticAuthorityConfigurationError(
            "Verb Authority session registration seal changed"
        )
    return seal


def _session_selector(
    session: PydanticAuthoritySession,
    tool_name: str,
) -> str | None:
    """Read selector identity from the sealed authoritative registration."""

    return _verify_session_registration_seal(session).selectors.get(tool_name)


def _exact_descriptor(owner: type[Any], name: str, instance: Any) -> Any:
    for base in owner.__mro__:
        namespace = vars(base)
        if name not in namespace:
            continue
        descriptor = namespace[name]
        if isinstance(descriptor, staticmethod):
            return descriptor.__get__(None, type(instance))
        if isinstance(descriptor, classmethod):
            return descriptor.__get__(None, type(instance))
        return descriptor.__get__(instance, type(instance))
    raise PydanticAuthorityConfigurationError(
        f"pinned Pydantic entry point disappeared: {name}"
    )


def _identity_items_match(
    actual: Mapping[str, Any],
    expected: tuple[tuple[str, Any], ...],
) -> bool:
    items = tuple(actual.items())
    return len(items) == len(expected) and all(
        actual_name == expected_name and actual_value is expected_value
        for (actual_name, actual_value), (expected_name, expected_value)
        in zip(items, expected)
    )


def _verify_run_tree(root: Any) -> _RunRootSeal:
    seal = _RUN_ROOT_SEALS.get(id(root))
    if seal is None or seal.ref() is not root or type(root) is not _PinnedRunRoot:
        raise PydanticAuthorityConfigurationError(
            "Pydantic run capability root is not pinned"
        )
    state = object.__getattribute__(root, "__dict__")
    if (
        set(state) != {"id", "description", "defer_loading", "capabilities"}
        or state["id"] is not None
        or state["description"] is not None
        or state["defer_loading"] is not False
        or type(state["capabilities"]) is not tuple
        or len(state["capabilities"]) != len(seal.children)
        or any(
            actual is not expected
            for actual, expected in zip(state["capabilities"], seal.children)
        )
        or type(seal.capabilities) is not dict
        or not _identity_items_match(seal.capabilities, seal.capability_items)
    ):
        raise PydanticAuthorityConfigurationError(
            "Pydantic run capability root changed"
        )

    tool_search, pending, managed = seal.children
    _reject_capability_instance_hooks(tool_search)
    search_state = vars(tool_search)
    if (
        type(tool_search) is not ToolSearch
        or set(search_state)
        != {
            "id",
            "description",
            "defer_loading",
            "strategy",
            "max_results",
            "tool_description",
            "parameter_description",
            "_search_fn",
        }
        or search_state["id"] is not None
        or search_state["description"] is not None
        or search_state["defer_loading"] is not False
        or search_state["strategy"] is not None
        or type(search_state["max_results"]) is not int
        or search_state["max_results"] != 10
        or search_state["tool_description"] is not None
        or search_state["parameter_description"] is not None
        or search_state["_search_fn"] is not None
    ):
        raise PydanticAuthorityConfigurationError("Pydantic ToolSearch changed")

    _reject_capability_instance_hooks(pending)
    if type(pending) is not PendingMessageDrainCapability or vars(pending):
        raise PydanticAuthorityConfigurationError(
            "Pydantic pending-message capability changed"
        )

    _reject_capability_instance_hooks(managed)
    managed_state = vars(managed)
    allowed_keys = {
        "id",
        "description",
        "defer_loading",
        "session_getter",
        "_statically_bound",
        "_bound_session",
    }
    if (
        type(managed) is not VerbAuthorityCapability
        or set(managed_state) not in (allowed_keys, allowed_keys | {"_resume_marker"})
        or managed_state["id"] is not None
        or managed_state["description"] is not None
        or managed_state["defer_loading"] is not False
        or managed_state["session_getter"] is not seal.session_getter
        or managed_state["_statically_bound"] is not True
        or managed_state["_bound_session"] is not seal.session
        or managed_state.get("_resume_marker") is not None
    ):
        raise PydanticAuthorityConfigurationError(
            "Verb Authority per-run capability changed"
        )
    return seal


def _replace_run_resume_marker(
    root: Any,
    managed: VerbAuthorityCapability,
    marker: _ResumeMarker | None,
) -> None:
    seal = _verify_run_tree(root)
    if seal.children[2] is not managed:
        raise PydanticAuthorityConfigurationError(
            "approval transition capability changed"
        )
    _RUN_ROOT_SEALS[id(root)] = replace(seal, resume_marker=marker)


def _replace_run_execution_permits(
    root: Any,
    managed: VerbAuthorityCapability,
    permits: tuple[_ToolExecutionPermit, ...],
) -> None:
    """Replace the bounded one-node tool-call permit set atomically."""

    seal = _verify_run_tree(root)
    if seal.children[2] is not managed:
        raise PydanticAuthorityConfigurationError(
            "tool execution capability changed"
        )
    if (
        type(permits) is not tuple
        or len(permits) > _MAX_PENDING_APPROVALS
        or any(type(permit) is not _ToolExecutionPermit for permit in permits)
    ):
        raise PydanticAuthorityConfigurationError(
            "Verb Authority rejects malformed tool execution permits"
        )
    _RUN_ROOT_SEALS[id(root)] = replace(seal, execution_permits=permits)


def _claim_run_node_start(
    root: Any,
    managed: VerbAuthorityCapability,
    run: Any,
    node: Any,
) -> None:
    """Claim one exact graph node before any lifecycle callback can run."""

    seal = _verify_run_tree(root)
    if seal.children[2] is not managed:
        raise PydanticAuthorityConfigurationError(
            "tool execution capability changed"
        )
    run_seal = _verify_agent_run(run)
    if (
        run_seal.token is not seal.token
        or run_seal.deps.root_capability is not root
    ):
        raise PydanticAuthorityConfigurationError(
            "Pydantic graph node lost its sealed AgentRun identity"
        )
    if seal.started_node is node:
        raise PydanticAuthorityConfigurationError(
            "Pydantic graph node lifecycle attempted to start twice"
        )
    # Mark first and clear the preceding node's permits in one external-seal
    # update. Context variables are copied into child tasks; such a child may
    # retain the transition token, but it cannot re-enter this node and re-arm
    # an already consumed execution permit.
    _RUN_ROOT_SEALS[id(root)] = replace(
        seal,
        started_node=node,
        execution_permits=(),
    )


def _run_execution_permit(
    ctx: RunContext[Any],
    managed: VerbAuthorityCapability,
    call: ToolCallPart,
    *,
    require_validated: bool,
) -> _ToolExecutionPermit:
    """Return the unique permit for this exact call and lifecycle stage."""

    root = ctx.root_capability
    seal = _verify_run_tree(root)
    if seal.children[2] is not managed:
        raise PydanticAuthorityConfigurationError(
            "tool execution capability changed"
        )
    matches = tuple(
        permit for permit in seal.execution_permits if permit.call is call
    )
    if len(matches) != 1:
        raise PydanticAuthorityConfigurationError(
            "Pydantic tool call has no unique current-node execution permit"
        )
    permit = matches[0]
    if (
        type(call) is not ToolCallPart
        or permit.run_id != ctx.run_id
        or permit.tool_name != call.tool_name
        or permit.tool_call_id != call.tool_call_id
        or (
            permit.selector is not None
            and (type(permit.selector) is not str or not permit.selector)
        )
        or permit.approved is not (ctx.tool_call_approved is True)
        or (require_validated and permit.validated_args_json is None)
    ):
        raise PydanticAuthorityConfigurationError(
            "Pydantic tool execution permit no longer matches its exact call"
        )
    return permit


def _mark_run_execution_permit_validated(
    root: Any,
    managed: VerbAuthorityCapability,
    permit: _ToolExecutionPermit,
    validated_args_json: str,
) -> None:
    """Bind one raw-call permit to the exact post-validation arguments."""

    seal = _verify_run_tree(root)
    if seal.children[2] is not managed:
        raise PydanticAuthorityConfigurationError(
            "tool execution capability changed"
        )
    positions = [
        index
        for index, current in enumerate(seal.execution_permits)
        if current is permit
    ]
    if len(positions) != 1 or permit.validated_args_json is not None:
        raise PydanticAuthorityConfigurationError(
            "Pydantic tool validation attempted to reuse an execution permit"
        )
    updated = list(seal.execution_permits)
    updated[positions[0]] = replace(
        permit,
        validated_args_json=validated_args_json,
    )
    _replace_run_execution_permits(root, managed, tuple(updated))


def _consume_run_execution_permit(
    root: Any,
    managed: VerbAuthorityCapability,
    permit: _ToolExecutionPermit,
) -> None:
    """Consume the exact permit before any resolver, ledger, or tool side effect."""

    seal = _verify_run_tree(root)
    if seal.children[2] is not managed:
        raise PydanticAuthorityConfigurationError(
            "tool execution capability changed"
        )
    positions = [
        index
        for index, current in enumerate(seal.execution_permits)
        if current is permit
    ]
    if len(positions) != 1 or permit.validated_args_json is None:
        raise PydanticAuthorityConfigurationError(
            "Pydantic tool execution attempted to reuse an execution permit"
        )
    remaining = tuple(
        current
        for index, current in enumerate(seal.execution_permits)
        if index != positions[0]
    )
    _replace_run_execution_permits(root, managed, remaining)


def _consume_run_resume_marker(
    root: Any,
    managed: VerbAuthorityCapability,
) -> _ResumeMarker | None:
    seal = _verify_run_tree(root)
    marker = seal.resume_marker
    _replace_run_resume_marker(root, managed, None)
    return marker


class _PinnedRunRoot(CombinedCapability[Any]):
    __slots__ = ()

    def __setattr__(self, name: str, value: Any) -> None:
        if id(self) in _RUN_ROOT_SEALS:
            raise PydanticAuthorityConfigurationError(
                "Pydantic run capability root is immutable"
            )
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        if id(self) in _RUN_ROOT_SEALS:
            raise PydanticAuthorityConfigurationError(
                "Pydantic run capability root is immutable"
            )
        object.__delattr__(self, name)

    def __getattribute__(self, name: str) -> Any:
        if name in _RUN_ROOT_GUARDED_NAMES and id(self) in _RUN_ROOT_SEALS:
            _verify_run_tree(self)
            if name == "wrap_run":
                return _PinnedRunRoot._va_wrap_run.__get__(self, type(self))
            if name == "before_run":
                return _PinnedRunRoot._va_before_run.__get__(self, type(self))
            return _exact_descriptor(CombinedCapability, name, self)
        return object.__getattribute__(self, name)

    async def _va_wrap_run(self, ctx: RunContext[Any], *, handler: Any) -> Any:
        manager = _ensure_pinned_tool_manager(ctx.tool_manager, self)
        _verify_run_context(ctx, self, manager)
        return await CombinedCapability.wrap_run(self, ctx, handler=handler)

    async def _va_before_run(self, ctx: RunContext[Any]) -> None:
        manager = _ensure_pinned_tool_manager(ctx.tool_manager, self)
        _verify_run_context(ctx, self, manager)
        await CombinedCapability.before_run(self, ctx)


def _pin_run_root(
    root: Any,
    session_getter: Any,
    capabilities: Any,
    user_deps: Any,
) -> _PinnedRunRoot:
    if type(root) is not CombinedCapability:
        raise PydanticAuthorityConfigurationError(
            "resolved Pydantic run root changed type"
        )
    _reject_capability_instance_hooks(root)
    state = vars(root)
    if (
        set(state) != {"id", "description", "defer_loading", "capabilities"}
        or state["id"] is not None
        or state["description"] is not None
        or state["defer_loading"] is not False
        or type(state["capabilities"]) is not list
        or len(state["capabilities"]) != 3
        or type(capabilities) is not dict
        or len(capabilities) != 3
    ):
        raise PydanticAuthorityConfigurationError(
            "resolved Pydantic run root has an unsupported shape"
        )
    children = tuple(state["capabilities"])
    capability_items = tuple(capabilities.items())
    if len(capability_items) != len(children) or any(
        actual is not expected
        for (_, actual), expected in zip(capability_items, children)
    ):
        raise PydanticAuthorityConfigurationError(
            "resolved Pydantic capability aliases changed"
        )
    managed = children[2]
    if type(managed) is not VerbAuthorityCapability:
        raise PydanticAuthorityConfigurationError(
            "resolved Pydantic run root lost Verb Authority"
        )
    session = vars(managed).get("_bound_session")
    if type(session) is not PydanticAuthoritySession:
        raise PydanticAuthorityConfigurationError(
            "resolved Verb Authority capability has no exact session"
        )
    object.__setattr__(root, "capabilities", children)
    object.__setattr__(root, "__class__", _PinnedRunRoot)
    token = object()
    capability_items = tuple(capabilities.items())
    _weak_store(
        _RUN_ROOT_SEALS,
        root,
        lambda ref: _RunRootSeal(
            ref=ref,
            token=token,
            children=children,  # type: ignore[arg-type]
            session_getter=session_getter,
            session=session,
            user_deps=user_deps,
            capabilities=capabilities,
            capability_items=capability_items,
            resume_marker=None,
            started_node=None,
            execution_permits=(),
        ),
    )
    _verify_run_tree(root)
    return root


def _runtime_tool_definition_seal(tool_def: Any) -> tuple[Any, ...]:
    schema_tool = _sealed_tool_from_definition(tool_def)
    state = vars(tool_def)
    return (
        tuple(sorted(state)),
        id(tool_def),
        id(schema_tool),
        tool_def.name,
        tool_def.description,
        tool_def.outer_typed_dict_key,
        tool_def.strict,
        tool_def.sequential,
        tool_def.kind,
        id(tool_def.metadata),
        id(tool_def.metadata[_SCHEMA_TOOL_METADATA_KEY]),
        tool_def.timeout,
        tool_def.defer_loading,
        tool_def.unless_native,
        tool_def.with_native,
        tool_def.tool_kind,
        tool_def.include_return_schema,
        tool_def.toolset_id,
        tool_def.capability_id,
        _canonical_schema(
            tool_def.parameters_json_schema,
            label="runtime tool schema",
        ),
        _canonical_schema(tool_def.return_schema, label="runtime return schema"),
    )


def _runtime_toolset_seal(toolset: Any) -> tuple[Any, ...]:
    if type(toolset) is not ToolSearchToolset:
        raise PydanticAuthorityConfigurationError(
            "run ToolSearchToolset changed"
        )
    top = vars(toolset)
    if (
        set(top)
        != {
            "wrapped",
            "search_fn",
            "max_results",
            "tool_description",
            "parameter_description",
            "enable_fallback",
            "max_retries",
        }
        or top["search_fn"] is not None
        or top["max_results"] != 10
        or top["tool_description"] is not None
        or top["parameter_description"] is not None
        or top["enable_fallback"] is not True
        or top["max_retries"] is not None
    ):
        raise PydanticAuthorityConfigurationError(
            "run ToolSearchToolset changed"
        )
    prepared = top["wrapped"]
    if type(prepared) is not PreparedToolset:
        raise PydanticAuthorityConfigurationError("run PreparedToolset changed")
    prepared_state = vars(prepared)
    if set(prepared_state) != {"wrapped", "prepare_func"} or not callable(
        prepared_state["prepare_func"]
    ):
        raise PydanticAuthorityConfigurationError("run PreparedToolset changed")
    combined = prepared_state["wrapped"]
    if type(combined) is not CombinedToolset:
        raise PydanticAuthorityConfigurationError("run CombinedToolset changed")
    combined_state = vars(combined)
    if (
        set(combined_state) not in ({"toolsets"}, {"toolsets", "_exit_stack"})
        or type(combined_state["toolsets"]) is not list
        or len(combined_state["toolsets"]) != 1
        or (
            combined_state.get("_exit_stack") is not None
            and type(combined_state["_exit_stack"]) is not AsyncExitStack
        )
    ):
        raise PydanticAuthorityConfigurationError("run CombinedToolset changed")
    function_toolset = combined_state["toolsets"][0]
    function_seal = _function_toolset_seal(function_toolset)
    return (
        id(toolset),
        id(prepared),
        id(prepared_state["prepare_func"]),
        id(combined),
        id(combined_state["toolsets"]),
        id(function_toolset),
        function_seal,
    )


def _runtime_manager_tools_seal(tools: Any) -> tuple[Any, ...] | None:
    if tools is None:
        return None
    if type(tools) is not dict:
        raise PydanticAuthorityConfigurationError(
            "ToolManager tools changed type"
        )
    result: list[Any] = []
    for name, tool in tools.items():
        if type(name) is not str or type(tool) is not _CombinedToolsetTool:
            raise PydanticAuthorityConfigurationError(
                "ToolManager tool changed type"
            )
        state = vars(tool)
        if set(state) != {
            "toolset",
            "tool_def",
            "max_retries",
            "args_validator",
            "args_validator_func",
            "source_toolset",
            "source_tool",
        }:
            raise PydanticAuthorityConfigurationError(
                "ToolManager tool changed shape"
            )
        source = state["source_tool"]
        if type(source) is not FunctionToolsetTool:
            raise PydanticAuthorityConfigurationError(
                "ToolManager source tool changed"
            )
        source_state = vars(source)
        if set(source_state) != {
            "toolset",
            "tool_def",
            "max_retries",
            "args_validator",
            "args_validator_func",
            "call_func",
            "is_async",
            "timeout",
            "original_name",
        }:
            raise PydanticAuthorityConfigurationError(
                "ToolManager source tool changed"
            )
        schema_tool = _sealed_tool_from_definition(state["tool_def"])
        if (
            state["toolset"] is not state["source_toolset"]
            or state["source_toolset"] is not source_state["toolset"]
            or state["args_validator"] is not schema_tool.function_schema.validator
            or state["args_validator_func"] is not None
            or source_state["args_validator"] is not state["args_validator"]
            or source_state["args_validator_func"] is not None
            or source_state["is_async"] is not False
            or source_state["timeout"] is not None
            or source_state["original_name"] != name
            or type(source_state["call_func"]) is not MethodType
            or source_state["call_func"].__self__
            is not schema_tool.function_schema
            or source_state["call_func"].__func__ is not FunctionSchema.call
        ):
            raise PydanticAuthorityConfigurationError(
                "ToolManager tool callbacks changed"
            )
        result.append(
            (
                name,
                id(tool),
                id(state["toolset"]),
                _runtime_tool_definition_seal(state["tool_def"]),
                state["max_retries"],
                id(state["args_validator"]),
                id(source),
                _runtime_tool_definition_seal(source_state["tool_def"]),
                source_state["max_retries"],
                id(source_state["call_func"]),
            )
        )
    return tuple(result)


def _verify_run_context(
    ctx: Any,
    root: Any,
    manager: Any | None = None,
) -> None:
    if (
        type(ctx) is not RunContext
        or ctx.root_capability is not root
        or ctx.deps is not _verify_run_tree(root).user_deps
        or (manager is not None and ctx.tool_manager is not manager)
    ):
        raise PydanticAuthorityConfigurationError(
            "Pydantic RunContext aliases changed"
        )
    seal = _verify_run_tree(root)
    capabilities = ctx.capabilities
    if (
        capabilities is not seal.capabilities
        or type(capabilities) is not dict
        or not _identity_items_match(capabilities, seal.capability_items)
    ):
        raise PydanticAuthorityConfigurationError(
            "Pydantic RunContext capabilities changed"
        )


def _verify_tool_manager(
    manager: Any,
    *,
    allow_provisional: bool = False,
) -> _ToolManagerSeal:
    seal = _TOOL_MANAGER_SEALS.get(id(manager))
    if (
        seal is None
        or seal.ref() is not manager
        or type(manager) is not _PinnedToolManager
    ):
        raise PydanticAuthorityConfigurationError(
            "Pydantic ToolManager is not pinned"
        )
    state = object.__getattribute__(manager, "__dict__")
    valid_keys = {
        "toolset",
        "root_capability",
        "ctx",
        "tools",
        "failed_tools",
        "succeeded_tools",
        "availability_refused",
        "default_max_retries",
    }
    if (
        set(state) not in (valid_keys, valid_keys | {"__orig_class__"})
        or state["root_capability"] is not seal.root
        or state["toolset"] is not seal.toolset
        or state["ctx"] is not seal.ctx
        or (
            state["ctx"] is not None
            and state["ctx"].deps is not seal.run_deps
        )
        or state["tools"] is not seal.tools
        or state["failed_tools"] is not seal.failed_tools
        or state["succeeded_tools"] is not seal.succeeded_tools
        or state["availability_refused"] is not seal.availability_refused
        or type(state["default_max_retries"]) is not int
        or state["default_max_retries"] != seal.default_max_retries
        or state.get("__orig_class__") is not seal.orig_class
        or type(state["failed_tools"]) is not set
        or type(state["succeeded_tools"]) is not set
        or type(state["availability_refused"]) is not set
        or not all(type(item) is str for item in state["failed_tools"])
        or not all(type(item) is str for item in state["succeeded_tools"])
        or not all(type(item) is str for item in state["availability_refused"])
        or _runtime_toolset_seal(state["toolset"]) != seal.toolset_seal
        or _runtime_manager_tools_seal(state["tools"]) != seal.tools_seal
    ):
        raise PydanticAuthorityConfigurationError("Pydantic ToolManager changed")
    root_seal = _verify_run_tree(seal.root)
    if root_seal.token is not seal.token:
        raise PydanticAuthorityConfigurationError(
            "Pydantic ToolManager run identity changed"
        )
    if not seal.committed and not allow_provisional:
        raise PydanticAuthorityConfigurationError(
            "Pydantic ToolManager successor is not committed"
        )
    if seal.committed and state["ctx"] is not None:
        _verify_run_context(state["ctx"], seal.root, manager)
    return seal


class _PinnedToolManager(ToolManager[Any]):
    __slots__ = ()

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        ToolManager.__init__(self, *args, **kwargs)
        _register_tool_manager(self)

    def __setattr__(self, name: str, value: Any) -> None:
        if id(self) in _TOOL_MANAGER_SEALS:
            raise PydanticAuthorityConfigurationError(
                "Pydantic ToolManager is immutable"
            )
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        if id(self) in _TOOL_MANAGER_SEALS:
            raise PydanticAuthorityConfigurationError(
                "Pydantic ToolManager is immutable"
            )
        object.__delattr__(self, name)

    def __getattribute__(self, name: str) -> Any:
        if id(self) in _TOOL_MANAGER_SEALS:
            _verify_tool_manager(self)
            if name == "for_run_step":
                return _PinnedToolManager._va_for_run_step.__get__(
                    self, type(self)
                )
            if name in _TOOL_MANAGER_METHOD_NAMES:
                return _exact_descriptor(ToolManager, name, self)
        return object.__getattribute__(self, name)

    async def _va_for_run_step(self, ctx: RunContext[Any]) -> Any:
        successor = await ToolManager.for_run_step(self, ctx)
        if successor is not self:
            successor_seal = _verify_tool_manager(
                successor,
                allow_provisional=True,
            )
            current_seal = _verify_tool_manager(self)
            if (
                successor_seal.token is not current_seal.token
                or successor_seal.root is not current_seal.root
                or successor_seal.predecessor is not self
                or successor_seal.committed is not False
                or successor_seal.ctx.tool_manager is not successor
            ):
                raise PydanticAuthorityConfigurationError(
                    "Pydantic ToolManager successor changed"
                )
            _TOOL_MANAGER_SEALS[id(successor)] = replace(
                successor_seal,
                predecessor=self,
                committed=True,
            )
            _verify_tool_manager(successor)
        return successor


def _register_tool_manager(manager: _PinnedToolManager) -> None:
    state = object.__getattribute__(manager, "__dict__")
    valid_keys = {
        "toolset",
        "root_capability",
        "ctx",
        "tools",
        "failed_tools",
        "succeeded_tools",
        "availability_refused",
        "default_max_retries",
    }
    if set(state) not in (valid_keys, valid_keys | {"__orig_class__"}):
        raise PydanticAuthorityConfigurationError(
            "Pydantic ToolManager shape changed"
        )
    root = state["root_capability"]
    root_seal = _verify_run_tree(root)
    predecessor = None
    committed = state["ctx"] is None
    if not committed:
        predecessor = state["ctx"].tool_manager
        predecessor_seal = _verify_tool_manager(predecessor)
        if (
            predecessor_seal.root is not root
            or predecessor_seal.token is not root_seal.token
        ):
            raise PydanticAuthorityConfigurationError(
                "Pydantic ToolManager predecessor changed"
            )
    toolset_seal = _runtime_toolset_seal(state["toolset"])
    tools_seal = _runtime_manager_tools_seal(state["tools"])
    _weak_store(
        _TOOL_MANAGER_SEALS,
        manager,
        lambda ref: _ToolManagerSeal(
            ref=ref,
            token=root_seal.token,
            root=root,
            toolset=state["toolset"],
            toolset_seal=toolset_seal,
            ctx=state["ctx"],
            run_deps=(None if state["ctx"] is None else state["ctx"].deps),
            tools=state["tools"],
            tools_seal=tools_seal,
            failed_tools=state["failed_tools"],
            succeeded_tools=state["succeeded_tools"],
            availability_refused=state["availability_refused"],
            default_max_retries=state["default_max_retries"],
            orig_class=state.get("__orig_class__"),
            predecessor=predecessor,
            committed=committed,
        ),
    )
    _verify_tool_manager(manager, allow_provisional=not committed)


def _ensure_pinned_tool_manager(
    manager: Any,
    root: _PinnedRunRoot,
) -> _PinnedToolManager:
    if type(manager) is _PinnedToolManager:
        seal = _verify_tool_manager(manager)
        if seal.root is not root:
            raise PydanticAuthorityConfigurationError(
                "ToolManager root alias changed"
            )
        return manager
    if (
        type(manager) is not ToolManager
        or vars(manager).get("root_capability") is not root
    ):
        raise PydanticAuthorityConfigurationError(
            "unexpected Pydantic ToolManager"
        )
    object.__setattr__(manager, "__class__", _PinnedToolManager)
    _register_tool_manager(manager)
    return manager


_GRAPH_DEPS_MUTABLE_FIELDS = frozenset(
    {
        "prompt",
        "new_message_index",
        "resumed_request",
        "resumed_request_index",
        "model",
        "model_id",
        "model_selected_for_step",
        "tool_manager",
    }
)
_GRAPH_DEPS_IMMUTABLE_FIELDS = (
    "model_selector",
    "evaluate_model_selector",
    "enter_model",
    "get_model_settings",
    "usage_limits",
    "max_output_retries",
    "end_strategy",
    "get_instructions",
    "output_schema",
    "output_validators",
    "validation_context",
    "tracer",
    "instrumentation_settings",
    "cancellation",
)


def _verify_graph_deps(deps: Any) -> _GraphDepsSeal:
    seal = _GRAPH_DEPS_SEALS.get(id(deps))
    if (
        seal is None
        or seal.ref() is not deps
        or type(deps) is not _PinnedGraphAgentDeps
    ):
        raise PydanticAuthorityConfigurationError(
            "Pydantic graph deps are not pinned"
        )
    state = object.__getattribute__(deps, "__dict__")
    expected_keys = {
        "user_deps",
        "prompt",
        "new_message_index",
        "resumed_request",
        "resumed_request_index",
        "model",
        "model_selector",
        "model_selected_for_step",
        "evaluate_model_selector",
        "enter_model",
        "get_model_settings",
        "usage_limits",
        "max_output_retries",
        "end_strategy",
        "get_instructions",
        "output_schema",
        "output_validators",
        "validation_context",
        "root_capability",
        "capabilities",
        "loaded_capability_ids",
        "discovered_tool_names",
        "native_tools",
        "tool_manager",
        "tracer",
        "instrumentation_settings",
        "agent",
        "cancellation",
        "model_id",
        "__orig_class__",
    }
    root_seal = _verify_run_tree(seal.root)
    if (
        set(state) != expected_keys
        or root_seal.token is not seal.token
        or state["root_capability"] is not seal.root
        or state["agent"] is not seal.agent
        or state["user_deps"] is not seal.user_deps
        or state["capabilities"] is not seal.capabilities
        or type(state["capabilities"]) is not dict
        or not _identity_items_match(
            state["capabilities"], seal.capability_items
        )
        or not _identity_items_match(
            root_seal.capabilities, seal.capability_items
        )
        or state["loaded_capability_ids"] is not seal.loaded_capability_ids
        or type(state["loaded_capability_ids"]) is not set
        or not all(type(item) is str for item in state["loaded_capability_ids"])
        or state["discovered_tool_names"] is not seal.discovered_tool_names
        or type(state["discovered_tool_names"]) is not set
        or not all(type(item) is str for item in state["discovered_tool_names"])
        or state["native_tools"] is not seal.native_tools
        or type(state["native_tools"]) is not list
        or len(state["native_tools"]) != len(seal.native_tool_items)
        or any(
            actual is not expected
            for actual, expected in zip(
                state["native_tools"], seal.native_tool_items
            )
        )
        or state["tool_manager"] is not seal.manager
        or state.get("__orig_class__") is not seal.orig_class
        or any(state[name] is not expected for name, expected in seal.immutable)
    ):
        raise PydanticAuthorityConfigurationError("Pydantic graph deps changed")
    manager_seal = _verify_tool_manager(state["tool_manager"])
    if (
        manager_seal.root is not seal.root
        or manager_seal.token is not seal.token
    ):
        raise PydanticAuthorityConfigurationError(
            "Pydantic graph manager root changed"
        )
    return seal


def _validate_graph_assignment(
    deps: Any,
    seal: _GraphDepsSeal,
    name: str,
    value: Any,
) -> None:
    if name == "tool_manager":
        manager_seal = _verify_tool_manager(value)
        if (
            manager_seal.root is not seal.root
            or manager_seal.token is not seal.token
            or (
                value is not seal.manager
                and manager_seal.predecessor is not seal.manager
            )
        ):
            raise PydanticAuthorityConfigurationError(
                "Pydantic graph manager transition changed"
            )
        if value is not seal.manager:
            _GRAPH_DEPS_SEALS[id(deps)] = replace(seal, manager=value)
    elif name == "new_message_index":
        if type(value) is not int or value < 0:
            raise PydanticAuthorityConfigurationError(
                "Pydantic graph index changed type"
            )
    elif name in {"resumed_request_index", "model_selected_for_step"}:
        if value is not None and (type(value) is not int or value < 0):
            raise PydanticAuthorityConfigurationError(
                "Pydantic graph index changed type"
            )
    elif name == "model_id":
        if value is not None and type(value) is not str:
            raise PydanticAuthorityConfigurationError(
                "Pydantic graph model id changed type"
            )


class _PinnedGraphAgentDeps(GraphAgentDeps[Any, Any]):
    __slots__ = ()

    def __setattr__(self, name: str, value: Any) -> None:
        if id(self) not in _GRAPH_DEPS_SEALS:
            object.__setattr__(self, name, value)
            return
        seal = _verify_graph_deps(self)
        if name not in _GRAPH_DEPS_MUTABLE_FIELDS:
            raise PydanticAuthorityConfigurationError(
                "Pydantic graph deps are immutable"
            )
        _validate_graph_assignment(self, seal, name, value)
        object.__setattr__(self, name, value)
        _verify_graph_deps(self)

    def __delattr__(self, name: str) -> None:
        if id(self) in _GRAPH_DEPS_SEALS:
            raise PydanticAuthorityConfigurationError(
                "Pydantic graph deps are immutable"
            )
        object.__delattr__(self, name)

    def __getattribute__(self, name: str) -> Any:
        if id(self) in _GRAPH_DEPS_SEALS:
            _verify_graph_deps(self)
        return object.__getattribute__(self, name)


def _pin_graph_deps(
    deps: Any,
    *,
    root: _PinnedRunRoot,
    agent: "PydanticAuthorityAgent",
) -> _PinnedGraphAgentDeps:
    if type(deps) is not GraphAgentDeps:
        raise PydanticAuthorityConfigurationError(
            "unexpected Pydantic graph deps"
        )
    root_seal = _verify_run_tree(root)
    state = vars(deps)
    manager_seal = _verify_tool_manager(state.get("tool_manager"))
    if (
        state.get("root_capability") is not root
        or manager_seal.root is not root
        or manager_seal.token is not root_seal.token
        or state.get("agent") is not agent
        or state.get("user_deps") is not root_seal.user_deps
        or state.get("capabilities") is not root_seal.capabilities
        or type(state.get("capabilities")) is not dict
        or not _identity_items_match(
            state["capabilities"], root_seal.capability_items
        )
        or type(state.get("loaded_capability_ids")) is not set
        or type(state.get("discovered_tool_names")) is not set
        or type(state.get("native_tools")) is not list
    ):
        raise PydanticAuthorityConfigurationError(
            "Pydantic graph aliases changed before pin"
        )
    immutable = tuple(
        (name, state[name]) for name in _GRAPH_DEPS_IMMUTABLE_FIELDS
    )
    object.__setattr__(deps, "__class__", _PinnedGraphAgentDeps)
    _weak_store(
        _GRAPH_DEPS_SEALS,
        deps,
        lambda ref: _GraphDepsSeal(
            ref=ref,
            token=root_seal.token,
            root=root,
            agent=agent,
            session=root_seal.session,
            user_deps=state["user_deps"],
            capabilities=state["capabilities"],
            capability_items=tuple(state["capabilities"].items()),
            loaded_capability_ids=state["loaded_capability_ids"],
            discovered_tool_names=state["discovered_tool_names"],
            native_tools=state["native_tools"],
            native_tool_items=tuple(state["native_tools"]),
            manager=state["tool_manager"],
            immutable=immutable,
            orig_class=state.get("__orig_class__"),
        ),
    )
    _verify_graph_deps(deps)
    return deps


_AGENT_RUN_EXACT_DISPATCH = frozenset(
    {
        "ctx",
        "next_node",
        "result",
        "_traceparent",
        "_task_to_node",
        "_node_to_task",
        "_sync_graph_state",
        "_graph_pending_node",
        "_graph_reflects",
    }
)
_AGENT_RUN_WRAPPED_DISPATCH = {
    "next": "_va_next",
    "_run_node_with_hooks": "_va_run_node_with_hooks",
    "_wrap_and_advance": "_va_wrap_and_advance",
    "_advance_graph": "_va_advance_graph",
    "_stream_and_advance": "_va_stream_and_advance",
}
_AGENT_RUN_GUARDED_NAMES = (
    _AGENT_RUN_EXACT_DISPATCH
    | frozenset(_AGENT_RUN_WRAPPED_DISPATCH)
    | frozenset({"_graph_run"})
)
_AGENT_RUN_MUTABLE_FIELDS = frozenset(
    {"_result_override", "_node_error", "_last_yielded_node"}
)
_AGENT_RUN_DYNAMIC_NAMES = tuple(sorted(_AGENT_RUN_MUTABLE_FIELDS))
_GRAPH_RUN_DYNAMIC_NAMES = ("_next", "_next_task_id", "_next_node_run_id")
_GRAPH_ITERATOR_DYNAMIC_NAMES = ("_next_node_run_id",)
_AGENT_RUN_TRANSITION: ContextVar[
    tuple[int, object, asyncio.Task[Any]] | None
] = ContextVar(
    "verb_authority_pydantic_agent_run_transition",
    default=None,
)
_AGENT_ITER_ENTRY: ContextVar[
    tuple[int, object, asyncio.Task[Any]] | None
] = ContextVar(
    "verb_authority_pydantic_agent_iter_entry",
    default=None,
)


def _execution_value_stamp(
    value: Any,
    *,
    depth: int = 5,
    seen: set[int] | None = None,
) -> tuple[Any, ...]:
    """Snapshot runtime state without invoking application-defined methods."""

    value_type = type(value)
    if value is None or value_type in (bool, int, str, bytes):
        return (value_type, value)
    if value_type is float:
        return (float, value.hex())
    if depth <= 0:
        return (value_type, id(value))
    if seen is None:
        seen = set()
    value_id = id(value)
    if value_id in seen:
        return ("cycle", value_type, value_id)
    seen.add(value_id)
    try:
        if value_type in (list, tuple):
            return (
                value_type,
                value_id,
                tuple(
                    _execution_value_stamp(
                        item,
                        depth=depth - 1,
                        seen=seen,
                    )
                    for item in value
                ),
            )
        if value_type is dict:
            return (
                dict,
                value_id,
                tuple(
                    (
                        _execution_value_stamp(
                            key,
                            depth=depth - 1,
                            seen=seen,
                        ),
                        _execution_value_stamp(
                            item,
                            depth=depth - 1,
                            seen=seen,
                        ),
                    )
                    for key, item in value.items()
                ),
            )
        if value_type in (set, frozenset):
            return (
                value_type,
                value_id,
                frozenset(
                    _execution_value_stamp(
                        item,
                        depth=depth - 1,
                        seen=seen,
                    )
                    for item in value
                ),
            )
        module = value_type.__module__
        if module.startswith(("pydantic_ai", "pydantic_graph")):
            try:
                state = vars(value)
            except TypeError:
                state = None
            if type(state) is dict:
                return (
                    value_type,
                    value_id,
                    tuple(
                        (
                            name,
                            _execution_value_stamp(
                                item,
                                depth=depth - 1,
                                seen=seen,
                            ),
                        )
                        for name, item in state.items()
                    ),
                )
        return (value_type, value_id)
    finally:
        seen.remove(value_id)


def _dynamic_state_stamp(
    state: Mapping[str, Any],
    names: tuple[str, ...],
) -> tuple[tuple[str, Any], ...]:
    return tuple(
        (name, _execution_value_stamp(state.get(name))) for name in names
    )


def _agent_run_transition_active(run: Any, seal: _AgentRunSeal) -> bool:
    active = _AGENT_RUN_TRANSITION.get()
    return (
        active is not None
        and active[0] == id(run)
        and active[1] is seal.token
    )


def _link_graph_run_owner(graph_run: Any, run: Any) -> None:
    key = id(graph_run)

    def cleanup(ref: weakref.ReferenceType[Any]) -> None:
        if _GRAPH_RUN_OWNERS.get(key) is ref:
            _GRAPH_RUN_OWNERS.pop(key, None)

    _GRAPH_RUN_OWNERS[key] = weakref.ref(run, cleanup)


def _require_pinned_graph_run_transition(graph_run: Any) -> _AgentRunSeal:
    owner_ref = _GRAPH_RUN_OWNERS.get(id(graph_run))
    run = owner_ref() if owner_ref is not None else None
    seal = _AGENT_RUN_SEALS.get(id(run)) if run is not None else None
    if (
        run is None
        or seal is None
        or seal.ref() is not run
        or seal.graph_run is not graph_run
        or type(graph_run) is not _PinnedGraphRun
    ):
        raise PydanticAuthorityConfigurationError(
            "Pydantic GraphRun is not pinned"
        )
    _verify_agent_run(run)
    if not _agent_run_transition_active(run, seal):
        raise PydanticAuthorityConfigurationError(
            "Pydantic GraphRun advanced outside the sealed AgentRun transition"
        )
    return seal


def _verify_agent_run(run: Any) -> _AgentRunSeal:
    seal = _AGENT_RUN_SEALS.get(id(run))
    if (
        seal is None
        or seal.ref() is not run
        or type(run) is not _PinnedAgentRun
    ):
        raise PydanticAuthorityConfigurationError(
            "Pydantic AgentRun is not pinned"
        )
    state = object.__getattribute__(run, "__dict__")
    allowed_run_keys = {"_graph_run", *_AGENT_RUN_MUTABLE_FIELDS}
    if (
        set(state) - allowed_run_keys
        or state.get("_graph_run") is not seal.graph_run
    ):
        raise PydanticAuthorityConfigurationError("Pydantic AgentRun changed")
    graph_run = seal.graph_run
    if type(graph_run) is not seal.graph_type:
        raise PydanticAuthorityConfigurationError(
            "Pydantic GraphRun changed type"
        )
    graph_state = vars(graph_run)
    if set(graph_state) != seal.graph_keys or any(
        graph_state[name] is not expected
        for name, expected in seal.graph_immutable
    ):
        raise PydanticAuthorityConfigurationError("Pydantic GraphRun changed")
    if graph_state["deps"] is not seal.deps:
        raise PydanticAuthorityConfigurationError(
            "Pydantic GraphRun deps changed"
        )
    iterator = graph_state["_iterator_instance"]
    if iterator is not seal.iterator or type(iterator) is not seal.iterator_type:
        raise PydanticAuthorityConfigurationError(
            "Pydantic graph iterator changed type"
        )
    iterator_state = vars(iterator)
    if set(iterator_state) != seal.iterator_keys or any(
        iterator_state[name] is not expected
        for name, expected in seal.iterator_immutable
    ):
        raise PydanticAuthorityConfigurationError(
            "Pydantic graph iterator changed"
        )
    if iterator_state["deps"] is not seal.deps:
        raise PydanticAuthorityConfigurationError(
            "Pydantic graph iterator deps changed"
        )
    deps_seal = _verify_graph_deps(seal.deps)
    if deps_seal.token is not seal.token:
        raise PydanticAuthorityConfigurationError(
            "Pydantic AgentRun identity changed"
        )
    if not _agent_run_transition_active(run, seal) and (
        _dynamic_state_stamp(state, _AGENT_RUN_DYNAMIC_NAMES)
        != seal.run_dynamic
        or _dynamic_state_stamp(graph_state, _GRAPH_RUN_DYNAMIC_NAMES)
        != seal.graph_dynamic
        or _dynamic_state_stamp(
            iterator_state,
            _GRAPH_ITERATOR_DYNAMIC_NAMES,
        )
        != seal.iterator_dynamic
    ):
        raise PydanticAuthorityConfigurationError(
            "Pydantic AgentRun execution state changed outside a guarded transition"
        )
    return seal


def _require_guarded_agent_run_transition(
    ctx: RunContext[Any],
    *,
    require_driver_task: bool = False,
) -> _PinnedAgentRun:
    """Require the exact live sealed AgentRun transition at execution sinks."""

    active = _AGENT_RUN_TRANSITION.get()
    root = ctx.root_capability
    root_seal = _verify_run_tree(root)
    if active is None or active[1] is not root_seal.token:
        raise PydanticAuthorityConfigurationError(
            "Pydantic tool execution occurred outside the sealed graph transition"
        )
    if require_driver_task and active[2] is not asyncio.current_task():
        raise PydanticAuthorityConfigurationError(
            "Pydantic graph node lifecycle left its exact driver task"
        )
    run_seal = _AGENT_RUN_SEALS.get(active[0])
    run = run_seal.ref() if run_seal is not None else None
    if (
        run_seal is None
        or run is None
        or run_seal.token is not root_seal.token
        or _verify_agent_run(run).deps.root_capability is not root
    ):
        raise PydanticAuthorityConfigurationError(
            "Pydantic tool execution lost its sealed AgentRun identity"
        )
    return run


def _refresh_agent_run_seal(run: Any) -> _AgentRunSeal:
    seal = _verify_agent_run(run)
    if not _agent_run_transition_active(run, seal):
        raise PydanticAuthorityConfigurationError(
            "Pydantic AgentRun transition was not authorized"
        )
    state = object.__getattribute__(run, "__dict__")
    graph_state = vars(seal.graph_run)
    iterator_state = vars(seal.iterator)
    refreshed = replace(
        seal,
        run_dynamic=_dynamic_state_stamp(state, _AGENT_RUN_DYNAMIC_NAMES),
        graph_dynamic=_dynamic_state_stamp(
            graph_state,
            _GRAPH_RUN_DYNAMIC_NAMES,
        ),
        iterator_dynamic=_dynamic_state_stamp(
            iterator_state,
            _GRAPH_ITERATOR_DYNAMIC_NAMES,
        ),
    )
    _AGENT_RUN_SEALS[id(run)] = refreshed
    return refreshed


async def _guarded_agent_run_transition(run: Any, operation: Any) -> Any:
    seal = _verify_agent_run(run)
    current_task = asyncio.current_task()
    if current_task is None:  # pragma: no cover - guarded entry is async
        raise PydanticAuthorityConfigurationError(
            "Pydantic AgentRun requires an active asyncio task"
        )
    active = _AGENT_RUN_TRANSITION.get()
    if (
        active is not None
        and active[0] == id(run)
        and active[1] is seal.token
    ):
        return await operation()
    key = (id(run), seal.token, current_task)
    context_token = _AGENT_RUN_TRANSITION.set(key)
    try:
        return await operation()
    finally:
        try:
            _refresh_agent_run_seal(run)
        finally:
            _AGENT_RUN_TRANSITION.reset(context_token)
        _verify_agent_run(run)


def _require_current_agent_node(run: Any, node: Any) -> None:
    _verify_agent_run(run)
    current = AgentRun.next_node.fget(run)
    if node is not current:
        raise PydanticAuthorityConfigurationError(
            "Pydantic AgentRun rejects skipped or injected graph nodes"
        )


def _require_first_party_agent_step(run: Any, step_fn: Any) -> None:
    expected = globals().get("_PINNED_AGENT_FIRST_PARTY_STEP")
    if (
        type(step_fn) is not MethodType
        or step_fn.__self__ is not run
        or step_fn.__func__ is not expected
    ):
        raise PydanticAuthorityConfigurationError(
            "Pydantic event-stream or replaced node drivers are outside this "
            "beta boundary"
        )


class _PinnedGraphRun(GraphRun[Any, Any, Any]):
    __slots__ = ()

    def __setattr__(self, name: str, value: Any) -> None:
        if id(self) in _GRAPH_RUN_OWNERS:
            if name not in _GRAPH_RUN_DYNAMIC_NAMES:
                raise PydanticAuthorityConfigurationError(
                    "Pydantic GraphRun execution aliases are immutable"
                )
            _require_pinned_graph_run_transition(self)
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        if id(self) in _GRAPH_RUN_OWNERS:
            raise PydanticAuthorityConfigurationError(
                "Pydantic GraphRun execution aliases are immutable"
            )
        object.__delattr__(self, name)

    def __getattribute__(self, name: str) -> Any:
        if id(self) in _GRAPH_RUN_OWNERS and name in {
            "_async_exit_stack",
            "_iterator",
            "_iterator_instance",
        }:
            _require_pinned_graph_run_transition(self)
        return object.__getattribute__(self, name)

    async def __aenter__(self) -> Any:
        _require_pinned_graph_run_transition(self)
        return await GraphRun.__aenter__(self)

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> Any:
        _require_pinned_graph_run_transition(self)
        return await GraphRun.__aexit__(self, exc_type, exc_val, exc_tb)

    def __aiter__(self) -> Any:
        _require_pinned_graph_run_transition(self)
        return self

    async def __anext__(self) -> Any:
        _require_pinned_graph_run_transition(self)
        return await GraphRun.__anext__(self)

    async def next(self, value: Any = None) -> Any:
        _require_pinned_graph_run_transition(self)
        return await GraphRun.next(self, value)

    def override_next(self, value: Any) -> None:
        _require_pinned_graph_run_transition(self)
        GraphRun.override_next(self, value)

    def _set_next(self, value: Any) -> None:
        _require_pinned_graph_run_transition(self)
        GraphRun._set_next(self, value)


class _PinnedAgentRun(AgentRun[Any, Any]):
    __slots__ = ()

    def __setattr__(self, name: str, value: Any) -> None:
        seal = _AGENT_RUN_SEALS.get(id(self))
        if seal is not None and seal.ref() is self:
            if (
                name not in _AGENT_RUN_MUTABLE_FIELDS
                or not _agent_run_transition_active(self, seal)
            ):
                raise PydanticAuthorityConfigurationError(
                    "Pydantic AgentRun execution aliases are immutable"
                )
            _verify_agent_run(self)
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        if id(self) in _AGENT_RUN_SEALS:
            raise PydanticAuthorityConfigurationError(
                "Pydantic AgentRun execution aliases are immutable"
            )
        object.__delattr__(self, name)

    def __getattribute__(self, name: str) -> Any:
        if id(self) in _AGENT_RUN_SEALS and name in _AGENT_RUN_GUARDED_NAMES:
            _verify_agent_run(self)
            wrapper_name = _AGENT_RUN_WRAPPED_DISPATCH.get(name)
            if wrapper_name is not None:
                return _exact_descriptor(_PinnedAgentRun, wrapper_name, self)
            if name in _AGENT_RUN_EXACT_DISPATCH:
                return _exact_descriptor(AgentRun, name, self)
        return object.__getattribute__(self, name)

    def __aiter__(self) -> Any:
        _verify_agent_run(self)
        return self

    async def __anext__(self) -> Any:
        return await _guarded_agent_run_transition(
            self,
            lambda: AgentRun.__anext__(self),
        )

    async def _va_next(self, node: Any) -> Any:
        _require_current_agent_node(self, node)
        return await _guarded_agent_run_transition(
            self,
            lambda: AgentRun.next(self, node),
        )

    async def _va_run_node_with_hooks(
        self,
        node: Any,
        step_fn: Any,
    ) -> Any:
        _require_current_agent_node(self, node)
        _require_first_party_agent_step(self, step_fn)
        return await _guarded_agent_run_transition(
            self,
            lambda: AgentRun._run_node_with_hooks(self, node, step_fn),
        )

    async def _va_wrap_and_advance(
        self,
        run_context: Any,
        node: Any,
        step_fn: Any,
    ) -> Any:
        _require_current_agent_node(self, node)
        _require_first_party_agent_step(self, step_fn)
        return await _guarded_agent_run_transition(
            self,
            lambda: AgentRun._wrap_and_advance(
                self,
                run_context,
                node,
                step_fn,
            ),
        )

    async def _va_advance_graph(self, node: Any) -> Any:
        _require_current_agent_node(self, node)
        return await _guarded_agent_run_transition(
            self,
            lambda: AgentRun._advance_graph(self, node),
        )

    async def _va_stream_and_advance(self, node: Any) -> Any:
        _require_current_agent_node(self, node)
        return await _guarded_agent_run_transition(
            self,
            lambda: AgentRun._stream_and_advance(self, node),
        )


_PINNED_AGENT_FIRST_PARTY_STEP = _PinnedAgentRun._va_stream_and_advance


def _pin_agent_run(run: Any, *, deps: Any) -> _PinnedAgentRun:
    if type(run) is not AgentRun:
        raise PydanticAuthorityConfigurationError(
            "unexpected Pydantic AgentRun"
        )
    run_state = vars(run)
    if set(run_state) - {"_graph_run", *_AGENT_RUN_MUTABLE_FIELDS}:
        raise PydanticAuthorityConfigurationError(
            "Pydantic AgentRun changed before pin"
        )
    graph_run = run_state.get("_graph_run")
    graph_state = vars(graph_run)
    required_graph_keys = {
        "graph",
        "state",
        "deps",
        "inputs",
        "_active_reducers",
        "_next",
        "_next_task_id",
        "_next_node_run_id",
        "_first_task",
        "_iterator_task_group",
        "_iterator_instance",
        "_iterator",
        "_GraphRun__traceparent",
        "_async_exit_stack",
        "__orig_class__",
    }
    if set(graph_state) != required_graph_keys or graph_state["deps"] is not deps:
        raise PydanticAuthorityConfigurationError(
            "Pydantic GraphRun changed before pin"
        )
    iterator = graph_state["_iterator_instance"]
    iterator_state = vars(iterator)
    required_iterator_keys = {
        "graph",
        "state",
        "deps",
        "task_group",
        "get_next_node_run_id",
        "get_next_task_id",
        "cancel_scopes",
        "active_tasks",
        "active_reducers",
        "iter_stream_sender",
        "iter_stream_receiver",
        "_next_node_run_id",
        "__orig_class__",
    }
    if (
        set(iterator_state) != required_iterator_keys
        or iterator_state["deps"] is not deps
        or iterator_state["graph"] is not graph_state["graph"]
        or iterator_state["state"] is not graph_state["state"]
        or iterator_state["task_group"] is not graph_state["_iterator_task_group"]
    ):
        raise PydanticAuthorityConfigurationError(
            "Pydantic graph iterator changed before pin"
        )
    graph_dynamic = {"_next", "_next_task_id", "_next_node_run_id"}
    iterator_dynamic = {"_next_node_run_id"}
    deps_seal = _verify_graph_deps(deps)
    object.__setattr__(graph_run, "__class__", _PinnedGraphRun)
    object.__setattr__(run, "__class__", _PinnedAgentRun)
    _weak_store(
        _AGENT_RUN_SEALS,
        run,
        lambda ref: _AgentRunSeal(
            ref=ref,
            token=deps_seal.token,
            graph_run=graph_run,
            graph_type=type(graph_run),
            deps=deps,
            graph_keys=frozenset(graph_state),
            graph_immutable=tuple(
                (name, value)
                for name, value in graph_state.items()
                if name not in graph_dynamic
            ),
            iterator=iterator,
            iterator_type=type(iterator),
            iterator_keys=frozenset(iterator_state),
            iterator_immutable=tuple(
                (name, value)
                for name, value in iterator_state.items()
                if name not in iterator_dynamic
            ),
            run_dynamic=_dynamic_state_stamp(
                run_state,
                _AGENT_RUN_DYNAMIC_NAMES,
            ),
            graph_dynamic=_dynamic_state_stamp(
                graph_state,
                _GRAPH_RUN_DYNAMIC_NAMES,
            ),
            iterator_dynamic=_dynamic_state_stamp(
                iterator_state,
                _GRAPH_ITERATOR_DYNAMIC_NAMES,
            ),
        ),
    )
    _link_graph_run_owner(graph_run, run)
    _verify_agent_run(run)
    return run


_AGENT_EXECUTION_ENTRY_NAMES = frozenset(
    {
        "iter",
        "run",
        "run_sync",
        "run_stream",
        "run_stream_sync",
        "run_stream_events",
        "realtime",
        "_open_realtime_session",
        "to_cli",
        "to_cli_sync",
        "to_web",
        "override",
        "_infer_name",
        "_base_run_capability",
        "_resolve_run_capabilities",
        "_effective_root_capability",
        "_get_toolset",
        "_bind_run_capabilities",
        "_verify_tool_boundary",
    }
)
_AGENT_EXPECTED_FIELD_NAMES = (
    "_event_stream_handler",
    "_verb_authority_expected_root",
    "_verb_authority_expected_root_seal",
    "_verb_authority_expected_leaves",
    "_verb_authority_expected_session_getter",
    "_verb_authority_expected_function_toolset",
    "_verb_authority_expected_function_toolset_seal",
    "_verb_authority_expected_tool_mapping",
    "_verb_authority_expected_tools",
    "_verb_authority_expected_user_toolsets",
    "_verb_authority_expected_dynamic_toolsets",
    "_verb_authority_expected_cap_toolsets",
    "_verb_authority_expected_override_vars",
)
_AGENT_SEALED_ATTRIBUTE_NAMES = (
    _AGENT_EXECUTION_ENTRY_NAMES
    | frozenset(_AGENT_EXPECTED_FIELD_NAMES)
    | frozenset(
        {
            "__class__",
            "__dict__",
            "event_stream_handler",
            "_verb_authority_initializing",
            "_verb_authority_managed_capability",
            "_root_capability",
            "_function_toolset",
            "_user_toolsets",
            "_dynamic_toolsets",
            "_cap_toolsets",
            "_override_tools",
            "_override_toolsets",
            "_override_native_tools",
            "_override_root_capability",
        }
    )
)


def _agent_external_seal(agent: Any) -> _AgentSeal:
    seal = _AGENT_SEALS.get(id(agent))
    if (
        seal is None
        or seal.ref() is not agent
        or type(agent) is not PydanticAuthorityAgent
    ):
        raise PydanticAuthorityConfigurationError(
            "PydanticAuthorityAgent's external tool-boundary seal is missing"
        )
    return seal


def _snapshot_run_retries(value: Any) -> int | dict[str, int] | None:
    """Copy the only supported retry shapes before an iter grant exists."""

    if value is None:
        return None
    if type(value) is int:
        if 0 <= value <= _MAX_RUN_RETRIES:
            return value
        raise PydanticAuthorityConfigurationError(
            f"Pydantic run retries must be between 0 and {_MAX_RUN_RETRIES}"
        )
    if type(value) is not dict or set(value) - {"tools", "output"}:
        raise PydanticAuthorityConfigurationError(
            "Pydantic run retries must be a plain int or a plain tools/output dict"
        )
    snapshot: dict[str, int] = {}
    for name in ("tools", "output"):
        if name not in value:
            continue
        item = value[name]
        if type(item) is not int or not 0 <= item <= _MAX_RUN_RETRIES:
            raise PydanticAuthorityConfigurationError(
                f"Pydantic run retry {name!r} must be a plain integer between "
                f"0 and {_MAX_RUN_RETRIES}"
            )
        snapshot[name] = item
    return snapshot


def _reject_ambient_run_binding() -> None:
    """Consume and reject Pydantic's unaudited event-stream binding path."""

    binding = take_run_binding()
    if binding is not None:
        raise PydanticAuthorityConfigurationError(
            "Pydantic run-stream bindings are outside this beta boundary"
        )


class PydanticAuthorityAgent(Agent[Any, Any]):
    """Sealed Pydantic Agent whose tool boundary cannot be replaced publicly."""

    def __init_subclass__(cls, **kwargs: Any) -> None:
        del cls, kwargs
        raise TypeError("PydanticAuthorityAgent cannot be subclassed")

    def __setattr__(self, name: str, value: Any) -> None:
        seal = _AGENT_SEALS.get(id(self))
        if (
            seal is not None
            and seal.ref() is self
            and name in _AGENT_SEALED_ATTRIBUTE_NAMES
        ):
            raise PydanticAuthorityConfigurationError(
                "PydanticAuthorityAgent's sealed boundary is immutable"
            )
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        seal = _AGENT_SEALS.get(id(self))
        if (
            seal is not None
            and seal.ref() is self
            and name in _AGENT_SEALED_ATTRIBUTE_NAMES
        ):
            raise PydanticAuthorityConfigurationError(
                "PydanticAuthorityAgent's sealed boundary is immutable"
            )
        object.__delattr__(self, name)

    def __getattribute__(self, name: str) -> Any:
        if name in _AGENT_EXECUTION_ENTRY_NAMES:
            seal = _AGENT_SEALS.get(id(self))
            if seal is not None and seal.ref() is self:
                state = object.__getattribute__(self, "__dict__")
                if name in state:
                    raise PydanticAuthorityConfigurationError(
                        "PydanticAuthorityAgent execution entry point was shadowed"
                    )
                return _exact_descriptor(PydanticAuthorityAgent, name, self)
        return object.__getattribute__(self, name)

    def __init__(
        self,
        model: Any = None,
        *,
        tools: Any = (),
        toolsets: Any = None,
        capabilities: Any = None,
        session_getter: Callable[
            [RunContext[Any]], PydanticAuthoritySession
        ] = _default_session_getter,
        **kwargs: Any,
    ) -> None:
        if type(self) is not PydanticAuthorityAgent:
            raise TypeError("PydanticAuthorityAgent cannot be subclassed")
        self._verb_authority_initializing = True
        if toolsets is not None:
            raise PydanticAuthorityConfigurationError(
                "PydanticAuthorityAgent supports direct local tools only; "
                "constructor toolsets are unsupported"
            )
        if kwargs.get("tool_timeout") is not None:
            raise PydanticAuthorityConfigurationError(
                "PydanticAuthorityAgent does not support a Pydantic tool timeout; "
                "enforce resource bounds inside the Registry implementation"
            )
        if kwargs.get("event_stream_handler") is not None:
            raise PydanticAuthorityConfigurationError(
                "Pydantic event_stream_handler is outside this beta boundary"
            )
        if type(tools) not in (list, tuple):
            raise PydanticAuthorityConfigurationError(
                "PydanticAuthorityAgent tools must be a plain list or tuple"
            )
        supplied_tools = tuple(tools)
        for tool in supplied_tools:
            _pydantic_tool_seal(tool)
        # Never retain a caller-owned Tool or validator graph.  Rebuild a fresh
        # inert Tool from the already validated plain signature and fields.
        safe_tools = tuple(
            pydantic_schema_tool(
                tool.function,
                name=tool.name,
                description=tool.description,
                strict=tool.strict,
                sequential=tool.sequential,
            )
            for tool in supplied_tools
        )
        if capabilities is None:
            extra_capabilities: list[AbstractCapability[Any]] = []
        elif type(capabilities) in (list, tuple):
            extra_capabilities = list(capabilities)
        else:
            raise PydanticAuthorityConfigurationError(
                "PydanticAuthorityAgent capabilities must be a plain list or tuple"
            )
        if extra_capabilities:
            raise PydanticAuthorityConfigurationError(
                "PydanticAuthorityAgent does not compose with application-supplied "
                "static capabilities in this beta"
            )

        managed = VerbAuthorityCapability(session_getter=session_getter)
        self._verb_authority_managed_capability = managed
        kwargs.setdefault("deps_type", PydanticAuthoritySession)
        super().__init__(
            model,
            tools=safe_tools,
            toolsets=None,
            capabilities=[*extra_capabilities, managed],
            **kwargs,
        )

        root = self.root_capability
        _static_capability_tree_seal(
            root,
            managed=managed,
            session_getter=session_getter,
        )
        leaves = tuple(vars(root)["capabilities"])
        root_seal = _static_capability_tree_seal(
            root,
            managed=managed,
            session_getter=session_getter,
            expected_children=leaves,
        )
        function_toolset = self._function_toolset
        function_toolset_seal = _function_toolset_seal(function_toolset)
        mapping = function_toolset.tools
        if type(mapping) is not dict or len(mapping) != len(safe_tools):
            raise PydanticAuthorityConfigurationError(
                "Pydantic did not preserve the sealed direct-tool mapping"
            )
        expected_tools: list[tuple[str, PydanticTool[Any], tuple[Any, ...]]] = []
        for (actual_name, actual_tool), expected_tool in zip(
            mapping.items(), safe_tools
        ):
            if (
                type(actual_name) is not str
                or actual_name != expected_tool.name
                or actual_tool is not expected_tool
            ):
                raise PydanticAuthorityConfigurationError(
                    "Pydantic changed the sealed direct-tool mapping"
                )
            expected_tools.append(
                (actual_name, actual_tool, _pydantic_tool_seal(actual_tool))
            )
        for field_name in (
            "_user_toolsets",
            "_dynamic_toolsets",
            "_cap_toolsets",
        ):
            value = getattr(self, field_name)
            if type(value) is not list or value:
                raise PydanticAuthorityConfigurationError(
                    "PydanticAuthorityAgent supports no external toolsets"
                )
        self._verb_authority_expected_root = root
        self._verb_authority_expected_root_seal = root_seal
        self._verb_authority_expected_leaves = leaves
        self._verb_authority_expected_session_getter = session_getter
        self._verb_authority_expected_function_toolset = function_toolset
        self._verb_authority_expected_function_toolset_seal = (
            function_toolset_seal
        )
        self._verb_authority_expected_tool_mapping = mapping
        self._verb_authority_expected_tools = tuple(expected_tools)
        self._verb_authority_expected_user_toolsets = self._user_toolsets
        self._verb_authority_expected_dynamic_toolsets = self._dynamic_toolsets
        self._verb_authority_expected_cap_toolsets = self._cap_toolsets
        self._verb_authority_expected_override_vars = tuple(
            (name, getattr(self, name))
            for name in (
                "_override_tools",
                "_override_toolsets",
                "_override_native_tools",
                "_override_root_capability",
            )
        )
        object.__setattr__(self, "_verb_authority_initializing", False)
        state = object.__getattribute__(self, "__dict__")
        expected_fields = tuple(
            (name, state[name]) for name in _AGENT_EXPECTED_FIELD_NAMES
        )
        _weak_store(
            _AGENT_SEALS,
            self,
            lambda ref: _AgentSeal(
                ref=ref,
                root=root,
                root_seal=root_seal,
                leaves=leaves,
                managed=managed,
                session_getter=session_getter,
                function_toolset=function_toolset,
                function_toolset_seal=function_toolset_seal,
                mapping=mapping,
                tools=tuple(expected_tools),
                user_toolsets=self._user_toolsets,
                dynamic_toolsets=self._dynamic_toolsets,
                cap_toolsets=self._cap_toolsets,
                override_vars=state["_verb_authority_expected_override_vars"],
                expected_fields=expected_fields,
            ),
        )
        PydanticAuthorityAgent._verify_tool_boundary(self)

    def _verify_tool_boundary(self) -> None:
        state = object.__getattribute__(self, "__dict__")
        stored = _AGENT_SEALS.get(id(self))
        if (
            (stored is None or stored.ref() is not self)
            and state.get("_verb_authority_initializing") is True
        ):
            return
        seal = _agent_external_seal(self)
        if (
            state.get("_verb_authority_initializing") is not False
            or any(state.get(name) is not value for name, value in seal.expected_fields)
            or state.get("_verb_authority_managed_capability") is not seal.managed
        ):
            raise PydanticAuthorityConfigurationError(
                "PydanticAuthorityAgent's tool-boundary baseline changed"
            )

        expected_root = seal.root
        expected_leaves = seal.leaves
        managed = seal.managed
        session_getter = seal.session_getter
        if (
            state.get("_root_capability") is not expected_root
            or type(expected_leaves) is not tuple
            or type(managed) is not VerbAuthorityCapability
            or _static_capability_tree_seal(
                expected_root,
                managed=managed,
                session_getter=session_getter,
                expected_children=expected_leaves,
            )
            != seal.root_seal
        ):
            raise PydanticAuthorityConfigurationError(
                "PydanticAuthorityAgent rejects mutation of its capability root"
            )

        expected_function_toolset = seal.function_toolset
        if state.get("_function_toolset") is not expected_function_toolset:
            raise PydanticAuthorityConfigurationError(
                "PydanticAuthorityAgent rejects replacement of its function toolset"
            )
        if (
            _function_toolset_seal(expected_function_toolset)
            != seal.function_toolset_seal
        ):
            raise PydanticAuthorityConfigurationError(
                "PydanticAuthorityAgent rejects mutation of its function toolset"
            )

        expected_lists = (
            ("_user_toolsets", seal.user_toolsets),
            ("_dynamic_toolsets", seal.dynamic_toolsets),
            ("_cap_toolsets", seal.cap_toolsets),
        )
        for actual_name, expected in expected_lists:
            actual = state.get(actual_name)
            if actual is not expected or type(actual) is not list or actual:
                raise PydanticAuthorityConfigurationError(
                    "PydanticAuthorityAgent rejects added or replaced toolsets"
                )

        mapping = expected_function_toolset.tools
        expected_mapping = seal.mapping
        expected_tools = seal.tools
        if (
            mapping is not expected_mapping
            or type(mapping) is not dict
            or len(mapping) != len(expected_tools)
        ):
            raise PydanticAuthorityConfigurationError(
                "PydanticAuthorityAgent rejects mutation of its direct-tool mapping"
            )
        for (actual_name, actual_tool), (name, tool, tool_seal) in zip(
            mapping.items(), expected_tools
        ):
            if (
                type(actual_name) is not str
                or actual_name != name
                or actual_tool is not tool
                or _pydantic_tool_seal(tool) != tool_seal
            ):
                raise PydanticAuthorityConfigurationError(
                    "PydanticAuthorityAgent rejects mutation of a schema-only tool"
                )

        for field_name, expected_var in seal.override_vars:
            actual_var = state.get(field_name)
            if actual_var is not expected_var:
                raise PydanticAuthorityConfigurationError(
                    "PydanticAuthorityAgent rejects replacement of override state"
                )
            if (
                field_name
                in ("_override_tools", "_override_toolsets", "_override_native_tools")
                and expected_var.get() is not None
            ):
                raise PydanticAuthorityConfigurationError(
                    "PydanticAuthorityAgent rejects active tool-boundary overrides"
                )

    async def _resolve_run_capabilities(
        self,
        ctx: RunContext[Any],
        *,
        base_capability: Any,
        extra_capabilities: list[Any],
        instrumentation_cap: Any,
        inject_deferred_loader: bool,
        base_is_override: bool,
    ) -> Any:
        PydanticAuthorityAgent._verify_tool_boundary(self)
        agent_seal = _agent_external_seal(self)
        expected_static = agent_seal.root
        if (
            base_capability is not expected_static
            or extra_capabilities
            or base_is_override
        ):
            raise PydanticAuthorityConfigurationError(
                "Pydantic run capability inputs changed"
            )
        resolved = await Agent._resolve_run_capabilities(
            self,
            ctx,
            base_capability=base_capability,
            extra_capabilities=extra_capabilities,
            instrumentation_cap=instrumentation_cap,
            inject_deferred_loader=inject_deferred_loader,
            base_is_override=base_is_override,
        )
        PydanticAuthorityAgent._verify_tool_boundary(self)
        if instrumentation_cap is not None:
            raise PydanticAuthorityConfigurationError(
                "instrumentation capabilities are outside this beta boundary"
            )
        old_root = resolved.run_capability
        pinned = _pin_run_root(
            old_root,
            agent_seal.session_getter,
            resolved.capabilities,
            ctx.deps,
        )
        resolved_layers = [
            pinned if layer is old_root else layer
            for layer in resolved.resolved_layers
        ]
        return replace(
            resolved,
            run_capability=pinned,
            resolved_layers=resolved_layers,
        )

    def _effective_root_capability(self) -> Any:
        self._verify_tool_boundary()
        root = super()._effective_root_capability()
        stored = _AGENT_SEALS.get(id(self))
        if stored is None or stored.ref() is not self:
            return root
        expected_root = stored.root
        if root is not expected_root or root.defer_loading is not False:
            raise PydanticAuthorityConfigurationError(
                "PydanticAuthorityAgent rejects replacement of its capability root"
            )
        return root

    def _base_run_capability(self) -> tuple[Any, bool]:
        self._verify_tool_boundary()
        entry = _AGENT_ITER_ENTRY.get()
        if (
            entry is None
            or entry[0] != id(self)
            or entry[2] is not asyncio.current_task()
        ):
            raise PydanticAuthorityConfigurationError(
                "PydanticAuthorityAgent runs must enter through its sealed iter wrapper"
            )
        # Consume the entry grant before base Agent.iter continues. A nested or
        # explicitly unbound Agent.iter call cannot inherit and reuse it.
        _AGENT_ITER_ENTRY.set(None)
        return Agent._base_run_capability(self)

    def _get_toolset(self, *args: Any, **kwargs: Any) -> Any:
        self._verify_tool_boundary()
        output_toolset = (
            args[0]
            if args
            else kwargs.get("output_toolset")
        )
        if output_toolset is not None:
            raise UserError(
                "Pydantic output tools execute outside the local Verb Authority "
                "runner and are unsupported"
            )
        additional_toolsets = (
            args[1]
            if len(args) > 1
            else kwargs.get("additional_toolsets")
        )
        if additional_toolsets is not None:
            raise PydanticAuthorityConfigurationError(
                "PydanticAuthorityAgent rejects per-run toolsets before setup"
            )
        return super()._get_toolset(*args, **kwargs)

    def _bind_run_capabilities(self, extra_capabilities: Any) -> Any:
        if extra_capabilities:
            raise PydanticAuthorityConfigurationError(
                "PydanticAuthorityAgent rejects per-run capabilities before setup"
            )
        return []

    @asynccontextmanager
    async def iter(self, *args: Any, **kwargs: Any) -> Any:
        if kwargs.get("toolsets") is not None:
            raise PydanticAuthorityConfigurationError(
                "PydanticAuthorityAgent rejects per-run toolsets before setup"
            )
        PydanticAuthorityAgent._verify_tool_boundary(self)
        kwargs["retries"] = _snapshot_run_retries(kwargs.get("retries"))
        infer_name = kwargs.get("infer_name", True)
        if type(infer_name) is not bool:
            raise PydanticAuthorityConfigurationError(
                "PydanticAuthorityAgent infer_name must be a plain boolean"
            )
        if infer_name and self.name is None:
            # Name inference runs before the entry grant exists and dispatches
            # to the exact pinned Pydantic implementation. No caller callback
            # can copy a live grant into a child task.
            Agent._infer_name(self, inspect.currentframe())
        kwargs["infer_name"] = False
        PydanticAuthorityAgent._verify_tool_boundary(self)
        # Must happen before the one-use iter entry grant. Event-stream bindings
        # are mutable external state and are intentionally outside this beta.
        _reject_ambient_run_binding()
        internal_cancellation = RunCancellation()
        if type(internal_cancellation) is not RunCancellation:
            raise PydanticAuthorityConfigurationError(
                "Pydantic run cancellation changed type"
            )
        # Supplying our own C-implemented SimpleNamespace keeps Pydantic from
        # constructing or descriptor-dispatching through mutable RunBinding
        # state after the entry grant is minted.
        internal_binding = SimpleNamespace(
            cancellation=internal_cancellation,
            agent_run=None,
        )
        current_task = asyncio.current_task()
        if current_task is None:  # pragma: no cover - async entry has a task
            raise PydanticAuthorityConfigurationError(
                "PydanticAuthorityAgent requires an active asyncio task"
            )
        pinned_run: _PinnedAgentRun | None = None
        deps: Any = None
        teardown_token: Any = None
        with provide_run_binding(internal_binding):
            # No caller-dispatched operation remains between minting this grant
            # and Agent._base_run_capability consuming it.
            entry_token = _AGENT_ITER_ENTRY.set(
                (id(self), object(), current_task)
            )
            try:
                async with Agent.iter(self, *args, **kwargs) as run:
                    binding_state = vars(internal_binding)
                    if (
                        set(binding_state) != {"cancellation", "agent_run"}
                        or binding_state["cancellation"] is not internal_cancellation
                        or binding_state["agent_run"] is not run
                    ):
                        raise PydanticAuthorityConfigurationError(
                            "Pydantic internal run binding changed"
                        )
                    graph_run = vars(run).get("_graph_run")
                    if graph_run is None:
                        raise PydanticAuthorityConfigurationError(
                            "Pydantic AgentRun changed"
                        )
                    deps = graph_run.deps
                    state = vars(deps)
                    root = state.get("root_capability")
                    if type(root) is not _PinnedRunRoot:
                        raise PydanticAuthorityConfigurationError(
                            "Pydantic run root was not pinned"
                        )
                    _pin_graph_deps(deps, root=root, agent=self)
                    pinned_run = _pin_agent_run(run, deps=deps)
                    if AgentRun.ctx.fget(pinned_run).deps is not deps:
                        raise PydanticAuthorityConfigurationError(
                            "Pydantic AgentRun context changed"
                        )
                    try:
                        yield pinned_run
                    finally:
                        run_seal = _AGENT_RUN_SEALS.get(id(pinned_run))
                        if run_seal is None or run_seal.ref() is not pinned_run:
                            raise PydanticAuthorityConfigurationError(
                                "Pydantic AgentRun seal disappeared"
                            )
                        try:
                            _verify_agent_run(pinned_run)
                            _verify_graph_deps(deps)
                        finally:
                            # Agent.iter finalizes the result after the caller's
                            # block returns. Guard that exact first-party write as
                            # part of the same sealed state machine.
                            teardown_token = _AGENT_RUN_TRANSITION.set(
                                (id(pinned_run), run_seal.token, current_task)
                            )
            finally:
                try:
                    if teardown_token is not None and pinned_run is not None:
                        try:
                            _refresh_agent_run_seal(pinned_run)
                        finally:
                            _AGENT_RUN_TRANSITION.reset(teardown_token)
                        _verify_agent_run(pinned_run)
                        _verify_graph_deps(deps)
                finally:
                    _AGENT_ITER_ENTRY.reset(entry_token)

    @contextmanager
    def override(self, **kwargs: Any) -> Any:
        if kwargs.get("spec") is not None:
            raise PydanticAuthorityConfigurationError(
                "PydanticAuthorityAgent rejects override(spec=...); it can "
                "replace the capability root"
            )
        replaced = [
            name
            for name in ("tools", "toolsets", "native_tools")
            if name in kwargs
        ]
        if replaced:
            raise PydanticAuthorityConfigurationError(
                "PydanticAuthorityAgent rejects tool-boundary overrides: "
                + ", ".join(replaced)
            )
        with super().override(**kwargs):
            yield

    async def run(self, *args: Any, **kwargs: Any) -> Any:
        self._verify_tool_boundary()
        if kwargs.get("event_stream_handler") is not None:
            raise PydanticAuthorityConfigurationError(
                "Pydantic event_stream_handler is outside this beta boundary"
            )
        return await Agent.run(self, *args, **kwargs)

    def run_sync(self, *args: Any, **kwargs: Any) -> Any:
        self._verify_tool_boundary()
        if kwargs.get("event_stream_handler") is not None:
            raise PydanticAuthorityConfigurationError(
                "Pydantic event_stream_handler is outside this beta boundary"
            )
        return Agent.run_sync(self, *args, **kwargs)

    def run_stream(self, *args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        self._verify_tool_boundary()
        raise PydanticAuthorityConfigurationError(
            "Pydantic run_stream is outside this beta boundary; use run, "
            "run_sync, or iter"
        )

    def run_stream_sync(self, *args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        self._verify_tool_boundary()
        raise PydanticAuthorityConfigurationError(
            "Pydantic run_stream_sync is outside this beta boundary; use run, "
            "run_sync, or iter"
        )

    def run_stream_events(self, *args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        self._verify_tool_boundary()
        raise PydanticAuthorityConfigurationError(
            "Pydantic run_stream_events is outside this beta boundary; use "
            "run, run_sync, or iter"
        )

    def realtime(self, *args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        self._verify_tool_boundary()
        raise PydanticAuthorityConfigurationError(
            "Pydantic realtime execution is outside this beta boundary"
        )

    def _open_realtime_session(self, *args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        self._verify_tool_boundary()
        raise PydanticAuthorityConfigurationError(
            "Pydantic realtime execution is outside this beta boundary"
        )

    @classmethod
    def from_spec(cls, *args: Any, **kwargs: Any) -> Any:
        del cls, args, kwargs
        raise PydanticAuthorityConfigurationError(
            "PydanticAuthorityAgent.from_spec is unsupported because Pydantic "
            "2.35 constructs an unsealed base Agent"
        )

    @classmethod
    def from_file(cls, *args: Any, **kwargs: Any) -> Any:
        del cls, args, kwargs
        raise PydanticAuthorityConfigurationError(
            "PydanticAuthorityAgent.from_file is unsupported because Pydantic "
            "2.35 constructs an unsealed base Agent"
        )

    def tool(self, *args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        raise PydanticAuthorityConfigurationError(
            "post-construction tool registration is unsupported; pass an exact "
            "pydantic_schema_tool to the constructor"
        )

    def tool_plain(self, *args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        raise PydanticAuthorityConfigurationError(
            "post-construction tool registration is unsupported; pass an exact "
            "pydantic_schema_tool to the constructor"
        )

    def toolset(self, *args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        raise PydanticAuthorityConfigurationError(
            "post-construction toolset registration is unsupported"
        )


__all__ = [
    "PydanticAuthorityAgent",
    "PydanticAuthorityConfigurationError",
    "PydanticAuthorityResolutionError",
    "PydanticAuthoritySession",
    "VerbAuthorityCapability",
    "pydantic_schema_tool",
]
