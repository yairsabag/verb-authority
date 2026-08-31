# Runtime gate

Use this reference when integrating Verb Authority immediately before tool
execution. The short path is in the [project README](../README.md); this page
keeps the complete runtime contract, resource limits, direct-dispatch caveats,
trusted-choice behavior, and the pinned Pydantic AI adapter boundary.

## Install

Install the latest published prerelease from PyPI:

```bash
python -m pip install "verb-authority==0.10.0b14"
env -u PYTHONPATH -u PYTHONHOME python -I -m verb_authority quickstart
```

Or install the same release tag directly from GitHub:

```bash
python -I -m pip install "verb-authority @ git+https://github.com/yairsabag/verb-authority.git@v0.10.0-beta.14"
```

The second command runs the offline schema-to-gate quickstart. The package has
no runtime dependencies and keeps the existing `verb_authority.py` module and
import API.

The [beta.14 release](https://github.com/yairsabag/verb-authority/releases/tag/v0.10.0-beta.14)
also includes a wheel, source archive, and `SHA256SUMS`. After downloading all
three files, use `sha256sum --check SHA256SUMS` on Linux or
`shasum -a 256 -c SHA256SUMS` on macOS to verify the wheel and source archive
against the manifest before installing. The manifest cannot authenticate
itself; for an adversarial distribution path, compare it or the two payload
hashes through an independent trusted channel.

The `verb-authority`, `verb-authority-scan`, and `verb-authority-diff` console
shortcuts are convenient in a trusted interpreter environment, but a console
script cannot enable Python isolation for itself and can honor a hostile
`PYTHONPATH`. When the current directory or environment is not fully trusted,
use the isolated `env -u ... python -I -m verb_authority` form shown above.

For a local checkout instead:

```bash
git clone https://github.com/yairsabag/verb-authority.git
cd verb-authority
python -I -m pip install .
```

## 60-second quickstart

After installing beta.14 or the current checkout, run the complete
schema-to-gate path with one command:

```bash
env -u PYTHONPATH -u PYTHONHOME python -I -m verb_authority quickstart
```

The demo scans an exported `send_email` schema, reports `to` as
`trusted_fixed` and `body` as `outbound_payload`, then blocks an
attacker-authored recipient before a safe local tool implementation runs. Its
invocation counter remains at zero for the blocked call and reaches one only
for the application-supplied trusted recipient. An overlong-body case proves the
schema's `maxLength` is registered and enforced at runtime without another
invocation. The local implementation records calls in memory; no email is sent.

The gate accepts a normalized tool call shaped as `{"name": ..., "input":
...}`. Provider-specific tool-call objects should be converted to that small
shape before dispatch.

```python
from verb_authority import Param, Registry, Risk, Tool, build_policy, dispatch

registry = Registry()
registry.add(
    Tool(
        "send_email",
        [Param("to", "email"), Param("body", "string")],
        risk=Risk.WRITE,
    )
)
policy = build_policy(registry)

# The model proposes an attacker-controlled recipient. The trusted value is
# supplied independently by the application from authenticated state.
tool_call = {
    "name": "send_email",
    "input": {"to": "attacker@evil.com", "body": "Meeting summary"},
}
decision = dispatch(
    registry,
    policy,
    tool_call,
    trusted_args={"to": "alice@company.com"},
)

print(decision.allow)   # False
print(decision.reason)  # param 'to' is a locked sink; data may not author it
```

`dispatch` is a decision-only API. Call it immediately before tool execution,
execute only when `decision.allow` is true, and request human approval when
`decision.needs_confirm` is true. A direct-dispatch integration owns the
atomic relationship between that decision, the exact arguments it executes,
confirmation, callable identity, and result recording. Use the guarded runner
below when those properties need to be enforced as one runtime boundary.

## Execute tools and resolve trusted choices

`GuardedToolRunner` is the synchronous integration point for a real tool loop.
It calls `dispatch` immediately before the registered function, fails closed
when required confirmation is unavailable, and records successful results in
one session ledger. Provider-specific calls still need to be normalized to the
small `name`/`input` shape shown above.

The runner accepts plain built-in JSON-shaped values (`dict`, `list`, strings,
finite numbers, booleans, and `None`). Normalize framework containers before
calling it. A root-to-leaf path is limited to 64 list/dict containers,
including the root input object, and integers are limited to 512 decimal
digits. Each logical snapshot is also limited to 100,000 total JSON values and
object keys and 8 MiB of conservatively estimated ASCII-escaped JSON material.
The tool name, proposed input, and `trusted_args` share one such budget. It is
charged incrementally, so one oversized string or a million repeated scalar
values fails without first expanding or serializing the whole value. Values
outside any portable serialization bound fail closed before confirmation or
invocation. Every registered parameter must appear explicitly in the tool
call, including a parameter declared with `Param(..., required=False)`. If the
provider or Python callable has a default, the application must materialize
that value before the gate. A protected materialized value must also appear,
with the same exact JSON type and value, in `trusted_args`. `required=False`
is retained as beta schema/API metadata; it is not permission to execute an
implicit default. The runner also rejects registered callables that consume an
undeclared parameter or rely on an undeclared default. The current core accepts
only an exact plain Python function as an implementation. Bound methods, callable
instances or classes, builtins, and partials are rejected because their hidden
receiver or bound state is not a declared tool argument; materialize that
state as explicit parameters instead.

Before confirmation, the runner isolates the tool call and trusted arguments
and snapshots registration/policy metadata. The callback receives an
immutable `ConfirmationRequest` whose ASCII-escaped, insertion-order-preserving
`arguments_json` encodes the exact private argument snapshot that can run.
Its compatibility `decision` object is also a detached snapshot, so even a
trusted callback that forcibly mutates its display object cannot rewrite the
decision metadata returned by the runner on denial.
Signed `0.0`/`-0.0` and nested object member order remain distinct in both the
snapshot and `action_id`, because Python tool implementations can observe
those differences. Runtime `Decision.reason` text ASCII-escapes control,
bidirectional, and non-ASCII characters from tool and parameter labels before
it reaches a log or terminal. A UI
may decode and show individual fields only through a trusted renderer that
neutralizes bidi/control characters and escapes each output context. Without
such a renderer, show the ASCII-escaped JSON verbatim; never inject
decoded fields directly into markup or a terminal. The request also contains
the effective risk and its evidence, the declared-risk conflict state, and
`registration_id`, `executable_id`, `ledger_version`, and `action_id`
commitments. The public inspection view and confirmation request expose policy,
risk, and risk-confidence values as detached canonical strings rather than the
process-wide Enum members retained by enforcement; compare these fields by
value (for example, `request.risk == "financial"`), not by Enum identity.
`executable_id` is an address-free SHA-256 digest of the function's
module/qualified name, code content, and raw non-unwrapped binding signature; a
separate private binding token detects replacement of the live function object
without exposing its address. `action_id` is a content commitment, not a
one-time nonce or replay-prevention mechanism. Applications must provide any
required request freshness or replay control. Approval requires the exact
boolean `True`.

Visible mutation of registered `Tool`/`Param`/policy material or replacement
of the function object/code denies the action and requires rebuilding the
runner. Derived risk, risk evidence, conflicts, and required confirmations
cannot be weakened in a caller-supplied `PolicySet`; a parameter policy can be
overridden only when that parameter appears in the derived review queue and
its bounded identifier inference completed. A review caused by an inference
resource limit remains locked; intentionally releasing it requires an explicit
`sink=False` declaration in trusted application registration code and a rebuilt
policy. Raw exported schema metadata is not a trusted release mechanism.
Required confirmation may be made stricter. The ledger's private stores and
lock are exact built-ins, are excluded from its representation, and replacement
of one after runner construction is detected. Direct in-process mutation of
private attributes remains trusted-application behavior. This is not a
semantic snapshot of module globals or closure contents.
Those are trusted application state: serialize their changes with tool
execution and rebuild the runner when they change action configuration. The
confirmation callback is likewise
trusted control-plane code; keep it synchronous and side-effect-safe, and do
not let untrusted code run inside it. Exceptions from that callback propagate
to its trusted caller. Public evidence snapshots do not alias enforcement
state, but arbitrary imported code in the same Python process remains inside
the trusted application boundary and can still interfere with module globals,
classes, or private objects. The session ledger owns a re-entrant lock. The runner
holds that shared lock from final revalidation through invocation and atomic
result publication, so multiple runners using the same ledger serialize that
critical action section. It deliberately releases the lock while human
confirmation may block, then reacquires it and rechecks configuration and the
ledger epoch. This is not a lock for globals, databases, or other application
state; externally synchronize those resources and avoid unsynchronized
mutation during a call.

The public `gate` and `dispatch` paths apply the same frozen-policy validation
as the runner: valid string forms such as `"trusted_fixed"` and `"financial"`
are normalized to their enums, while malformed, unbound, or weakened policy
material produces a closed `Decision` instead of escaping a runtime exception.

One session ledger retains at most 10,000 exact/search-index entries and 8 MiB
of UTF-8 text material. It never evicts old taint. If publishing a completed
tool result would exceed either budget, that write is not partially committed,
the ledger becomes permanently saturated, and every later call is denied until
the application starts a new session with a fresh ledger. The already-entered
tool must not be retried: the runner reports `invoked=True`, `executed=False`,
and `contract_violation="ledger_capacity_exceeded"` with that instruction.
Unicode normalization is bounded twice: no individual NFKC input may exceed
4,096 characters, and one policy-inference, gate, ledger-publication, or lookup
operation shares a cumulative 32,768-character work budget across all of its
nested values. Repeated result strings are normalized once per publication.
Budget exhaustion fails closed; data-authored locked sinks are rejected before
their nested values enter normalization at all.

The runner is deliberately synchronous. It rejects coroutine and async-
generator implementations before invocation, rejects awaitable results, and
closes native coroutine results without invoking hooks on arbitrary awaitable
objects. A successful result must also be plain finite JSON; it is
deep-snapshotted before being returned and recorded. `ExecutionResult.invoked`
says whether the callable was entered, `executed` says it completed the
synchronous JSON-result contract and was recorded, and `contract_violation`
distinguishes an awaitable or unsupported result. A callable can therefore be
`invoked=True` but `executed=False`. If a tool implementation raises an
ordinary `Exception`, the runner returns a generic denial with `invoked=True`,
`executed=False`, `result=None`, and
`contract_violation="invocation_exception"`; exception details are not placed
in the result. Process-control `BaseException` subclasses still propagate.
Never automatically retry when `invoked=True`, even if `executed=False`: the
implementation may have produced an external side effect before raising or
violating the result contract. A result beyond the JSON depth or integer bound
or the total node/material snapshot budget is reported after invocation as
`contract_violation="unsupported_result"` without exposing the result. A
snapshot-budget denial also carries an explicit no-retry instruction.
Free outbound payloads may be authored by data, but they still must satisfy
their declared runtime type and bounds such as `max_len`.

When a model supplies a human label such as a contact name, resolve that label
against an application-owned catalog first. `TrustedResolver` implements only
an exact `key -> (value, evidence)` lookup after trimming and case-folding. It
does not perform fuzzy matching, authorization, endpoint policy, or path/prefix
checks. Unknown and ambiguous keys remain unresolved. Catalog values must be
finite plain JSON. The resolver snapshots them at construction and returns a
fresh snapshot for each successful lookup, so mutating the constructor input or
one resolution cannot redefine a later trusted choice. Keys, evidence, and
normalizer results must be bounded built-in strings; string subclasses,
surrogates, oversized lookup keys, and non-string keys fail closed before
caller-controlled conversion or normalization hooks can run.

```python
from verb_authority import (
    GuardedToolRunner, Param, Registry, Risk, Tool,
    TrustedChoice, TrustedResolver,
)

contacts = TrustedResolver([
    TrustedChoice(
        "Dana",
        "dana@company.com",
        "authenticated company directory: contact-17",
    ),
])

registry = Registry()
registry.add(Tool(
    "send_email",
    [Param("to", "email"), Param("body", "string")],
    fn=send_email,
    risk=Risk.WRITE,
))
runner = GuardedToolRunner(registry)

resolution = contacts.resolve(model_selected_contact)
if not resolution.resolved:
    return {"error": resolution.status.value}

tool_call = {
    "name": "send_email",
    "input": {"to": resolution.value, "body": model_generated_body},
}
execution = runner.run(
    tool_call,
    trusted_args={"to": resolution.value},
)
```

The application must populate the catalog from a genuinely trusted source;
the `evidence` string is retained for review but is not verified by Verb
Authority. The lookup key may itself be influenced by untrusted content. The
control-flow example at the top of this page is therefore an explicit product
boundary, not an inference that the request was user-authorized.

## Pydantic AI 2.35 runtime adapter

The optional Pydantic AI adapter, introduced in beta.11, is deliberately
narrow. It routes every supported tool invocation through the existing
`GuardedToolRunner`; Pydantic performs schema generation and argument
validation, but the registered Pydantic callable is a fresh, permanently inert
function. The schema source is not retained as an execution target. The exact
function frozen in the Verb Authority `Registry` is the only implementation
that the sealed agent can invoke. At construction, the agent validates each
caller-supplied schema helper and builds a second private inert tool and
validator graph; mutating the caller-owned helper later cannot change the
runtime tool. Immediately before argument validation and again before guarded
execution, the adapter compares that private tool and validator graph with its
construction-time seal. A callback that mutates an executable validator after
run setup therefore fails before the validator or Registry implementation can
execute.

The optional extra pins Pydantic AI 2.35.0, Pydantic 2.13.4, and
pydantic-core 2.46.4 because this fail-closed adapter audits private runtime
surfaces rather than assuming compatibility from public version ranges.
Pydantic 2.13.4 builds one of two validator shapes depending on whether its
plugin loader finds installed plugins. The adapter accepts the exact direct
`SchemaValidator` used by a clean installation, or Pydantic's exact plugin
container only while all three validation methods remain bound directly to the
same sealed core validator. Plugin-provided executable validation wrappers are
outside this beta's trust boundary and fail closed.

Install the optional integration from a local checkout:

```bash
python -I -m pip install ".[pydantic]"
```

For an application-fixed recipient, omit `to` from the model-visible Pydantic
function entirely and inject it through an authenticated session:

```python
from verb_authority import Param, Registry, Risk, Tool, build_policy
from verb_authority_pydantic import (
    PydanticAuthorityAgent,
    PydanticAuthoritySession,
    pydantic_schema_tool,
)

def send_email(to: str, body: str):
    # The real implementation; only GuardedToolRunner may call it.
    return {"status": "sent", "to": to}

def model_visible_send_email(body: str):
    # Schema source only. The adapter never calls this function.
    raise AssertionError("unreachable")

registry = Registry()
registry.add(Tool(
    "send_email",
    [
        Param("to", "email", sink=True),
        Param("body", "string", sink=False),
    ],
    fn=send_email,
    risk=Risk.WRITE,
))

session = PydanticAuthoritySession(
    registry,
    build_policy(registry),
    trusted_fixed={
        "send_email": {"to": "dana@company.com"},
    },
)

agent = PydanticAuthorityAgent(
    existing_model,
    deps_type=PydanticAuthoritySession,
    tools=[pydantic_schema_tool(model_visible_send_email, name="send_email")],
)

result = agent.run_sync(
    "Send Dana the meeting summary",
    deps=session,  # created by authenticated application code, never by the model
)
```

For an approved catalog choice, keep the key visible to the model and bind the
argument through `trusted_choices`. A model value such as `"Dana"` is resolved
to the catalog's canonical value plus evidence before the gate sees it.
Unknown and ambiguous keys fail closed. A later trusted resolution cannot
launder a value already recorded as untrusted tool output in the session
ledger.

The adapter also accepts finite, exact JSON-scalar `Literal[...]` annotations
for a selector whose `Registry` tool carries an exhaustive `selector_cases`
map. `Literal` constrains representation only: the runtime registration must
still use `sink=False` when the model is intentionally allowed to choose the
selector. The selected branch then controls effective risk, active arguments,
and deferred-confirmation metadata, and approval is bound to that exact branch.

The current Pydantic adapter supports branch risk only when every selector
case shares one model-visible active-argument shape. A session rejects
branch-varying `active_args` during construction instead of failing later at
invocation. The core gate and scanner do support branch-varying active
arguments, but Pydantic AI materializes one global required/default argument
shape before this adapter's gate runs. Split such a polymorphic tool into
separate Pydantic tools, or use `GuardedToolRunner` directly; this first
adapter does not add a conditional-schema DSL.

The first adapter is intentionally pinned to
`pydantic-ai-slim==2.35.0`, `pydantic==2.13.4`, and its exact core, and supports
only direct, local
`PydanticAuthorityAgent` tools created by `pydantic_schema_tool`, whose
authoritative implementations are synchronous callables frozen by the
Registry runner.
Every protected argument must have either a fixed application binding or a
closed `TrustedResolver`. A direct tool absent from the Registry fails run
setup. Runtime-added, remote, capability-provided, MCP, provider-native,
deferred/native-swapped, executable output-tool, durable, and asynchronous
execution paths are rejected rather than left outside the gate. Realtime
sessions are rejected at run setup because their provider-side tool path does
not pass through the audited classic-run hooks. `run_stream`,
`run_stream_sync`, and `run_stream_events` are also explicitly unsupported in
this beta. Supplying an `event_stream_handler` to `run` or `run_sync` is
unsupported too. In particular, Pydantic's mutable event-stream `RunBinding`
is rejected before the sealed `Agent.iter` entry grant exists; it is never
reconciled after entry. Use `run`, `run_sync`, or `iter` without an event
handler. Validation-time
approval and external deferral are rejected as well: a resumed caller-supplied
result would otherwise reach the model without execution by the guarded
Registry function or a provenance-ledger record. Application-supplied static and per-run
Pydantic capabilities are rejected in this beta, as are runtime toolsets. They
are rejected before Pydantic invokes their `for_agent`, `for_run`, enter, or
wrapper hooks, so a setup or error-recovery hook cannot turn a rejected run
into a forged success. The two Pydantic-injected infrastructure capabilities
are accepted only in their exact pristine 2.35 state. Manual or per-run
installation of `VerbAuthorityCapability` is not a supported API. The sealed
agent installs it statically, inspects the pinned `CombinedCapability` list
directly rather than asking the mutable root to describe itself, seals every
child against instance-method shadowing, and verifies the complete root before
every run. It rejects `override(spec=...)`,
tool-boundary overrides, post-construction tool registration, and declarative
`from_spec`/`from_file` construction. If the capability boundary is absent,
the inert Pydantic callable still fails before any Registry implementation can
run. The session getter is bound to one exact session object for the whole
run; changing tenants, registries, policies, or ledgers between hooks fails
closed. Model-visible signatures are limited to exact `str`, `int`, `float`,
`bool`, `list[T]`, `dict[str, T]`, and finite exact JSON-scalar `Literal[...]`
shapes. `Annotated` validators, unions, models, Python enums, custom classes,
mutable defaults, `Field` metadata, and default factories fail setup without
being executed. Defaults are limited to immutable finite JSON scalars. Each
model tool call must be an exact Pydantic
`ToolCallPart` with bounded plain-string identities. Its arguments and
provider details are copied into bounded plain JSON before Pydantic argument
validation; subclasses and aliased or cyclic object graphs fail closed.
Pydantic-owned tool timeouts are rejected too: the adapter intentionally
does not call Pydantic's execution handler, and a synchronous Python thread
cannot be safely killed. Resource limits must therefore be enforced inside the
registered implementation or its transport.

Financial, destructive, code-execution, and unknown-risk calls use Pydantic's
deferred approval flow. The session accepts approval only for the exact prior
tool-call ID, action commitment, arguments, registered executable, and ledger
version. Changing an amount after the approval request creates a new request;
it does not execute under the old approval. Pending state retains only a
fixed-size action commitment, not the argument payload. Pydantic denials are
removed automatically; applications should call
`session.discard_pending_approval(tool_call_id)` when a request is cancelled or
abandoned without sending a denial result back to Pydantic. Resume input is
deliberately narrower than Pydantic's general deferred API: only exact boolean
decisions for IDs currently pending in this session are accepted. External
`calls` results and caller-supplied deferred metadata are rejected before
Pydantic can convert them into a result visible to the model. A one-use,
run-bound transition then checks Pydantic's normalized approval or denial
against those exact raw booleans before execution. Manually driving a
`CallToolsNode` cannot insert an approval or result without that immediately
preceding transition. In a mixed batch, Pydantic's internal `skip` marker is
accepted only for the same call ID and tool name already settled in the
authenticated history; the approved sibling still executes exactly once.
Approval and tool-call batches are capped at 256 entries.

The live `AgentRun`, its backing `GraphRun`, graph iterator, graph dependencies,
tool manager, and execution state are sealed as one runtime identity. Retaining
the private `GraphRun`, replacing an iterator dependency alias, and advancing
it directly fails before a capability hook, Registry function, or ledger write.
Only the exact current node may advance. Its lifecycle may begin only in the exact asyncio task that
drives the transition, and each exact node is claimed once in the external
run seal before any callback or await. A child task that copied the context
therefore cannot start the node again and re-arm a consumed permit. Every
validation or execution sink still requires the active transition token for
that sealed run so Pydantic's legitimate parallel tool tasks can proceed.
That transition alone is not an execution authority: `before_node_run` mints
one permit for each exact
executable call in the exact current `CallToolsNode`. Validation binds the
permit to both the raw and validated plain-JSON arguments. For a selector,
its raw presence, JSON-scalar type, value, and signed zero must survive
Pydantic validation exactly; coercion is rejected before trusted resolvers,
the ledger, or the Registry implementation can run. Execution consumes the
permit before trusted resolvers, confirmation callbacks, ledger writes, or
the Registry implementation can run. An instruction, model-setting, or other
accepted callback therefore cannot borrow a valid node transition to execute
a different call, and a nested or replayed call finds no permit.
Approved permits are additionally bound to the pending action commitment.
Every node must also be driven by the exact sealed `AgentRun` step function;
an event handler or replaced node driver cannot observe a context while a
permit is live, even through an explicit unbound call to Pydantic's base API.
Calling an unbound base `Agent.iter`, `AgentRun._advance_graph`, or
`ToolManager.handle_call` therefore cannot expose an unsealed run, inject a
result, or turn `approved=True` into an execution. The base-iter entry grant is
bound to the exact asyncio task, consumed before setup continues, and created
only after executable retry mappings and mutable run-stream bindings have been
removed from the path. Rewriting the agent's own expected-baseline fields or a
public resume-marker attribute does not rewrite the external seals. These
checks run before the Registry implementation and ledger can change; a later
context-exit check is defense in depth, not the enforcement point.

Any non-empty `message_history` passed to a resumed run must be authenticated,
unmodified history produced by the same application session and ledger. This
adapter does not authenticate foreign Pydantic history or reconstruct
provenance that was never recorded by Verb Authority. If an application
accepts caller-authored history, the adapter's provenance claims do not apply
to that history.

The local Python `Model` implementation and provider adapter are inside the
trusted application boundary. In particular, a custom `FunctionModel`
callback is executable application code, and Pydantic may inspect the Python
objects it returns before capability hooks regain control. It must return
provider-shaped values built from exact plain Python/JSON types. A remote model
controlling JSON bytes cannot create a Python `list` or `str` subclass, but an
untrusted in-process model implementation could; this adapter does not sandbox
such Python code.

This integration preserves the same stated claim boundaries as the core gate:
per-argument provenance and local constraints, plus explicitly registered
exact one-selector branch risk and argument applicability. It does not
establish selection intent, general cross-argument composition, sequence, or
action-instance authorization. If Pydantic or application code can invoke an
implementation through any route not covered above, that route is outside
this beta and must remain disabled.

## Integrating a tool loop

`trusted_args` is an application provenance declaration: an argument is marked
trusted only when it equals the corresponding application-supplied value.
Everything else is data.

```python
from verb_authority import Param, ProvenanceLedger, Registry, Risk, Tool
from verb_authority import build_policy, dispatch

registry = Registry()
registry.add(
    Tool(
        "send_email",
        [Param("to", "email"), Param("subject"), Param("body")],
        risk=Risk.WRITE,
    )
)
policy = build_policy(registry)
ledger = ProvenanceLedger()

# After normalizing the model/provider tool call:
decision = dispatch(
    registry,
    policy,
    tool_call,
    trusted_args={"to": user_confirmed_email},
    ledger=ledger,
)
if not decision.allow:
    return {"error": decision.reason}
if decision.needs_confirm and not ask_user(decision.reason):
    return {"error": "user denied"}

result = run_tool(tool_call)
ledger.record_result(result)
```

For a reviewed polymorphic tool, trusted application code can register one
exact selector map. The selector remains explicitly model-authored here;
branch metadata changes the risk and accepted argument set, not its
provenance:

```python
from verb_authority import GuardedToolRunner, SelectorCase

def browser_tabs(action: str, **active_arguments):
    # Only arguments admitted by the selected branch reach this function.
    return call_browser(action=action, **active_arguments)

registry.add(Tool(
    "browser_tabs",
    [
        Param(
            "action",
            "enum",
            enum=["list", "new", "close", "select"],
            sink=False,
        ),
        Param("index", "integer", sink=False),
        Param("url", "uri"),
    ],
    fn=browser_tabs,
    risk=Risk.WRITE,
    selector="action",
    selector_cases=[
        SelectorCase("list", Risk.READ_ONLY, ["action"]),
        SelectorCase("new", Risk.WRITE, ["action", "url"]),
        SelectorCase("close", Risk.DESTRUCTIVE, ["action", "index"]),
        SelectorCase("select", Risk.WRITE, ["action", "index"]),
    ],
))

runner = GuardedToolRunner(registry)
result = runner.run(
    {"name": "browser_tabs", "input": {"action": "close", "index": 0}},
    confirm=show_structured_confirmation,
)
```

`list` runs at read-only risk, while `close` is bound to a destructive
confirmation request containing the exact selector value and active arguments.
Sending `index` on the `list` branch, omitting `index` from `close`, changing
the selector after approval, or using an unmapped value fails before the
implementation runs. The application's own authorization layer must still
decide whether closing that particular tab is permitted.

When selector cases have different active-argument sets, the registered Python
implementation must accept those conditional arguments through `**kwargs`, as
shown above. An explicit Python parameter that is inactive in any case is
rejected at registration, preventing its callable default from materializing
after authorization. The first Pydantic AI adapter is narrower still: every
case must share one model-visible argument shape; split a polymorphic tool or
use `GuardedToolRunner` directly when its shapes differ.

This direct-dispatch example leaves confirmation-to-execution atomicity,
callable identity, result validation, and result capture to the application.
Thread one ledger through the session and record each plain JSON result
immediately after the tool returns. If `record_result` raises a capacity error,
the tool has already run: do not retry it, discard the saturated session, and
start a fresh ledger. Prefer `GuardedToolRunner` when those
operations should share the frozen runtime boundary described above. The
ledger is a containment layer, not sound taint tracking: it recognizes values
(including every exact key, exact containers, and typed scalar leaves nested
in JSON) and selected risk-shaped lexical forms, not arbitrary transformations
or control flow.

## Related boundaries

- [Security model](security-model.md)
- [Limits and boundaries](limits-and-boundaries.md)
