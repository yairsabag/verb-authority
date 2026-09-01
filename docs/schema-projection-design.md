# Optional schema-projection API: design proposal

**Status:** design proposal only. No generic schema-projection API is shipped
in beta.14.

## Problem and preferred remediation

Consider the canonical application tool:

```text
send_email(to: str, body: str)
```

If authenticated application state already determines `to`, the model does
not need authority to author that argument. The preferred model-visible shape
is therefore:

```text
send_reply(body: str)
```

`send_reply` is a conceptual model-visible name in this proposal, not a
function or alias API shipped in beta.14. A framework-native integration may
keep the canonical model-visible name and still omit `to`.

Immediately before execution, trusted application code supplies `to` from
state that was established independently of webpages, retrieved documents,
model output, and prior untrusted tool results. Merely copying an untrusted
value into an application object does not make it trusted.

The canonical `send_email(to, body)` registration and callable remain intact.
Projection narrows what the model can propose; it does not create a second
executable implementation. When projection is unavailable, the compatibility
path is to keep the canonical model-visible schema and require the exact
application-owned value in both the canonical call input and `trusted_args` at
the runtime gate. `trusted_args` verifies an exact match; it does not insert or
overwrite the call input.

## Proposed explicit shape

The names below are illustrative and intentionally do not establish a public
API:

```python
projection = project_tool_schema(
    runner,
    tool_name="send_email",
    model_name="send_reply",
    remove={"to"},
)

# Only this schema is sent to the model.
model_schema = projection.model_schema

# The provider returns only model-visible arguments.
model_call = {
    "name": "send_reply",
    "input": {"body": model_body},
}

execution = runner.run_projected(
    projection,
    model_call,
    trusted_args={"to": authenticated_session.recipient},
)
```

The runner supplies the frozen canonical registry and policy to which the
projection binds. The application must explicitly choose the canonical tool,
optional model-visible alias, removed arguments, and trusted values. The API
must not infer any of them from request content.

## Required invariants

Any implementation should preserve all of these properties:

1. **One canonical executable tool.** The `Registry` continues to own the
   canonical tool, parameter contract, risk metadata, and callable. Projection
   creates schema data and binding metadata, not an executable wrapper.
2. **Explicit eligible arguments.** An argument may be projected out only when
   it is explicitly selected by trusted application code and its reviewed
   authority is suitable for application binding. An uncertain
   `trusted_fixed` result, an argument marked `review_required`, or a selector
   the model is meant to choose must not be removed automatically.
3. **Model input cannot author hidden arguments.** A projected call containing
   `to`, including a value equal to the trusted value, fails closed. Hidden
   arguments are never accepted from the model/provider input object.
4. **Every hidden value comes from `trusted_args`.** Each removed required
   argument must be present with its exact JSON type and value. There is no
   fallback to a model value, callable default, environment guess, prior tool
   result, or request-derived state.
5. **Fresh canonical snapshot.** Binding creates a fresh canonical input by
   combining validated model-visible arguments with application-supplied
   hidden arguments. That exact snapshot and the same `trusted_args` then pass
   through `GuardedToolRunner`; projection does not replace the runtime gate.
6. **Registration and projection binding.** Projection metadata is bound to an
   immutable normalized fingerprint of the canonical tool registration, the
   relevant policy state, and the exact projected schema. A tool, parameter,
   alias, policy, or projected-schema change invalidates the binding before
   confirmation or execution.
7. **Existing runtime guarantees remain.** Type and bounds validation,
   provenance checks, branch risk, confirmation binding, callable identity,
   resource budgets, and ledger containment still apply to the reconstructed
   canonical call.
8. **Reports remain advisory.** A remediation recommendation may explain that
   projection is preferred, but it neither proves that a trusted source exists
   nor performs a schema or runtime change. Review-required selector-like
   arguments remain distinguished from other uncertain authority in the report
   through `selector_semantics_require_review` and
   `authority_inference_requires_review`; neither reason authorizes automatic
   projection.

## Fail-closed conditions

A projected call should be rejected before the canonical callable can run
when any of the following is true:

- the model/provider supplies a hidden argument;
- a hidden argument is missing from `trusted_args`;
- a trusted value differs in JSON type or value from the restored value;
- the canonical registration, policy state, or projected schema no longer
  matches its bound fingerprint;
- the model-visible alias resolves ambiguously or to another canonical tool;
- an argument is no longer eligible for projection after review or policy
  changes; or
- normalization or resource-budget checks fail.

## Non-goals

This proposal does not include:

- generating, deploying, or registering executable wrappers automatically;
- guessing where a trusted value comes from or whether application state is
  actually independent of untrusted content;
- generating context-specific tool families or dozens of tool aliases;
- changing business authorization, identity, freshness, or approval policy;
- adding a conditional-schema or policy DSL; or
- bypassing `GuardedToolRunner` for projected calls.

The proposal should remain optional until additional real schemas show that a
generic projection API is preferable to framework-native patterns such as
application context injection.
