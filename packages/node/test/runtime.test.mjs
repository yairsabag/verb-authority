import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { runInNewContext } from "node:vm";

import { createGuardedToolRunner } from "../dist/index.js";

function emailRegistration(handler, overrides = {}) {
  return {
    name: "send_email",
    risk: "write",
    params: [
      { name: "to", authority: "trusted_fixed", type: "string" },
      {
        name: "body",
        authority: "outbound_payload",
        type: "string",
        maxLength: 2000,
      },
    ],
    handler,
    ...overrides,
  };
}

function emailCall(to = "alice@company.com", body = "Meeting summary") {
  return { name: "send_email", input: { to, body } };
}

test("untrusted recipient is blocked before invocation", async () => {
  let invocations = 0;
  const runner = createGuardedToolRunner([
    emailRegistration(() => {
      invocations += 1;
      return { ok: true };
    }),
  ]);

  const result = await runner.run(emailCall("attacker@evil.com"), {
    trustedArgs: { to: "alice@company.com" },
  });

  assert.equal(result.decision.code, "trusted_value_mismatch");
  assert.equal(result.invoked, false);
  assert.equal(result.handlerCompleted, false);
  assert.equal(result.resultValidated, false);
  assert.equal(invocations, 0);
});

test("application-supplied exact recipient invokes the private handler once", async () => {
  const received = [];
  const runner = createGuardedToolRunner([
    emailRegistration((input) => {
      received.push(input);
      return { ok: true };
    }),
  ]);

  const result = await runner.run(emailCall(), {
    trustedArgs: { to: "alice@company.com" },
  });

  assert.equal(result.decision.code, "allowed");
  assert.equal(result.invoked, true);
  assert.equal(result.handlerCompleted, true);
  assert.equal(result.resultValidated, true);
  assert.equal(received.length, 1);
  assert.equal(received[0].to, "alice@company.com");
  assert.equal(Object.isFrozen(received[0]), true);
});

test("bounds apply before invocation on data-authored arguments", async () => {
  let invocations = 0;
  const runner = createGuardedToolRunner([
    emailRegistration(() => {
      invocations += 1;
      return null;
    }),
  ]);

  const result = await runner.run(emailCall("alice@company.com", "x".repeat(2001)), {
    trustedArgs: { to: "alice@company.com" },
  });

  assert.equal(result.decision.code, "constraint_violation");
  assert.equal(result.invoked, false);
  assert.equal(invocations, 0);
});

test("every registered bound is enforced, including on trusted_fixed values", async () => {
  let invocations = 0;
  const runner = createGuardedToolRunner([
    {
      name: "bounded_write",
      risk: "write",
      params: [
        {
          name: "destination",
          authority: "trusted_fixed",
          type: "string",
          maxLength: 4,
        },
        {
          name: "amount",
          authority: "typed_bounded",
          type: "number",
          minimum: 0,
          maximum: 10,
        },
        {
          name: "items",
          authority: "outbound_payload",
          type: "array",
          maxItems: 2,
        },
        {
          name: "metadata",
          authority: "outbound_payload",
          type: "object",
          maxProperties: 1,
        },
      ],
      handler: () => {
        invocations += 1;
        return null;
      },
    },
  ]);
  const base = {
    destination: "safe",
    amount: 5,
    items: [1],
    metadata: { one: 1 },
  };
  const run = (input, trustedDestination = input.destination) => runner.run(
    { name: "bounded_write", input },
    { trustedArgs: { destination: trustedDestination } },
  );

  const cases = [
    [{ ...base, destination: "longer" }, "longer"],
    [{ ...base, amount: -1 }, "safe"],
    [{ ...base, amount: 11 }, "safe"],
    [{ ...base, items: [1, 2, 3] }, "safe"],
    [{ ...base, metadata: { one: 1, two: 2 } }, "safe"],
  ];
  for (const [input, trustedDestination] of cases) {
    const result = await run(input, trustedDestination);
    assert.equal(result.decision.code, "constraint_violation");
    assert.equal(result.invoked, false);
  }
  assert.equal((await run(base)).resultValidated, true);
  assert.equal(invocations, 1);
});

test("unknown tool, unknown argument, and missing argument fail before confirmation", async () => {
  let confirmations = 0;
  let invocations = 0;
  const runner = createGuardedToolRunner([
    emailRegistration(() => {
      invocations += 1;
      return null;
    }, { risk: "destructive" }),
  ]);
  const confirm = () => {
    confirmations += 1;
    return true;
  };

  const unknownTool = await runner.run(
    { name: "other_tool", input: {} },
    { confirm },
  );
  const unknownArgument = await runner.run(
    {
      name: "send_email",
      input: { to: "alice@company.com", body: "ok", extra: true },
    },
    { trustedArgs: { to: "alice@company.com" }, confirm },
  );
  const missingArgument = await runner.run(
    { name: "send_email", input: { to: "alice@company.com" } },
    { trustedArgs: { to: "alice@company.com" }, confirm },
  );

  assert.equal(unknownTool.decision.code, "unknown_tool");
  assert.equal(unknownArgument.decision.code, "unknown_argument");
  assert.equal(missingArgument.decision.code, "missing_argument");
  assert.equal(confirmations, 0);
  assert.equal(invocations, 0);
});

test("trustedArgs may name only trusted_fixed arguments", async () => {
  const runner = createGuardedToolRunner([emailRegistration(() => null)]);
  const result = await runner.run(emailCall(), {
    trustedArgs: {
      to: "alice@company.com",
      body: "Meeting summary",
    },
  });
  assert.equal(result.decision.code, "invalid_trusted_args");
  assert.equal(result.invoked, false);
});

test("deep exact authority distinguishes booleans, numbers, signed zero, and object order", async () => {
  let invocations = 0;
  const runner = createGuardedToolRunner([
    {
      name: "use_value",
      risk: "write",
      params: [{ name: "value", authority: "trusted_fixed", type: "json" }],
      handler: () => {
        invocations += 1;
        return null;
      },
    },
  ]);

  const booleanVsNumber = await runner.run(
    { name: "use_value", input: { value: true } },
    { trustedArgs: { value: 1 } },
  );
  const signedZero = await runner.run(
    { name: "use_value", input: { value: -0 } },
    { trustedArgs: { value: 0 } },
  );
  const reordered = await runner.run(
    { name: "use_value", input: { value: { first: 1, second: 2 } } },
    { trustedArgs: { value: { second: 2, first: 1 } } },
  );
  const exact = await runner.run(
    { name: "use_value", input: { value: { first: 1, second: [2, 3] } } },
    { trustedArgs: { value: { first: 1, second: [2, 3] } } },
  );

  assert.equal(booleanVsNumber.decision.code, "trusted_value_mismatch");
  assert.equal(signedZero.decision.code, "trusted_value_mismatch");
  assert.equal(reordered.decision.code, "trusted_value_mismatch");
  assert.equal(exact.resultValidated, true);
  assert.equal(invocations, 1);
});

test("enum equality is type-strict", async () => {
  let invocations = 0;
  const runner = createGuardedToolRunner([
    {
      name: "choose",
      risk: "read_only",
      params: [
        {
          name: "value",
          authority: "typed_bounded",
          type: "json",
          enum: [1, "1"],
        },
      ],
      handler: () => {
        invocations += 1;
        return null;
      },
    },
  ]);

  assert.equal(
    (await runner.run({ name: "choose", input: { value: true } })).decision.code,
    "constraint_violation",
  );
  assert.equal(
    (await runner.run({ name: "choose", input: { value: 1 } })).resultValidated,
    true,
  );
  assert.equal(invocations, 1);
});

test("string bounds count Unicode code points and reject lone surrogates", async () => {
  let invocations = 0;
  const runner = createGuardedToolRunner([
    {
      name: "write_label",
      risk: "write",
      params: [
        {
          name: "label",
          authority: "outbound_payload",
          type: "string",
          maxLength: 1,
        },
      ],
      handler: () => {
        invocations += 1;
        return null;
      },
    },
  ]);

  assert.equal(
    (await runner.run({ name: "write_label", input: { label: "😀" } })).resultValidated,
    true,
  );
  const lone = await runner.run({
    name: "write_label",
    input: { label: "\ud800" },
  });
  assert.equal(lone.decision.code, "invalid_call");
  assert.equal(invocations, 1);
});

test("unsafe integers and non-finite numbers fail closed", async () => {
  const runner = createGuardedToolRunner([
    {
      name: "calculate",
      risk: "read_only",
      params: [
        {
          name: "value",
          authority: "typed_bounded",
          type: "number",
          minimum: -100,
          maximum: 100,
        },
      ],
      handler: () => null,
    },
  ]);

  for (const value of [Number.MAX_SAFE_INTEGER + 1, Number.NaN, Infinity, -Infinity]) {
    const result = await runner.run({ name: "calculate", input: { value } });
    assert.equal(result.decision.code, "invalid_call");
    assert.equal(result.invoked, false);
  }
});

test("cycles, shared aliases, exotic objects, sparse arrays, and symbol keys are rejected", async () => {
  const runner = createGuardedToolRunner([
    {
      name: "accept_json",
      risk: "read_only",
      params: [{ name: "value", authority: "outbound_payload", type: "json" }],
      handler: () => null,
    },
  ]);

  const cycle = {};
  cycle.self = cycle;
  const shared = { safe: true };
  const sparse = new Array(2);
  sparse[1] = "present";
  const symbolValue = { safe: true };
  symbolValue[Symbol("hidden")] = "no";
  const cases = [cycle, { left: shared, right: shared }, new Date(), sparse, symbolValue];

  for (const value of cases) {
    const result = await runner.run({ name: "accept_json", input: { value } });
    assert.equal(result.decision.code, "invalid_call");
    assert.equal(result.invoked, false);
  }
});

test("prototype-masked built-ins remain exotic and cannot collapse to empty JSON", async () => {
  const runner = createGuardedToolRunner([
    {
      name: "accept_json",
      risk: "read_only",
      params: [{ name: "value", authority: "outbound_payload", type: "json" }],
      handler: () => null,
    },
  ]);
  const masked = [new Date(), new Map(), new Set(), /pattern/u, new Number(7)];
  for (const value of masked) {
    Object.setPrototypeOf(value, Object.prototype);
    const result = await runner.run({ name: "accept_json", input: { value } });
    assert.equal(result.decision.code, "invalid_call");
    assert.equal(result.invoked, false);
  }

  const trustedRunner = createGuardedToolRunner([
    {
      name: "use_target",
      risk: "write",
      params: [{ name: "target", authority: "trusted_fixed", type: "json" }],
      handler: () => null,
    },
  ]);
  const disguisedDate = new Date();
  Object.setPrototypeOf(disguisedDate, Object.prototype);
  const malformedTrusted = await trustedRunner.run(
    { name: "use_target", input: { target: {} } },
    { trustedArgs: { target: disguisedDate } },
  );
  assert.equal(malformedTrusted.decision.code, "invalid_trusted_args");
  assert.equal(malformedTrusted.invoked, false);
});

test("malformed trusted application state is reported separately from the call", async () => {
  let invocations = 0;
  const runner = createGuardedToolRunner([
    emailRegistration(() => {
      invocations += 1;
      return null;
    }),
  ]);
  const cycle = { to: "alice@company.com" };
  cycle.self = cycle;

  const result = await runner.run(emailCall(), { trustedArgs: cycle });

  assert.equal(result.decision.code, "invalid_trusted_args");
  assert.equal(result.invoked, false);
  assert.equal(invocations, 0);
});

test("input getters are rejected without being invoked", async () => {
  let getterReads = 0;
  const input = { body: "Meeting summary" };
  Object.defineProperty(input, "to", {
    enumerable: true,
    get() {
      getterReads += 1;
      return "alice@company.com";
    },
  });
  const runner = createGuardedToolRunner([emailRegistration(() => null)]);
  const result = await runner.run({ name: "send_email", input }, {
    trustedArgs: { to: "alice@company.com" },
  });
  assert.equal(result.decision.code, "invalid_call");
  assert.equal(getterReads, 0);
});

test("Proxy inputs and run options are rejected before their traps can run", async () => {
  let traps = 0;
  let invocations = 0;
  const handler = {
    getPrototypeOf() {
      traps += 1;
      return Object.prototype;
    },
    ownKeys() {
      traps += 1;
      return ["value"];
    },
    getOwnPropertyDescriptor() {
      traps += 1;
      return { configurable: true, enumerable: true, value: "safe" };
    },
  };
  const runner = createGuardedToolRunner([
    {
      name: "accept_json",
      risk: "read_only",
      params: [{ name: "value", authority: "outbound_payload", type: "json" }],
      handler: () => {
        invocations += 1;
        return null;
      },
    },
  ]);

  const inputProxy = new Proxy({ value: "safe" }, handler);
  const inputResult = await runner.run({ name: "accept_json", input: inputProxy });
  const optionsProxy = new Proxy({}, handler);
  const optionsResult = await runner.run(
    { name: "accept_json", input: { value: "safe" } },
    optionsProxy,
  );
  assert.equal(inputResult.decision.code, "invalid_call");
  assert.equal(optionsResult.decision.code, "invalid_trusted_args");
  assert.equal(traps, 0);
  assert.equal(invocations, 0);
});

test("ambient prototype pollution cannot expose the private prepared handler", async () => {
  let invocations = 0;
  const runner = createGuardedToolRunner([
    {
      name: "delete_once",
      risk: "destructive",
      params: [],
      handler: () => {
        invocations += 1;
        return { ok: true };
      },
    },
  ]);
  Object.defineProperty(Object.prototype, "allow", {
    value: true,
    configurable: true,
  });
  try {
    const result = await runner.run({ name: "delete_once", input: {} });
    assert.equal(result.decision.allow, false);
    assert.equal(result.decision.code, "confirmation_required");
    assert.equal(result.invoked, false);
    assert.equal(invocations, 0);
    assert.deepEqual(
      Reflect.ownKeys(result.decision).sort(),
      ["allow", "code", "needsConfirmation", "reason"],
    );
  } finally {
    delete Object.prototype.allow;
  }
});

test("ambient then pollution cannot assimilate the public execution result", async () => {
  const runner = createGuardedToolRunner([
    {
      name: "read_once",
      risk: "read_only",
      params: [],
      handler: () => ({ ok: true }),
    },
  ]);
  let thenReads = 0;
  Object.defineProperty(Object.prototype, "then", {
    configurable: true,
    get() {
      thenReads += 1;
      return undefined;
    },
  });
  try {
    const result = await runner.run({ name: "read_once", input: {} });
    assert.equal(result.decision.code, "allowed");
    assert.equal(result.resultValidated, true);
    assert.equal(Object.getPrototypeOf(result), null);
    assert.equal(Object.getPrototypeOf(result.decision), null);
    assert.equal(thenReads, 0);
  } finally {
    delete Object.prototype.then;
  }
});

test("descriptor checks ignore inherited value pollution without reading getters", () => {
  let inheritedReads = 0;
  let sourceReads = 0;
  const registration = {
    risk: "write",
    params: [],
    handler: () => ({ ok: true }),
  };
  Object.defineProperty(registration, "name", {
    enumerable: true,
    get() {
      sourceReads += 1;
      return "write_once";
    },
  });
  const params = [];
  Object.defineProperty(params, "0", {
    enumerable: true,
    get() {
      sourceReads += 1;
      return {};
    },
  });
  const arrayRegistration = {
    name: "write_once",
    risk: "write",
    params,
    handler: () => ({ ok: true }),
  };
  try {
    Object.defineProperty(Object.prototype, "value", {
      configurable: true,
      get() {
        inheritedReads += 1;
        return "polluted";
      },
    });
    assert.throws(() => createGuardedToolRunner([registration]), /data fields/u);
    assert.throws(() => createGuardedToolRunner([arrayRegistration]), /sparse|accessors/u);
    assert.equal(inheritedReads, 0);
    assert.equal(sourceReads, 0);
  } finally {
    delete Object.prototype.value;
  }
});

test("deep and material resource limits fail before invocation", async () => {
  let invocations = 0;
  const runner = createGuardedToolRunner([
    {
      name: "accept_json",
      risk: "read_only",
      params: [{ name: "value", authority: "outbound_payload", type: "json" }],
      handler: () => {
        invocations += 1;
        return null;
      },
    },
  ]);
  let deep = null;
  for (let index = 0; index < 70; index += 1) deep = [deep];
  const deepResult = await runner.run({ name: "accept_json", input: { value: deep } });
  const hugeResult = await runner.run({
    name: "accept_json",
    input: { value: "x".repeat(1_400_000) },
  });
  const tooManyValuesResult = await runner.run({
    name: "accept_json",
    input: { value: new Array(100_000).fill(null) },
  });
  const wideObject = Object.create(null);
  for (let index = 0; index < 50_000; index += 1) {
    wideObject[`k${index}`] = null;
  }
  const tooManyFieldsResult = await runner.run({
    name: "accept_json",
    input: { value: wideObject },
  });
  assert.equal(deepResult.decision.code, "invalid_call");
  assert.equal(hugeResult.decision.code, "invalid_call");
  assert.equal(tooManyValuesResult.decision.code, "invalid_call");
  assert.equal(tooManyFieldsResult.decision.code, "invalid_call");
  assert.equal(invocations, 0);
});

test("prototype-sensitive JSON keys are rejected before handler code can merge them", async () => {
  let invocations = 0;
  const runner = createGuardedToolRunner([
    {
      name: "accept_json",
      risk: "read_only",
      params: [{ name: "value", authority: "outbound_payload", type: "json" }],
      handler: (input) => {
        invocations += 1;
        Object.assign({}, input.value);
        return null;
      },
    },
  ]);
  for (const payload of [
    JSON.parse('{"__proto__":{"polluted":true}}'),
    { nested: { constructor: { prototype: { polluted: true } } } },
  ]) {
    const result = await runner.run({
      name: "accept_json",
      input: { value: payload },
    });
    assert.equal(result.decision.code, "invalid_call");
    assert.equal(result.invoked, false);
  }
  assert.equal(invocations, 0);
  assert.equal({}.polluted, undefined);
});

test("registration mutation cannot weaken policy or replace the captured handler", async () => {
  let originalInvocations = 0;
  let replacementInvocations = 0;
  const registration = emailRegistration(() => {
    originalInvocations += 1;
    return null;
  });
  const runner = createGuardedToolRunner([registration]);
  registration.params[0].authority = "outbound_payload";
  registration.handler = () => {
    replacementInvocations += 1;
    return null;
  };

  const blocked = await runner.run(emailCall("attacker@evil.com"), {
    trustedArgs: { to: "alice@company.com" },
  });
  const allowed = await runner.run(emailCall(), {
    trustedArgs: { to: "alice@company.com" },
  });
  assert.equal(blocked.invoked, false);
  assert.equal(allowed.resultValidated, true);
  assert.equal(originalInvocations, 1);
  assert.equal(replacementInvocations, 0);
});

test("the private registration object is never exposed as the handler receiver", async () => {
  let receiver = "not-called";
  let invocations = 0;
  const runner = createGuardedToolRunner([
    emailRegistration(function (input) {
      receiver = this;
      invocations += 1;
      return { copied: input.body };
    }),
  ]);

  const allowed = await runner.run(emailCall(), {
    trustedArgs: { to: "alice@company.com" },
  });
  const unknown = await runner.run(
    {
      name: "send_email",
      input: {
        to: "alice@company.com",
        body: "Meeting summary",
        unregistered: "must stay unknown",
      },
    },
    { trustedArgs: { to: "alice@company.com" } },
  );

  assert.equal(receiver, undefined);
  assert.equal(allowed.resultValidated, true);
  assert.equal(unknown.decision.code, "unknown_argument");
  assert.equal(invocations, 1);
});

test("high-risk tools require confirmation and only exact true proceeds", async () => {
  const responses = [false, null, 0, 1, "true", {}, new Boolean(true)];
  for (const response of responses) {
    let invocations = 0;
    const runner = createGuardedToolRunner([
      {
        name: "delete_record",
        risk: "destructive",
        params: [{ name: "id", authority: "trusted_fixed", type: "string" }],
        handler: () => {
          invocations += 1;
          return null;
        },
      },
    ]);
    const result = await runner.run(
      { name: "delete_record", input: { id: "42" } },
      { trustedArgs: { id: "42" }, confirm: async () => response },
    );
    assert.equal(result.decision.code, "confirmation_denied");
    assert.equal(result.invoked, false);
    assert.equal(invocations, 0);
  }

  let approvedInvocations = 0;
  const approvedRunner = createGuardedToolRunner([
    {
      name: "delete_record",
      risk: "destructive",
      params: [{ name: "id", authority: "trusted_fixed", type: "string" }],
      handler: () => {
        approvedInvocations += 1;
        return null;
      },
    },
  ]);
  const approved = await approvedRunner.run(
    { name: "delete_record", input: { id: "42" } },
    { trustedArgs: { id: "42" }, confirm: async () => true },
  );
  assert.equal(approved.resultValidated, true);
  assert.equal(approved.decision.needsConfirmation, true);
  assert.equal(approvedInvocations, 1);
});

test("confirmation does not assimilate generic thenables or Promise proxies", async () => {
  let getterReads = 0;
  let proxyTraps = 0;
  let invocations = 0;
  const runner = createGuardedToolRunner([
    {
      name: "delete_record",
      risk: "destructive",
      params: [],
      handler: () => {
        invocations += 1;
        return null;
      },
    },
  ]);
  const thenable = {};
  Object.defineProperty(thenable, "then", {
    get() {
      getterReads += 1;
      return (resolve) => resolve(true);
    },
  });
  const promiseProxy = new Proxy(Promise.resolve(true), {
    get(target, key, receiver) {
      proxyTraps += 1;
      return Reflect.get(target, key, receiver);
    },
  });

  const thenableResult = await runner.run(
    { name: "delete_record", input: {} },
    { confirm: () => thenable },
  );
  const proxyResult = await runner.run(
    { name: "delete_record", input: {} },
    { confirm: () => promiseProxy },
  );
  assert.equal(thenableResult.decision.code, "confirmation_denied");
  assert.equal(proxyResult.decision.code, "confirmation_denied");
  assert.equal(getterReads, 0);
  assert.equal(proxyTraps, 0);
  assert.equal(invocations, 0);
});

test("requiresConfirmation elevates even a read-only registration", async () => {
  let invocations = 0;
  let confirmationReceiver = "not-called";
  const runner = createGuardedToolRunner([
    {
      name: "read_secret_name",
      risk: "read_only",
      requiresConfirmation: true,
      params: [],
      handler: () => {
        invocations += 1;
        return { name: "redacted" };
      },
    },
  ]);

  const missing = await runner.run({ name: "read_secret_name", input: {} });
  const approved = await runner.run(
    { name: "read_secret_name", input: {} },
    {
      confirm: function () {
        confirmationReceiver = this;
        return true;
      },
    },
  );

  assert.equal(missing.decision.code, "confirmation_required");
  assert.equal(missing.invoked, false);
  assert.equal(approved.decision.needsConfirmation, true);
  assert.equal(approved.resultValidated, true);
  assert.equal(confirmationReceiver, undefined);
  assert.equal(invocations, 1);
});

test("missing or failing confirmation never invokes the tool", async () => {
  let invocations = 0;
  const runner = createGuardedToolRunner([
    {
      name: "delete_record",
      risk: "destructive",
      params: [{ name: "id", authority: "trusted_fixed", type: "string" }],
      handler: () => {
        invocations += 1;
        return null;
      },
    },
  ]);
  const call = { name: "delete_record", input: { id: "42" } };
  const trustedArgs = { id: "42" };
  const missing = await runner.run(call, { trustedArgs });
  const thrown = await runner.run(call, {
    trustedArgs,
    confirm: () => {
      throw new Error("secret confirmation failure");
    },
  });
  const rejected = await runner.run(call, {
    trustedArgs,
    confirm: async () => Promise.reject(new Error("secret rejection")),
  });
  assert.equal(missing.decision.code, "confirmation_required");
  assert.equal(thrown.decision.code, "confirmation_error");
  assert.equal(rejected.decision.code, "confirmation_error");
  assert.equal(thrown.contractViolation, "confirmation_exception");
  assert.equal(thrown.decision.reason.includes("secret"), false);
  assert.equal(invocations, 0);
});

test("confirmation is bound to the private snapshot and displayed request is frozen", async () => {
  let received;
  let captured;
  const runner = createGuardedToolRunner([
    {
      name: "transfer",
      risk: "financial",
      params: [
        { name: "destination", authority: "trusted_fixed", type: "string" },
        { name: "amount", authority: "typed_bounded", type: "number", maximum: 100 },
      ],
      handler: (input) => {
        received = input;
        return { ok: true };
      },
    },
  ]);
  const call = {
    name: "transfer",
    input: { destination: "acct-approved", amount: 10 },
  };
  const trustedArgs = { destination: "acct-approved" };
  const result = await runner.run(call, {
    trustedArgs,
    confirm: async (request) => {
      captured = request;
      call.input.destination = "acct-attacker";
      call.input.amount = 99;
      trustedArgs.destination = "acct-attacker";
      assert.equal(Object.isFrozen(request), true);
      assert.throws(() => {
        request.confirmationId = "forged";
      }, TypeError);
      return true;
    },
  });
  assert.equal(result.resultValidated, true);
  assert.deepEqual({ ...received }, { destination: "acct-approved", amount: 10 });
  assert.match(captured.confirmationId, /^[0-9a-f]{64}$/u);
  assert.match(captured.actionDigest, /^[0-9a-f]{64}$/u);
  assert.equal(captured.argumentsJson, '{"destination":"acct-approved","amount":10}');
});

test("registration mutation during awaited confirmation cannot swap policy or handler", async () => {
  let originalInvocations = 0;
  let replacementInvocations = 0;
  const registration = {
    name: "delete_record",
    risk: "destructive",
    params: [{ name: "id", authority: "trusted_fixed", type: "string" }],
    handler: () => {
      originalInvocations += 1;
      return null;
    },
  };
  const runner = createGuardedToolRunner([registration]);
  const result = await runner.run(
    { name: "delete_record", input: { id: "42" } },
    {
      trustedArgs: { id: "42" },
      confirm: async () => {
        await Promise.resolve();
        registration.risk = "read_only";
        registration.params[0].authority = "outbound_payload";
        registration.handler = () => {
          replacementInvocations += 1;
          return null;
        };
        return true;
      },
    },
  );
  assert.equal(result.resultValidated, true);
  assert.equal(originalInvocations, 1);
  assert.equal(replacementInvocations, 0);
});

test("different exact arguments receive different action digests including signed zero and order", async () => {
  const runner = createGuardedToolRunner([
    {
      name: "inspect",
      risk: "code_exec",
      params: [{ name: "value", authority: "outbound_payload", type: "json" }],
      handler: () => null,
    },
  ]);
  const requests = [];
  const capture = async (value) => {
    await runner.run(
      { name: "inspect", input: { value } },
      {
        confirm: (request) => {
          requests.push(request);
          return false;
        },
      },
    );
  };
  await capture(0);
  await capture(-0);
  await capture({ first: 1, second: 2 });
  await capture({ second: 2, first: 1 });
  assert.equal(new Set(requests.map((request) => request.actionDigest)).size, 4);
  assert.equal(new Set(requests.map((request) => request.confirmationId)).size, 4);
  assert.equal(requests[1].argumentsJson, '{"value":-0}');
});

test("identical concurrent attempts have unique confirmation IDs and one shared digest", async () => {
  let invocations = 0;
  const requests = [];
  const runner = createGuardedToolRunner([
    {
      name: "charge",
      risk: "financial",
      params: [
        { name: "account", authority: "trusted_fixed", type: "string" },
        {
          name: "amount",
          authority: "typed_bounded",
          type: "integer",
          minimum: 0,
          maximum: 100,
        },
      ],
      handler: async () => {
        invocations += 1;
        await Promise.resolve();
        return { ok: true };
      },
    },
  ]);
  const run = () => runner.run(
    { name: "charge", input: { account: "acct", amount: 10 } },
    {
      trustedArgs: { account: "acct" },
      confirm: async (request) => {
        requests.push(request);
        await Promise.resolve();
        return true;
      },
    },
  );

  const results = await Promise.all([run(), run()]);

  assert.equal(results.every((result) => result.resultValidated), true);
  assert.equal(invocations, 2);
  assert.equal(new Set(requests.map(({ confirmationId }) => confirmationId)).size, 2);
  assert.equal(new Set(requests.map(({ actionDigest }) => actionDigest)).size, 1);
});

test("confirmation JSON ASCII-escapes bidi, markup, BMP, and astral text", async () => {
  let request;
  const runner = createGuardedToolRunner([
    {
      name: "review",
      risk: "unknown",
      params: [{ name: "text", authority: "outbound_payload", type: "string" }],
      handler: () => null,
    },
  ]);
  await runner.run(
    { name: "review", input: { text: "<tag>\nאב😀\u202e" } },
    {
      confirm: (value) => {
        request = value;
        return false;
      },
    },
  );
  assert.equal(/[<>\u0080-\uffff]/u.test(request.argumentsJson), false);
  assert.match(request.argumentsJson, /\\u003c/u);
  assert.match(request.argumentsJson, /\\u202e/u);
  assert.match(request.argumentsJson, /\\ud83d\\ude00/u);
  assert.match(request.argumentsJson, /\\n/u);
});

test("confirmation serialization stays within the conservative material budget", async () => {
  let request;
  const runner = createGuardedToolRunner([
    {
      name: "review",
      risk: "unknown",
      params: [
        {
          name: "text",
          authority: "outbound_payload",
          type: "string",
          maxLength: 1_300_000,
        },
      ],
      handler: () => null,
    },
  ]);
  const result = await runner.run(
    { name: "review", input: { text: "x".repeat(1_300_000) } },
    {
      confirm: (value) => {
        request = value;
        return false;
      },
    },
  );
  assert.equal(result.decision.code, "confirmation_denied");
  assert.ok(Buffer.byteLength(request.argumentsJson, "utf8") <= 8 * 1024 * 1024);
});

test("handler failure and unsupported result report invoked once and never expose secrets", async () => {
  let throws = 0;
  const throwing = createGuardedToolRunner([
    {
      name: "write_once",
      risk: "write",
      params: [],
      handler: async () => {
        throws += 1;
        throw new Error("database-password-secret");
      },
    },
  ]);
  const failed = await throwing.run({ name: "write_once", input: {} });
  assert.equal(failed.invoked, true);
  assert.equal(failed.decision.code, "allowed");
  assert.equal(failed.handlerCompleted, false);
  assert.equal(failed.resultValidated, false);
  assert.equal(failed.contractViolation, "invocation_exception");
  assert.equal(failed.decision.reason.includes("database-password"), false);
  assert.equal(throws, 1);

  let unsupportedCalls = 0;
  const unsupported = createGuardedToolRunner([
    {
      name: "write_once",
      risk: "write",
      params: [],
      handler: () => {
        unsupportedCalls += 1;
        return new Map();
      },
    },
  ]);
  const invalid = await unsupported.run({ name: "write_once", input: {} });
  assert.equal(invalid.invoked, true);
  assert.equal(invalid.decision.code, "allowed");
  assert.equal(invalid.handlerCompleted, true);
  assert.equal(invalid.resultValidated, false);
  assert.equal(invalid.contractViolation, "unsupported_result");
  assert.equal(unsupportedCalls, 1);

  let getterReads = 0;
  const getterResult = {};
  Object.defineProperty(getterResult, "then", {
    enumerable: true,
    get() {
      getterReads += 1;
      return () => {};
    },
  });
  const getterRunner = createGuardedToolRunner([
    {
      name: "write_once",
      risk: "write",
      params: [],
      handler: () => getterResult,
    },
  ]);
  const invalidGetter = await getterRunner.run({ name: "write_once", input: {} });
  assert.equal(invalidGetter.invoked, true);
  assert.equal(invalidGetter.handlerCompleted, true);
  assert.equal(invalidGetter.resultValidated, false);
  assert.equal(invalidGetter.contractViolation, "unsupported_result");
  assert.equal(getterReads, 0);

  let proxyTraps = 0;
  const resultProxy = new Proxy({}, {
    get() {
      proxyTraps += 1;
      return undefined;
    },
    getPrototypeOf() {
      proxyTraps += 1;
      return Object.prototype;
    },
  });
  const proxyRunner = createGuardedToolRunner([
    {
      name: "write_once",
      risk: "write",
      params: [],
      handler: () => resultProxy,
    },
  ]);
  const invalidProxy = await proxyRunner.run({ name: "write_once", input: {} });
  assert.equal(invalidProxy.invoked, true);
  assert.equal(invalidProxy.handlerCompleted, true);
  assert.equal(invalidProxy.resultValidated, false);
  assert.equal(invalidProxy.contractViolation, "unsupported_result");
  assert.equal(proxyTraps, 0);

  const nativePromise = Promise.resolve({ ok: true });
  const promiseProxy = new Proxy(nativePromise, {
    get(target, key, receiver) {
      proxyTraps += 1;
      return Reflect.get(target, key, receiver);
    },
  });
  const promiseProxyRunner = createGuardedToolRunner([
    {
      name: "write_once",
      risk: "write",
      params: [],
      handler: () => promiseProxy,
    },
  ]);
  const invalidPromiseProxy = await promiseProxyRunner.run({
    name: "write_once",
    input: {},
  });
  assert.equal(invalidPromiseProxy.invoked, true);
  assert.equal(invalidPromiseProxy.handlerCompleted, true);
  assert.equal(invalidPromiseProxy.resultValidated, false);
  assert.equal(invalidPromiseProxy.contractViolation, "unsupported_result");
  assert.equal(proxyTraps, 0);
});

test("genuine Promise subclasses settle without consulting overridden then", async () => {
  let thenReads = 0;
  class HostilePromise extends Promise {}
  Object.defineProperty(HostilePromise.prototype, "then", {
    configurable: true,
    get() {
      thenReads += 1;
      return Promise.prototype.then;
    },
  });
  const subclassRunner = createGuardedToolRunner([
    {
      name: "write_once",
      risk: "write",
      params: [],
      handler: () => new HostilePromise((resolve) => resolve({ ok: true })),
    },
  ]);
  const subclassResult = await subclassRunner.run({
    name: "write_once",
    input: {},
  });

  let ownThenReads = 0;
  const decorated = Promise.resolve({ ok: true });
  Object.defineProperty(decorated, "then", {
    configurable: true,
    get() {
      ownThenReads += 1;
      return Promise.prototype.then;
    },
  });
  const decoratedRunner = createGuardedToolRunner([
    {
      name: "write_once",
      risk: "write",
      params: [],
      handler: () => decorated,
    },
  ]);
  const decoratedResult = await decoratedRunner.run({
    name: "write_once",
    input: {},
  });

  let constructorReads = 0;
  const constructorDecorated = Promise.resolve({ ok: true });
  Object.defineProperty(constructorDecorated, "constructor", {
    configurable: true,
    get() {
      constructorReads += 1;
      throw new Error("constructor must not be read");
    },
  });
  const constructorRunner = createGuardedToolRunner([
    {
      name: "write_once",
      risk: "write",
      params: [],
      handler: () => constructorDecorated,
    },
  ]);
  const constructorResult = await constructorRunner.run({
    name: "write_once",
    input: {},
  });

  for (const result of [subclassResult, decoratedResult, constructorResult]) {
    assert.equal(result.decision.code, "allowed");
    assert.equal(result.invoked, true);
    assert.equal(result.handlerCompleted, true);
    assert.equal(result.resultValidated, true);
    assert.deepEqual({ ...result.result }, { ok: true });
  }
  assert.equal(thenReads, 0);
  assert.equal(ownThenReads, 0);
  assert.equal(constructorReads, 0);
});

test("rejected Promise subclasses are observed and reported without retry", async () => {
  let invocations = 0;
  class RejectedPromise extends Promise {}
  const runner = createGuardedToolRunner([
    {
      name: "write_once",
      risk: "write",
      params: [],
      handler: () => {
        invocations += 1;
        return new RejectedPromise((_resolve, reject) => {
          reject(new Error("sentinel"));
        });
      },
    },
  ]);

  const result = await runner.run({ name: "write_once", input: {} });
  assert.equal(result.decision.code, "allowed");
  assert.equal(result.invoked, true);
  assert.equal(result.handlerCompleted, false);
  assert.equal(result.resultValidated, false);
  assert.equal(result.contractViolation, "invocation_exception");
  assert.equal(invocations, 1);
  await new Promise((resolve) => setImmediate(resolve));
});

test("settled payloads are never re-assimilated through a later then getter", async () => {
  let thenReads = 0;
  const payload = { ok: true };
  const settled = Promise.resolve(payload);
  Object.defineProperty(payload, "then", {
    enumerable: true,
    get() {
      thenReads += 1;
      return () => {};
    },
  });
  const runner = createGuardedToolRunner([
    {
      name: "read_once",
      risk: "read_only",
      params: [],
      handler: () => settled,
    },
  ]);

  const result = await runner.run({ name: "read_once", input: {} });
  assert.equal(result.decision.code, "allowed");
  assert.equal(result.invoked, true);
  assert.equal(result.handlerCompleted, true);
  assert.equal(result.resultValidated, false);
  assert.equal(result.contractViolation, "unsupported_result");
  assert.equal(thenReads, 0);
});

test("prototype-reset and cross-realm branded Promises are observed first", async () => {
  const rejected = Promise.reject(new Error("sentinel"));
  Object.setPrototypeOf(rejected, Object.prototype);
  const rejectedRunner = createGuardedToolRunner([
    {
      name: "write_once",
      risk: "write",
      params: [],
      handler: () => rejected,
    },
  ]);
  const rejectedResult = await rejectedRunner.run({
    name: "write_once",
    input: {},
  });
  assert.equal(rejectedResult.invoked, true);
  assert.equal(rejectedResult.handlerCompleted, false);
  assert.equal(rejectedResult.resultValidated, false);
  assert.equal(rejectedResult.contractViolation, "invocation_exception");

  const crossRealm = runInNewContext("Promise.resolve(7)");
  const crossRealmRunner = createGuardedToolRunner([
    {
      name: "read_once",
      risk: "read_only",
      params: [],
      handler: () => crossRealm,
    },
  ]);
  const crossRealmResult = await crossRealmRunner.run({
    name: "read_once",
    input: {},
  });
  assert.equal(crossRealmResult.handlerCompleted, true);
  assert.equal(crossRealmResult.resultValidated, true);
  assert.equal(crossRealmResult.result, 7);
  await new Promise((resolve) => setImmediate(resolve));
});

test("rejected decorated confirmation is contained before invocation", async () => {
  let constructorReads = 0;
  let invocations = 0;
  const runner = createGuardedToolRunner([
    {
      name: "delete_once",
      risk: "destructive",
      params: [],
      handler: () => {
        invocations += 1;
        return { ok: true };
      },
    },
  ]);
  const result = await runner.run(
    { name: "delete_once", input: {} },
    {
      confirm: () => {
        const rejected = Promise.reject(new Error("sentinel"));
        Object.defineProperty(rejected, "constructor", {
          configurable: true,
          get() {
            constructorReads += 1;
            throw new Error("constructor must not be read");
          },
        });
        return rejected;
      },
    },
  );

  assert.equal(result.decision.code, "confirmation_error");
  assert.equal(result.invoked, false);
  assert.equal(result.contractViolation, "confirmation_exception");
  assert.equal(invocations, 0);
  assert.equal(constructorReads, 0);
  await new Promise((resolve) => setImmediate(resolve));
});

test("strict unhandled-rejection mode survives rejected handler and confirmation Promises", () => {
  const moduleUrl = new URL("../dist/index.js", import.meta.url).href;
  const source = `
    import { createGuardedToolRunner } from ${JSON.stringify(moduleUrl)};
    class RejectedPromise extends Promise {}
    let invocations = 0;
    const handlerRunner = createGuardedToolRunner([{
      name: "write_once",
      risk: "write",
      params: [],
      handler: () => new RejectedPromise((_resolve, reject) => reject(new Error("handler"))),
    }]);
    const handlerResult = await handlerRunner.run({ name: "write_once", input: {} });
    if (handlerResult.contractViolation !== "invocation_exception") process.exit(11);

    const confirmationRunner = createGuardedToolRunner([{
      name: "delete_once",
      risk: "destructive",
      params: [],
      handler: () => { invocations += 1; return { ok: true }; },
    }]);
    const confirmationResult = await confirmationRunner.run(
      { name: "delete_once", input: {} },
      { confirm: () => Promise.reject(new Error("confirmation")) },
    );
    if (confirmationResult.decision.code !== "confirmation_error") process.exit(12);
    if (invocations !== 0) process.exit(13);
    await new Promise((resolve) => setImmediate(resolve));
  `;
  const child = spawnSync(
    process.execPath,
    ["--unhandled-rejections=strict", "--input-type=module", "--eval", source],
    { encoding: "utf8", timeout: 5000 },
  );
  assert.ifError(child.error);
  assert.equal(child.status, 0, child.stderr || child.stdout);
});

test("successful results are detached and deeply frozen", async () => {
  const original = { nested: [1, 2] };
  const runner = createGuardedToolRunner([
    {
      name: "read",
      risk: "read_only",
      params: [],
      handler: () => original,
    },
  ]);
  const result = await runner.run({ name: "read", input: {} });
  original.nested.push(3);
  assert.deepEqual({ ...result.result }, { nested: [1, 2] });
  assert.equal(Object.isFrozen(result.result), true);
  assert.equal(Object.isFrozen(result.result.nested), true);
});

test("parallel approvals keep action snapshots independent", async () => {
  const seen = [];
  const runner = createGuardedToolRunner([
    {
      name: "charge",
      risk: "financial",
      params: [
        { name: "account", authority: "trusted_fixed", type: "string" },
        { name: "amount", authority: "typed_bounded", type: "integer", maximum: 100 },
      ],
      handler: async (input) => {
        await new Promise((resolve) => setTimeout(resolve, input.amount === 1 ? 10 : 0));
        seen.push({ ...input });
        return { ok: true };
      },
    },
  ]);
  const confirmationIds = [];
  const actionDigests = [];
  const run = (amount) => runner.run(
    { name: "charge", input: { account: "acct", amount } },
    {
      trustedArgs: { account: "acct" },
      confirm: async (request) => {
        confirmationIds.push(request.confirmationId);
        actionDigests.push(request.actionDigest);
        await new Promise((resolve) => setTimeout(resolve, amount === 1 ? 0 : 10));
        return true;
      },
    },
  );
  const results = await Promise.all([run(1), run(2)]);
  assert.equal(results.every((result) => result.resultValidated), true);
  assert.equal(new Set(confirmationIds).size, 2);
  assert.equal(new Set(actionDigests).size, 2);
  assert.deepEqual(
    seen.map((value) => value.amount).sort(),
    [1, 2],
  );
});

test("registration rejects malformed constraints, duplicate names, and duplicate enum values", () => {
  assert.throws(
    () => createGuardedToolRunner([
      {
        name: "bad",
        risk: "write",
        params: [{ name: "value", authority: "outbound_payload", type: "number", maxLength: 2 }],
        handler: () => null,
      },
    ]),
    /maxLength/u,
  );
  assert.throws(
    () => createGuardedToolRunner([
      {
        name: "bad",
        risk: "write",
        params: [
          { name: "value", authority: "outbound_payload", type: "string" },
          { name: "value", authority: "outbound_payload", type: "string" },
        ],
        handler: () => null,
      },
    ]),
    /duplicate param/u,
  );
  assert.throws(
    () => createGuardedToolRunner([
      {
        name: "bad",
        risk: "write",
        params: [
          { name: "value", authority: "typed_bounded", type: "integer", enum: [1, 1] },
        ],
        handler: () => null,
      },
    ]),
    /duplicate exact values/u,
  );
  for (const name of ["__proto__", "constructor", "prototype"]) {
    assert.throws(
      () => createGuardedToolRunner([
        {
          name: "bad",
          risk: "write",
          params: [{ name, authority: "outbound_payload", type: "json" }],
          handler: () => null,
        },
      ]),
      /prototype-sensitive/u,
    );
  }
  for (const param of [
    { name: "value", authority: "typed_bounded", type: "json" },
    { name: "value", authority: "typed_bounded", type: "string" },
    { name: "value", authority: "typed_bounded", type: "number" },
  ]) {
    assert.throws(
      () => createGuardedToolRunner([
        {
          name: "bad",
          risk: "write",
          params: [param],
          handler: () => null,
        },
      ]),
      /typed_bounded requires/u,
    );
  }
  assert.doesNotThrow(() => createGuardedToolRunner([
    {
      name: "bounded_boolean",
      risk: "read_only",
      params: [{ name: "value", authority: "typed_bounded", type: "boolean" }],
      handler: () => null,
    },
  ]));
  assert.throws(
    () => createGuardedToolRunner(new Array(257).fill({
      name: "tool",
      risk: "write",
      params: [],
      handler: () => null,
    })),
    /too many items/u,
  );
  assert.throws(
    () => createGuardedToolRunner([
      {
        name: "too_many_params",
        risk: "write",
        params: new Array(257).fill({
          name: "value",
          authority: "outbound_payload",
          type: "string",
        }),
        handler: () => null,
      },
    ]),
    /too many items/u,
  );
});
