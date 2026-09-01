import { createGuardedToolRunner } from "./index.js";

const invocations: Array<{ to: string; body: string }> = [];

const runner = createGuardedToolRunner([
  {
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
    handler: ({ to, body }) => {
      if (typeof to !== "string" || typeof body !== "string") {
        throw new Error("runtime registration regression");
      }
      invocations.push({ to, body });
      return { status: "recorded-locally" };
    },
  },
]);

const applicationRecipient = "alice@company.com";
const blocked = await runner.run(
  {
    name: "send_email",
    input: { to: "attacker@evil.com", body: "Meeting summary" },
  },
  { trustedArgs: { to: applicationRecipient } },
);
const blockedInvocations = invocations.length;

const overlong = await runner.run(
  {
    name: "send_email",
    input: { to: applicationRecipient, body: "x".repeat(2001) },
  },
  { trustedArgs: { to: applicationRecipient } },
);
const overlongInvocations = invocations.length;

const allowed = await runner.run(
  {
    name: "send_email",
    input: { to: applicationRecipient, body: "Meeting summary" },
  },
  { trustedArgs: { to: applicationRecipient } },
);

if (
  blocked.decision.allow ||
  blocked.invoked ||
  blockedInvocations !== 0 ||
  overlong.decision.allow ||
  overlong.invoked ||
  overlongInvocations !== 0 ||
  !allowed.decision.allow ||
  !allowed.invoked ||
  !allowed.handlerCompleted ||
  !allowed.resultValidated ||
  invocations.length !== 1
) {
  throw new Error("Node quickstart contract failed");
}

console.log("Verb Authority Node prototype: TRUSTED REGISTRATION -> RUNTIME GATE");
console.log("Offline demo: no model, network, or email is used.\n");
console.log("1) UNTRUSTED CONTENT PROPOSES THE RECIPIENT");
console.log(`   ${blocked.decision.code}: ${blocked.decision.reason}`);
console.log(`   local tool invocations=${blockedInvocations}`);
console.log("\n2) REGISTERED maxLength IS ENFORCED");
console.log(`   ${overlong.decision.code}: ${overlong.decision.reason}`);
console.log(`   local tool invocations=${overlongInvocations}`);
console.log("\n3) APPLICATION-SUPPLIED TRUSTED RECIPIENT");
console.log(`   ${allowed.decision.code}: ${allowed.decision.reason}`);
console.log(`   local tool invocations=${invocations.length}`);
console.log("\nThis source-only prototype uses explicit trusted registration; it does not infer policy from schemas.");
