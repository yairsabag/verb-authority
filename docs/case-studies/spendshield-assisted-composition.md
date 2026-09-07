# Assisted external composition: Verb Authority and SpendShield

This is **assisted external composition evidence**. It is not a customer
testimonial, self-service adoption, independent certification, or a production
deployment.

The SpendShield maintainer wrote and published the integration harness. The
Verb Authority maintainer proposed adversarial cases, reviewed intermediate
artifacts, found missing checks, and independently reran the final pinned code.
That collaboration is useful engineering evidence, but it must not be described
as an unassisted third-party evaluation.

## Status and immutable pins

The final local reproduction used these exact revisions:

| Component | Revision | Role |
|---|---|---|
| Verb Authority | [`5ef6e11091208070daaac88735cec741a3abce22`](https://github.com/yairsabag/verb-authority/commit/5ef6e11091208070daaac88735cec741a3abce22) | Pre-dispatch argument gate |
| SpendShield | [`31e584bbcb070fc05fe0994304dcda97e4e50c6c`](https://github.com/felixpg13-glitch/spendshield/commit/31e584bbcb070fc05fe0994304dcda97e4e50c6c) | Policy decision, signed grant, verification, and in-memory used-token recording |
| SpendShield status follow-up | [`2c20526c16c85ebc99a1db859f6963d859d04fb2`](https://github.com/felixpg13-glitch/spendshield/commit/2c20526c16c85ebc99a1db859f6963d859d04fb2) | Documentation-only status update |

The executable evidence is the pinned
[`va_e2e_authorize_payment.py`](https://github.com/felixpg13-glitch/spendshield/blob/31e584bbcb070fc05fe0994304dcda97e4e50c6c/composition/va_e2e_authorize_payment.py)
harness, its dedicated
[`policy.va_e2e.yaml`](https://github.com/felixpg13-glitch/spendshield/blob/31e584bbcb070fc05fe0994304dcda97e4e50c6c/composition/policy.va_e2e.yaml),
and the committed
[`va_e2e_results.txt`](https://github.com/felixpg13-glitch/spendshield/blob/31e584bbcb070fc05fe0994304dcda97e4e50c6c/composition/va_e2e_results.txt).

The final SpendShield composition README still names an earlier host revision
and says external confirmation is pending. The executable revision and results
above, not that stale status text, are the basis of this report.

## Composition boundary

The harness adapts this public SpendShield tool shape:

```text
authorize_payment(recipient, amount, purpose, agent_id)
```

SpendShield publicly exposes these four named fields, but the harness does not
import its `tools/list` schema byte for byte. The public schema requires only
`recipient` and `amount`; this local Verb Authority registration materializes
all four fields and adds explicit authority declarations. It is a purpose-built
composition fixture around a real public tool shape, not a captured production
schema or direct MCP-server dispatch.

The harness declares `recipient`, `amount`, and `agent_id` as `trusted_fixed`
and leaves `purpose` model-writable. The registration is written explicitly in
trusted host code; the harness does not automatically turn scanner output into
runtime policy.

The exercised path is:

```text
model-shaped call + host-owned trusted_args
                    |
                    v
Verb Authority GuardedToolRunner
  mismatch or missing trusted binding -> stop before handler
                    |
                    v
SpendShield authorize()
  policy ALLOW -> issue source-labelled HMAC grant
                    |
                    v
SpendShield Executor.verify()
  verify the exact values and declared source labels
  record the grant in an in-memory used-token set
```

The last step verifies the grant and records its digest in the executor's
in-memory used-token set. The harness does not attempt a second use, and it
does not make a payment-rail call.

## Seven composition cases

The clean reproduction produced the same stdout, byte for byte, as the pinned
results file and exited successfully.

| Case | Expected handler entries | Observed | Result |
|---|---:|---:|---|
| Host binds recipient, amount, and `agent_id`; model-channel payload varies purpose | 1 | 1 | pass |
| Model changes the trusted-fixed amount | 0 | 0 | pass |
| Model changes the trusted-fixed recipient | 0 | 0 | pass |
| Protected values arrive without independent `trusted_args` | 0 | 0 | pass |
| Payload adds unknown source-shaped tool arguments, rejected by Verb Authority before SpendShield | 0 | 0 | pass |
| Writable purpose contains source-looking spoof text | 1 | 1; host binding unchanged | pass |
| Only the writable purpose changes | 1 | 1 | pass |

For allow cases, the harness also requires Verb Authority `allow=True`, actual
handler execution, SpendShield `ALLOW`, grant issuance, source-bound grant
verification, in-memory used-token recording, and an independent handler-entry
counter. For deny cases, it requires `allow=False`, `res.invoked=False`, and
zero independent handler entries.

The deny cases do not currently assert the exact Verb Authority reason code.
They therefore establish fail-closed non-invocation, not a frozen diagnostic
contract.

## Source-binding probes

The pinned harness contains two negative probes and one positive control. All
three use a verifier-provided complete expected map over `merchant`, `amount`,
and `agent`:

| Probe | Result |
|---|---|
| `agent` label omitted while the verifier requires it | rejected as `SOURCE_MISSING:agent` |
| `amount` label differs from the verifier's expected value | rejected as `SOURCE_MISMATCH:amount` |
| Complete matching source map | accepted as `AUTHORIZED` |

The commit message calls these “3 negative probes,” but the third is a positive
control. This report uses the measured distinction.

Supplemental probes were also run in the Verb Authority maintainer's local
review environment, outside the SpendShield repository:

| Supplemental probe | Result |
|---|---|
| `merchant` source omitted at issuance while the verifier supplies the complete expected map | rejected as `SOURCE_MISSING:merchant` |
| `merchant` source changed to `agent_controlled` | rejected as `SOURCE_MISMATCH:merchant` |
| Executor omits a merchant source required by the grant | rejected as `SOURCE_MISSING:merchant` |
| Complete matching merchant map | accepted as `AUTHORIZED` |

Those merchant results exercise the final verifier directly. They are not part
of the pinned upstream harness, so they are supporting review evidence rather
than a frozen contributed regression.

## Review-driven correction

The first published composition result was not accepted at face value. Public
review found that the committed output captured a failed run, source keys did
not match SpendShield's canonical fields, and a handler-entry count alone did
not establish the whole intended path. The next revision corrected those
issues and added the seven full-chain assertions.

The subsequent review found another load-bearing gap: if the verifier caller
provided an expected source map but the signed grant omitted a corresponding
source label, the old verifier checked only labels that happened to be present
in the grant. A missing label could therefore escape comparison.

SpendShield commit
[`31e584bb`](https://github.com/felixpg13-glitch/spendshield/commit/31e584bbcb070fc05fe0994304dcda97e4e50c6c)
added the reverse fail-closed check and two committed regression tests. The
clean final reproduction ran 261 SpendShield tests, all seven composition
cases, and all three built-in source probes successfully.

The review trail is public:

- [initial pinned artifacts](https://github.com/yairsabag/verb-authority/issues/7#issuecomment-5524714232);
- [experiment boundary](https://github.com/yairsabag/verb-authority/issues/7#issuecomment-5525744152);
- [first reproduction findings](https://github.com/yairsabag/verb-authority/issues/7#issuecomment-5526193964);
- [corrected seven-case result](https://github.com/yairsabag/verb-authority/issues/7#issuecomment-5526238869); and
- [final review requirements](https://github.com/yairsabag/verb-authority/issues/7#issuecomment-5526680620).

At the time of the 2026-09-04 reproduction, the SpendShield maintainer had not
posted a later Issue #7 reply reconfirming the final `31e584bb` revision. The
clean final rerun described here was performed in the Verb Authority
maintainer's local review environment.

## What this establishes

At the pinned revisions, the experiment establishes that:

- a host-owned `trusted_args` binding can stop protected-value changes before
  the SpendShield handler runs;
- model-writable purpose text can vary without gaining authority over the
  protected recipient, amount, or agent identifier;
- an allowed call can proceed through a real SpendShield policy decision into
  signed-grant verification and in-process used-token recording;
- source-looking claims inside a writable string do not change the host-owned
  binding; and
- review by the Verb Authority maintainer of the cross-project boundary found
  and prompted a concrete fail-closed correction in SpendShield's public
  repository.

That last point is product learning as well as code evidence: a small,
argument-level mutation suite can expose a composition error that happy-path
integration does not reveal.

## What this does not establish

The result does **not** establish:

- organic or self-service adoption, customer demand, retention, or willingness
  to pay;
- independent certification of either project;
- production safety or execution against a real payment rail;
- a real model, network request, or human approval—the harness uses
  `confirm=lambda _: True`;
- automatic scanner-to-policy wiring—the authority map is registered manually;
- a mechanical provenance handoff between the two libraries—the Verb Authority
  runner passes ordinary argument values to the trusted handler, and that
  handler explicitly supplies the source labels used in the SpendShield grant;
- truthful origin by itself—SpendShield signs and compares declared labels,
  while the host is still responsible for constructing `trusted_args` outside
  the model-controlled envelope;
- mandatory or validated source coverage—source binding is opt-in. A matching
  partial map over recognized keys authorizes; unknown or misspelled keys are
  silently ignored at issuance and verification; and an omitted grant label
  fails only when the verifier supplies that recognized key in its expected
  `sources` map. Stronger claims require strict exact-key and full-coverage
  enforcement;
- durable cross-process replay prevention—the used-token set is in memory; or
- a canonical merchant-identity model. Case, Unicode/IDNA, URL components,
  subdomains, trailing dots, and public suffixes remain outside this test.

The current composition also lacks a case where Verb Authority allows the
handler but SpendShield denies the business policy, a mutation of `agent_id`,
an asserted confirmation boundary, and a fake execution callback proving
exactly one downstream effect after verification. It also does not attempt a
second verification of the same grant to assert replay rejection. Those are
the next useful tests for this particular integration; they are not new Verb
Authority product promises.

## Reproduce

Clone both repositories and detach them at the exact revisions shown above.
From a fresh Python 3.11 environment with SpendShield's dependencies installed,
run:

```bash
cd spendshield
python -m pytest -q

PYTHONPATH=/absolute/path/to/verb-authority \
  python composition/va_e2e_authorize_payment.py
```

The 2026-09-04 reproduction used Python 3.11.4 and produced:

```text
261 passed
7/7 composition cases passed
2 negative source probes passed
1 positive source control passed
exit status 0
```

Key SHA-256 values from that clean checkout:

| Artifact | SHA-256 |
|---|---|
| Composition harness | `168efd0ea94338885c0a7008c57d485ffae0473a14ca5f38dc559a08f0f05513` |
| Composition policy | `94accaa855cd554462b124f8c5179262d64b83d68d2d13fca17f25744e862e65` |
| Committed results | `e32ab7d25659ee8d70ce001e225fa6d5373ed83a39499d7881ec306a241edc73` |
| SpendShield verifier | `f55c7621384e044cba86e16e29811afb087907207715f9f706ea640507c23308` |
| Verb Authority runtime | `f5a8468094ca1438db342898b76f58401520c097cc0b6e71928836d7969fd0ca` |

The full SpendShield suite requires a temporary loopback webhook server. A
restricted sandbox may deny that bind. No external service is required by the
reproduced test path.

## Attribution and reuse

The harness and SpendShield implementation were published by
[`felixpg13-glitch`](https://github.com/felixpg13-glitch/spendshield) under the
repository's [MIT license](https://github.com/felixpg13-glitch/spendshield/blob/31e584bbcb070fc05fe0994304dcda97e4e50c6c/LICENSE).
Links here record provenance and do not imply endorsement.

The external files are linked at immutable revisions rather than copied into
Verb Authority. No permission to relicense a contributed evidence bundle under
this repository's Apache-2.0 license has been assumed.
