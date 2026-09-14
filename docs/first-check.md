# One tool, one authority check

Your agent writes an email draft. Your application chooses the recipient.
Can a model-proposed call replace that recipient?

Start with the small offline demonstration below. Then review one tool you own.
You do not need a model, API key, GPU, or service account. This guide uses the
published `0.10.0b17` core, not the separate SQLite change-checking example.

## 1. Install in a new environment

Use Python 3.10–3.14. From a new, empty working directory, on macOS or Linux:

```sh
python3 -m venv .venv
.venv/bin/python -I -m pip install "verb-authority==0.10.0b17"
.venv/bin/python -I -m verb_authority quickstart
```

On Windows, use a supported Python interpreter and its environment path instead:

```powershell
python -m venv .venv
.venv\Scripts\python.exe -I -m pip install "verb-authority==0.10.0b17"
.venv\Scripts\python.exe -I -m verb_authority quickstart
```

Installation downloads the package. The quickstart itself uses no network or
model and sends no email. If setup fails, keep the first error; do not interpret
an incomplete run as a successful protection test. Release hashes and
package-integrity details are in the [installation reference](https://github.com/yairsabag/verb-authority/blob/main/docs/runtime-gate.md#install).

## 2. Read the three outcomes

| Local call | Expected outcome | Local handler entries |
| --- | --- | --- |
| Recipient differs from the application-owned value | BLOCKED | 0 |
| Body exceeds the registered length limit | BLOCKED | 0 |
| Application-owned recipient, valid body | ALLOWED | 1 |

The third case matters: the check should allow the legitimate operation, not
just stop everything. The demo handler only increments an in-memory counter.
These are deliberately constructed calls, not a live-model attack experiment.

**This proves only the demonstrated boundary works in this setup.** Installing
the package does not protect other tools automatically. Real protection requires
owner-reviewed policy, independently supplied application values, and the gate
on the actual execution path. It cannot correct a handler that uses those values
incorrectly.

## 3. Review one tool you own

Save your client's exported MCP `tools/list` response as `tools.json` in your
working directory. Do not include credentials or customer records. Run:

```sh
.venv/bin/python -I -m verb_authority scan tools.json --output authority-report.md
```

On Windows, replace `.venv/bin/python` with `.venv\Scripts\python.exe`.
The scanner reads the exported JSON locally. It does not start the MCP server,
invoke its tools, upload the schema, or establish whether its server enforces
the rules.

Pick one argument in the report and compare it with your intended rule:

- Who may choose it: the model, the application, or the model within a limit?
- Does the report agree? Its classifications are suggestions for owner review,
  not a vulnerability verdict or automatically installed policy.
- What already enforces that rule in your application?

If your application can remove a protected field from the model-visible schema
and inject it from trusted state, prefer that simple design. If it already does
this correctly, this path may not need another gate. When the canonical schema
must retain the field, see the [runtime integration contract](https://github.com/yairsabag/verb-authority/blob/main/docs/runtime-gate.md#preferred-remediation-remove-protected-arguments-from-model-view).

## One useful result to share

In [the schema clinic](https://github.com/yairsabag/verb-authority/issues/7), share
one small public or redacted example: the argument, your intended rule, the
report's classification, and whether it changed a decision or was already
covered. A setup failure or unnecessary warning is useful evidence too.

Review any report before sharing it; tool and argument names, stable hashes,
and author-supplied evidence may be sensitive. See the [report privacy reference](https://github.com/yairsabag/verb-authority/blob/main/docs/schema-scanner.md).
No full report, private implementation, or customer data is needed.
If you later rerun after a real change, say what changed and whether the result
helped. A passing demo alone is not evidence of production use or time saved.
