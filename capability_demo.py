"""
capability_demo.py -- declared capability beats name-based guessing.

The long-standing weak spot (raised independently by two reviewers): the gate
inferred sink-ness from the PARAM NAME. Overloaded names break that. `path`,
`query`, `template` look innocent, but whether they're dangerous depends on the
TOOL, not the name. A regex can't know.

DylanWang's fix, implemented here: let the tool MANIFEST declare capability.
`Param(..., sink=True/False)` overrides the guess. Same name, opposite policy
in two different tools -- decided by declaration, not by a name-based heuristic.
"""
from verb_authority import Param, Risk, Tool, Registry, build_policy, gate

# Two tools, both with a param literally named "path".
reg = Registry()
# This decision-only example performs no filesystem access. Trusted application
# code supplies a finite catalog of public fixture names; read-only risk alone
# would not make an arbitrary file path safe for model selection.
public_paths = ["public/guide.txt", "public/reference.txt"]
# The application allows the model to choose only within that public catalog.
reg.add(Tool(
    "read_public_fixture",
    [Param("path", "enum", enum=public_paths, sink=False)],
    risk=Risk.READ_ONLY,
))
# delete_file: the path decides what gets destroyed -- a sink. Declared locked.
reg.add(Tool(
    "delete_file", [Param("path", "enum", enum=public_paths, sink=True)],
    risk=Risk.DESTRUCTIVE,
))
ps = build_policy(reg)

print("=== same param name 'path', opposite declared capability ===\n")

# Untrusted data proposes a path for BOTH tools.
data_prov = {"path": "data"}

d = gate(reg, ps, "read_public_fixture", {"path": "public/guide.txt"}, data_prov)
print(f"  read_public_fixture(path=...) data-filled catalog member: "
      f"{'ALLOWED' if d.allow else 'BLOCKED'} - {d.reason}")

d = gate(reg, ps, "delete_file", {"path": "public/guide.txt"}, data_prov)
print(f"  delete_file(path=...) data-filled path: "
      f"{'ALLOWED' if d.allow else 'BLOCKED'} - {d.reason}")

d = gate(reg, ps, "read_public_fixture", {"path": "private/secrets.txt"}, data_prov)
print(f"  read_public_fixture(path=...) outside public catalog: "
      f"{'ALLOWED' if d.allow else 'BLOCKED'} - {d.reason}")

print("\n=== why this matters ===")
print("  Same name, same type, same provenance: the application permits choosing")
print("  a public fixture to read, while retaining authorship of the deletion target.")
print("  The public catalog bound is still enforced for the model-writable path.")
print("  A real file service must also enforce its own resource authorization.")
