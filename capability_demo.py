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
from verb_authority import Param, Tool, Registry, build_policy, gate

# Two tools, both with a param literally named "path".
reg = Registry()
# read_file: the path is just a location to read -- NOT a sink. Declared safe.
reg.add(Tool("read_file",   [Param("path", "string", sink=False)]))
# delete_file: the path decides what gets destroyed -- a sink. Declared locked.
reg.add(Tool("delete_file", [Param("path", "string", sink=True)]))
ps = build_policy(reg)

print("=== same param name 'path', opposite declared capability ===\n")

# Untrusted data proposes a path for BOTH tools.
data_prov = {"path": "data"}

d = gate(reg, ps, "read_file", {"path": "/etc/notes.txt"}, data_prov)
print(f"  read_file(path=...)   data-filled path: "
      f"{'ALLOWED' if d.allow else 'BLOCKED'} - {d.reason}")

d = gate(reg, ps, "delete_file", {"path": "/etc/passwd"}, data_prov)
print(f"  delete_file(path=...) data-filled path: "
      f"{'ALLOWED' if d.allow else 'BLOCKED'} - {d.reason}")

print("\n=== why this matters ===")
print("  Same name, same type, same provenance -- but read_file lets data")
print("  choose the path while delete_file does not. The difference comes from")
print("  the tool's own declaration, not from guessing sink-ness off the name.")
print("  This is what closes the overloaded-param weakness (query/path/template).")
