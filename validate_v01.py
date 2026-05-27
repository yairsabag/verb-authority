"""
Did v0.1 (confidence + verb-risk) actually improve on the v1 70%?
We re-run the same 11 tools and classify each param's OUTCOME, focusing on the
metric that matters: SILENT unsafe mis-classifications (the dangerous kind).
"""
from verb_authority import Registry, Tool, Param, Policy, build_policy

T, B, O = Policy.TRUSTED_FIXED, Policy.TYPED_BOUNDED, Policy.OUTBOUND_PAYLOAD

# (tool, [(param, type, EXPECTED correct policy)])
SUITE = [
 ("send_email",[("to","email",T),("subject","string",B),("body","string",O)]),
 ("create_calendar_event",[("title","string",B),("start_time","string",B),("attendees","string",T),("location","string",B)]),
 ("make_payment",[("amount","number",B),("currency","enum",B),("recipient_account","string",T),("memo","string",O)]),
 ("search_web",[("query","string",O),("num_results","integer",B)]),
 ("post_slack_message",[("channel","string",T),("text","string",O)]),
 ("execute_sql",[("query","string",T)]),
 ("create_file",[("path","string",T),("content","string",O)]),
 ("http_request",[("url","uri",T),("method","enum",B),("body","string",O),("headers","string",T)]),
 ("book_flight",[("origin","string",B),("destination","string",B),("passenger_name","string",B),("payment_token","string",T)]),
 ("delete_record",[("table","string",T),("record_id","string",B)]),
 ("transfer_funds",[("from_account","string",T),("to_account","string",T),("amount","number",B)]),
]

reg = Registry()
for tool,params in SUITE:
    reg.add(Tool(tool,[Param(n,t) for n,t,_ in params]))
ps = build_policy(reg)
review = set(ps.review)

auto_ok = surfaced = silent_unsafe = silent_cosmetic = 0
silent = []
for tool,params in SUITE:
    for n,t,expected in params:
        got = ps.policy[tool][n]
        if (tool,n) in review:
            surfaced += 1                      # uncertain -> locked + flagged (safe)
        elif got is expected:
            auto_ok += 1                       # auto-decided, correct
        else:
            # auto-decided but != expected. Unsafe only if it UNDER-locks a real sink.
            unsafe = (expected is T and got is not T)
            silent.append((tool,n,got.value,expected.value,"UNSAFE" if unsafe else "cosmetic/safe"))
            if unsafe: silent_unsafe += 1
            else: silent_cosmetic += 1

total = sum(len(p) for _,p in SUITE)
print(f"params: {total}")
print(f"  auto-decided & correct : {auto_ok}")
print(f"  surfaced for review    : {surfaced}  (safe: locked until you confirm)")
print(f"  silent mismatch (safe) : {silent_cosmetic}")
print(f"  SILENT UNSAFE          : {silent_unsafe}   <-- the dangerous kind")
print(f"\ntools forcing human confirm (verb-level danger caught): {ps.confirm}")
print("\nv1 baseline had 9 silent mistakes (several unsafe).")
print(f"v0.1 silent UNSAFE mistakes: {silent_unsafe}")
if silent:
    print("\n(the non-fatal silent mismatches:)")
    for tool,n,g,e,kind in silent:
        print(f"   {tool}.{n}: got {g}, expected {e}  [{kind}]")
