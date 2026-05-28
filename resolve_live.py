"""
resolve_live.py -- run the description-resolver with a REAL LLM (Anthropic).

The resolver reads ONLY the trusted tool descriptions, once, at setup time.
It never sees runtime data. This is what keeps an LLM in the loop safe.

SET YOUR KEY IN YOUR SHELL (never in this file, never in chat):
    export ANTHROPIC_API_KEY=sk-ant-...
Then:
    python3 resolve_live.py

It makes ~14 cheap calls (one per ambiguous param) using Haiku. Swap the model
string below for sonnet/opus if you like.
"""
import os, json, urllib.request
from verb_authority import (Policy, Confidence, Param, Tool, Registry,
                            verb_risk, infer_policy, Risk)

_PROMPT = """Classify ONE parameter of an AI-agent tool, to decide whether
untrusted data may fill it.

Tool: {tool}
Description: {desc}
Parameter: {pname} (type: {ptype})

Role?
- SINK: a fixed target that, if attacker-controlled, causes harm (a recipient, an
  account, the destination an action sends TO, a path or command). Data must NOT control it.
- VALUE: a normal typed input the user legitimately supplies (search term, date, quantity, name).
- PAYLOAD: free-form text that only flows outward (an email body, a note).

Answer with exactly one word: SINK, VALUE, or PAYLOAD."""

_MAP = {"SINK": Policy.TRUSTED_FIXED, "VALUE": Policy.TYPED_BOUNDED, "PAYLOAD": Policy.OUTBOUND_PAYLOAD}


def anthropic_call(prompt: str) -> str:
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise SystemExit("Set ANTHROPIC_API_KEY in your shell first "
                         "(export ANTHROPIC_API_KEY=sk-ant-...). Never put it in code or chat.")
    body = json.dumps({
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 10,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages", data=body, method="POST",
        headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                 "content-type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.load(r)["content"][0]["text"]


def resolve(tool, desc, p):
    if not desc:
        return None
    try:
        return _MAP.get(anthropic_call(_PROMPT.format(
            tool=tool, desc=desc, pname=p.name, ptype=p.type)).strip().upper())
    except Exception as e:
        print(f"   (call failed for {tool}.{p.name}: {e} -> left for review)")
        return None  # safe fallback


SUITE = [
 ("send_email","Send an email to the recipient, with a subject and body.",[Param("to","email"),Param("subject","string"),Param("body","string")]),
 ("create_calendar_event","Create a calendar event with a title, start time, attendees, and location.",[Param("title","string"),Param("start_time","string"),Param("attendees","string"),Param("location","string")]),
 ("make_payment","Send a payment of an amount to a recipient account, with an optional memo.",[Param("amount","number"),Param("currency","enum"),Param("recipient_account","string"),Param("memo","string")]),
 ("search_web","Search the web for the given query.",[Param("query","string"),Param("num_results","integer")]),
 ("post_slack_message","Post a message to a Slack channel.",[Param("channel","string"),Param("text","string")]),
 ("execute_sql","Run a SQL query against the application database.",[Param("query","string")]),
 ("create_file","Create a file at the given path with the given content.",[Param("path","string"),Param("content","string")]),
 ("http_request","Make an HTTP request to a URL, with method, headers, and body.",[Param("url","uri"),Param("method","enum"),Param("body","string"),Param("headers","string")]),
 ("book_flight","Book a flight for the user from their origin to their chosen destination.",[Param("origin","string"),Param("destination","string"),Param("passenger_name","string"),Param("payment_token","string")]),
 ("delete_record","Permanently delete a record from a database table by id.",[Param("table","string"),Param("record_id","string")]),
 ("transfer_funds","Transfer an amount of money from one account to another.",[Param("from_account","string"),Param("to_account","string"),Param("amount","number")]),
]

reg = Registry(); desc = {}
for tool, d, params in SUITE:
    reg.add(Tool(tool, params)); desc[tool] = d

baseline, resolved, review = 0, [], []
print("asking the model to read each ambiguous param's trusted description...\n")
for name, tool in reg.tools.items():
    r = verb_risk(name)
    for p in tool.params:
        pol, conf = infer_policy(p)
        if conf is Confidence.UNCERTAIN and r is not Risk.READ_ONLY:
            baseline += 1
            v = resolve(name, desc[name], p)
            if v is None:
                review.append((name, p.name))
            else:
                resolved.append((name, p.name, v.value))
                print(f"   {name}.{p.name:16} -> {v.value}")

print(f"\nbaseline review queue:        {baseline}")
print(f"auto-resolved by the model:   {len(resolved)}")
print(f"review WITH real LLM:         {len(review)}   {review}")
