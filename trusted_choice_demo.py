"""A complete local runtime integration with a trusted contact resolver.

No model, provider, network, or real email service is used. The in-memory
outbox stands in for the side-effecting SDK call that an application would
register as ``Tool.fn``.
"""

from verb_authority import (
    GuardedToolRunner,
    Param,
    Registry,
    Risk,
    Tool,
    TrustedChoice,
    TrustedResolver,
)


OUTBOX: list[dict[str, str]] = []


def send_email(to: str, body: str) -> dict[str, str]:
    message = {"to": to, "body": body}
    OUTBOX.append(message)
    return {"status": "sent"}


CONTACTS = TrustedResolver(
    [
        TrustedChoice(
            "Dana",
            "dana@company.com",
            "authenticated company directory: contact-17",
        ),
        TrustedChoice(
            "Alice",
            "alice@company.com",
            "authenticated company directory: contact-23",
        ),
    ]
)

REGISTRY = Registry()
REGISTRY.add(
    Tool(
        "send_email",
        [Param("to", "email"), Param("body", "string")],
        fn=send_email,
        risk=Risk.WRITE,
    )
)
RUNNER = GuardedToolRunner(REGISTRY)


def deliver_to_contact(contact_key: str, body: str):
    """Resolve first, gate second, execute last."""

    resolution = CONTACTS.resolve(contact_key)
    if not resolution.resolved:
        print(f"BLOCKED before tool call: contact {resolution.status.value}")
        return None

    tool_call = {
        "name": "send_email",
        # The destination is copied from the trusted catalog, not from the key.
        "input": {"to": resolution.value, "body": body},
    }
    execution = RUNNER.run(
        tool_call,
        trusted_args={"to": resolution.value},
    )
    verdict = "EXECUTED" if execution.executed else "BLOCKED"
    print(
        f"{verdict}: key={contact_key!r}, to={resolution.value!r}, "
        f"evidence={resolution.evidence!r}"
    )
    return execution


if __name__ == "__main__":
    print("1. Approved contact")
    deliver_to_contact("Dana", "Meeting notes")

    print("\n2. Unapproved destination")
    deliver_to_contact("attacker@evil.com", "Stolen document")

    print("\n3. Documented control-flow boundary")
    print("   Imagine the key 'Alice' below came from an untrusted email.")
    deliver_to_contact("Alice", "Document contents")
    print("   The value-level gate allows this approved destination by design.")
