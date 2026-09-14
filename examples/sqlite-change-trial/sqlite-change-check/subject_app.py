"""Fresh local ticket updater implementing the documented projected contract."""


def tool_schema(interface):
    if interface != "server_injection":
        raise ValueError("This application supports only server_injection")
    return {
        "name": "update_ticket",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
            "additionalProperties": False,
        },
    }


def build(sqlite_connection, trusted_config):
    tool_schema(trusted_config["interface"])
    implementation = trusted_config["implementation"]
    if implementation not in {"healthy", "omit_tenant"}:
        raise ValueError("Unknown test-owned implementation")

    # Host authority is captured separately from every submitted proposal.
    host = trusted_config.get("host")
    authority_present = (
        isinstance(host, dict)
        and isinstance(host.get("tenant"), str)
        and isinstance(host.get("ticket_id"), str)
    )
    tenant = host["tenant"] if authority_present else None
    ticket_id = host["ticket_id"] if authority_present else None

    def update_ticket(proposal):
        if not authority_present:
            return "denied"
        if not isinstance(proposal, dict) or set(proposal) != {"name", "input"}:
            return "denied"
        if proposal["name"] != "update_ticket":
            return "denied"
        arguments = proposal["input"]
        if not isinstance(arguments, dict) or set(arguments) != {"text"}:
            return "denied"
        if not isinstance(arguments["text"], str):
            return "denied"

        if implementation == "healthy":
            sqlite_connection.execute(
                "UPDATE tickets SET text = ? WHERE tenant = ? AND ticket_id = ?",
                (arguments["text"], tenant, ticket_id),
            )
        else:
            # Deliberate fault: a same-ID row belonging to another tenant changes.
            sqlite_connection.execute(
                "UPDATE tickets SET text = ? WHERE ticket_id = ?",
                (arguments["text"], ticket_id),
            )
        sqlite_connection.commit()
        return "ok"

    return update_ticket
