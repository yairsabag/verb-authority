"""Pure result classification shared by separately observed integration workflows.

This module does not observe execution, evaluate effects, or establish that two
applications implement the same contract. Each workflow owns those checks and
must retain their evidence, failures, and uncertainty independently.
"""

EXIT_CODES = {"pass": 0, "regression": 1, "incomplete": 2}
ARM_STATUSES = frozenset({"pass", "fail", "incomplete"})


def classify_comparison(baseline_status, candidate_status, *, comparable=True,
                        incomplete=False):
    """Classify already evaluated arms; missing or malformed state is non-green."""
    if (type(baseline_status) is not str or baseline_status not in ARM_STATUSES
            or type(candidate_status) is not str or candidate_status not in ARM_STATUSES
            or type(comparable) is not bool or type(incomplete) is not bool):
        return "incomplete"
    if incomplete or not comparable or baseline_status != "pass" or candidate_status == "incomplete":
        return "incomplete"
    return "regression" if candidate_status == "fail" else "pass"


def _has_errors(value):
    # Missing errors is accepted by the existing report API; present malformed
    # error containers must not be interpreted as evidence of successful execution.
    errors = value.get("errors", [])
    return type(errors) is not list or bool(errors)


def _valid_identity(value):
    # The filesystem producer computes the actual digest. Keep this report API's
    # existing opaque-string identity semantics (including short test identities).
    return type(value) is str and bool(value) and value == value.strip()


def compare_results(report):
    """Compatibility adapter for the existing filesystem report shape.

    Only classify the report. Do not erase observed failures when another part
    of the report is incomplete, and do not reinterpret a different workflow's
    observations as filesystem or MCP evidence.
    """
    if type(report) is not dict or _has_errors(report):
        return "incomplete"
    runs = report.get("runs")
    if type(runs) is not dict:
        return "incomplete"
    baseline, candidate = runs.get("baseline"), runs.get("candidate")
    if type(baseline) is not dict or type(candidate) is not dict:
        return "incomplete"
    baseline_schema, candidate_schema = baseline.get("schema_sha256"), candidate.get("schema_sha256")
    comparable = (_valid_identity(baseline_schema) and _valid_identity(candidate_schema)
                  and baseline_schema == candidate_schema)
    return classify_comparison(
        baseline.get("status"), candidate.get("status"), comparable=comparable,
        incomplete=_has_errors(baseline) or _has_errors(candidate),
    )
