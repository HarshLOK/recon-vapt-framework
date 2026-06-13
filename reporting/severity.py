SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNKNOWN"]
SEVERITY_COLORS = {
    "CRITICAL":      "#e74c3c",
    "HIGH":          "#e67e22",
    "MEDIUM":        "#f39c12",
    "LOW":           "#3498db",
    "INFORMATIONAL": "#95a5a6",
    "UNKNOWN":       "#7f8c8d",
}
CONFIDENCE_ORDER = ["HIGH", "MEDIUM", "LOW"]


def sort_findings(findings: list) -> list:
    """Sort findings by severity then confidence."""
    def rank(f):
        sev  = f.get("severity", "UNKNOWN").upper()
        conf = f.get("confidence", "LOW").upper()
        return (
            SEVERITY_ORDER.index(sev)  if sev  in SEVERITY_ORDER  else 99,
            CONFIDENCE_ORDER.index(conf) if conf in CONFIDENCE_ORDER else 99,
        )
    return sorted(findings, key=rank)


def count_by_severity(findings: list) -> dict:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "UNKNOWN").upper()
        if sev in counts:
            counts[sev] += 1
    return counts


def filter_by_min_severity(findings: list, min_sev: str) -> list:
    """Return only findings at or above min_sev."""
    if min_sev not in SEVERITY_ORDER:
        return findings
    threshold = SEVERITY_ORDER.index(min_sev)
    return [
        f for f in findings
        if SEVERITY_ORDER.index(f.get("severity","UNKNOWN").upper()
           if f.get("severity","UNKNOWN").upper() in SEVERITY_ORDER
           else "UNKNOWN") <= threshold
    ]