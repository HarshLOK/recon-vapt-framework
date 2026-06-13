COOKIE_FLAGS = ["HttpOnly", "Secure", "SameSite"]


def _check_csp(value: str) -> tuple:
    """Returns (is_weak, reason)."""
    issues = []
    v = value.lower()
    if "'unsafe-inline'" in v:
        issues.append("contains 'unsafe-inline'")
    if "'unsafe-eval'" in v:
        issues.append("contains 'unsafe-eval'")
    if "* " in v or v.startswith("*"):
        issues.append("contains wildcard source")
    return bool(issues), ", ".join(issues)


def _check_hsts(value: str) -> tuple:
    issues = []
    v = value.lower()
    if "max-age" not in v:
        issues.append("missing max-age")
    else:
        try:
            age = int(v.split("max-age=")[1].split(";")[0].strip())
            if age < 31536000:
                issues.append(f"max-age too short ({age}s, recommend 31536000+)")
        except Exception:
            issues.append("max-age unparseable")
    return bool(issues), ", ".join(issues)


def _check_xframe(value: str) -> tuple:
    v = value.strip().upper()
    # DENY and SAMEORIGIN are both valid
    if v in ("DENY", "SAMEORIGIN"):
        return False, ""
    return True, f"Invalid value: '{value}' — use DENY or SAMEORIGIN"


def _check_xcontent(value: str) -> tuple:
    if value.strip().lower() == "nosniff":
        return False, ""
    return True, f"Must be 'nosniff', got: '{value}'"


def _check_referrer(value: str) -> tuple:
    valid = {
        "no-referrer", "no-referrer-when-downgrade", "strict-origin",
        "strict-origin-when-cross-origin", "same-origin",
    }
    if value.strip().lower() in valid:
        return False, ""
    return True, f"Weak referrer policy: '{value}'"


HEADER_CHECKS = {
    "Strict-Transport-Security": _check_hsts,
    "Content-Security-Policy":   _check_csp,
    "X-Frame-Options":           _check_xframe,
    "X-Content-Type-Options":    _check_xcontent,
    "Referrer-Policy":           _check_referrer,
}


def check_security_headers(headers: dict) -> list:
    findings = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for header, check_fn in HEADER_CHECKS.items():
        value = headers_lower.get(header.lower())
        if not value:
            findings.append({
                "type": "MISSING_HEADER", "severity": "MEDIUM",
                "confidence": "HIGH",
                "header": header,
                "detail": f"{header} is missing entirely.",
            })
        else:
            is_weak, reason = check_fn(value)
            if is_weak:
                findings.append({
                    "type": "WEAK_HEADER", "severity": "LOW",
                    "confidence": "HIGH",
                    "header": header,
                    "detail": f"{header} misconfigured — {reason}",
                })

    # Permissions-Policy — just check presence
    if "permissions-policy" not in headers_lower:
        findings.append({
            "type": "MISSING_HEADER", "severity": "LOW",
            "confidence": "HIGH",
            "header": "Permissions-Policy",
            "detail": "Permissions-Policy missing — controls browser features.",
        })

    # Cookie flags
    for key, value in headers.items():
        if key.lower() == "set-cookie":
            for flag in COOKIE_FLAGS:
                if flag.lower() not in value.lower():
                    findings.append({
                        "type": "COOKIE_FLAG_MISSING", "severity": "MEDIUM",
                        "confidence": "HIGH",
                        "header": "Set-Cookie",
                        "detail": f"Cookie missing '{flag}': {value[:80]}",
                    })

    return findings