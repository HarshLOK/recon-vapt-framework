import httpx

SENSITIVE_PATHS = ["/api/", "/admin/", "/user/", "/account/", "/profile/"]


async def check_cors(url: str, session: httpx.AsyncClient) -> list:
    findings = []
    test_origin = "https://evil.attacker.com"

    try:
        r = await session.get(url, headers={"Origin": test_origin})
        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "")
        is_sensitive = any(p in url for p in SENSITIVE_PATHS)
        has_auth = "authorization" in str(r.headers).lower() or \
                   "set-cookie" in str(r.headers).lower()

        if acao == "*":
            if acac.lower() == "true":
                # Wildcard + credentials = always critical
                findings.append({
                    "type":       "CORS_WILDCARD_WITH_CREDENTIALS",
                    "severity":   "CRITICAL",
                    "confidence": "HIGH",
                    "url":        url,
                    "detail":     "Wildcard CORS with credentials allowed — exploitable.",
                })
            elif is_sensitive or has_auth:
                findings.append({
                    "type":       "CORS_WILDCARD",
                    "severity":   "HIGH",
                    "confidence": "HIGH",
                    "url":        url,
                    "detail":     "Wildcard CORS on sensitive/authenticated endpoint.",
                })
            else:
                findings.append({
                    "type":       "CORS_WILDCARD",
                    "severity":   "INFORMATIONAL",
                    "confidence": "MEDIUM",
                    "url":        url,
                    "detail":     "Wildcard CORS on public endpoint — low risk unless used on APIs.",
                })

        if acao == test_origin:
            severity = "CRITICAL" if acac.lower() == "true" else "HIGH"
            findings.append({
                "type":       "CORS_ORIGIN_REFLECTED",
                "severity":   severity,
                "confidence": "HIGH",
                "url":        url,
                "detail":     f"Arbitrary origin reflected. Credentials: {acac or 'false'}.",
            })

    except Exception as e:
        print(f"  [CORS] Error: {e}")

    return findings