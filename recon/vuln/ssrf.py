import httpx


# Common redirect/SSRF parameter names to test
SSRF_PARAMS = [
    "url", "redirect", "next", "target", "dest",
    "destination", "redir", "return", "returnTo",
    "go", "goto", "link", "ref",
]

# Internal addresses to probe for SSRF
SSRF_TARGETS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254",          # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
]


async def check_ssrf(
    url: str,
    session: httpx.AsyncClient,
) -> list:
    """
    Probe common redirect parameters for SSRF.
    Looks for: redirect to internal IPs, metadata endpoints responding.
    """
    findings = []

    for param in SSRF_PARAMS:
        for target in SSRF_TARGETS:
            probe_url = f"{url}?{param}={target}"
            try:
                r = await session.get(probe_url, follow_redirects=False)

                # Open redirect — server is redirecting to our injected URL
                if r.status_code in (301, 302, 303, 307, 308):
                    location = r.headers.get("location", "")
                    if any(t in location for t in SSRF_TARGETS):
                        findings.append({
                            "type":     "OPEN_REDIRECT",
                            "severity": "HIGH",
                            "url":      probe_url,
                            "detail":   f"Redirects to: {location}",
                        })

                # SSRF — server fetched internal content
                if r.status_code == 200 and "169.254.169.254" in target:
                    if any(k in r.text.lower() for k in [
                        "ami-id", "instance-id", "iam", "security-credentials"
                    ]):
                        findings.append({
                            "type":     "SSRF_CLOUD_METADATA",
                            "severity": "CRITICAL",
                            "url":      probe_url,
                            "detail":   "AWS metadata endpoint returned data!",
                        })

            except Exception:
                pass

    return findings