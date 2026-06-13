import httpx


SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


async def fetch_headers(url: str, session: httpx.AsyncClient) -> dict:
    """Make a GET request and return response headers."""
    try:
        response = await session.get(url)
        return dict(response.headers)
    except Exception as e:
        print(f"  [HTTP] Error fetching headers: {e}")
        return {}


def detect_server(headers: dict) -> str:
    """Read the Server header to identify server software."""
    return headers.get("server", "Not disclosed")


def detect_technologies(headers: dict) -> dict:
    """Detect technologies from headers."""
    tech = {}
    if "x-powered-by" in headers:
        tech["X-Powered-By"] = headers["x-powered-by"]
    if "x-generator" in headers:
        tech["X-Generator"] = headers["x-generator"]
    if "x-drupal-cache" in headers:
        tech["CMS"] = "Drupal"
    if "x-pingback" in headers:
        tech["CMS"] = "WordPress (likely)"
    return tech


def check_security_headers(headers: dict) -> dict:
    """Check which security headers are present or missing."""
    headers_lower = {k.lower(): v for k, v in headers.items()}
    results = {}
    for header in SECURITY_HEADERS:
        results[header] = header.lower() in headers_lower
    return results


async def run_http_fingerprint(url: str, session: httpx.AsyncClient) -> dict:
    """Run full HTTP fingerprinting and return all results."""
    print(f"  [HTTP] Fingerprinting: {url}")
    headers = await fetch_headers(url, session)
    return {
        "server":           detect_server(headers),
        "technologies":     detect_technologies(headers),
        "security_headers": check_security_headers(headers),
        "raw_headers":      headers,
    }