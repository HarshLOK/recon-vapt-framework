import httpx

SKIP_WITHOUT_VERSION = {
    "cloudflare", "cdn", "nginx", "apache", "iis",
    "not disclosed", "unknown",
}


async def lookup_cves(product: str, version: str = "") -> list:
    product_lower = product.lower().strip()
    if not version and any(s in product_lower for s in SKIP_WITHOUT_VERSION):
        print(f"  [CVE] Skipping '{product}' — no version, too generic")
        return []

    print(f"  [CVE] Looking up: {product} {version}")
    results = []
    keyword = f"{product} {version}".strip()
    params  = {"keywordSearch": keyword, "resultsPerPage": 5}

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params=params
            )
            if r.status_code != 200:
                return results

            for item in r.json().get("vulnerabilities", []):
                cve    = item.get("cve", {})
                cve_id = cve.get("id", "")

                score, severity = "N/A", "UNKNOWN"
                metrics = cve.get("metrics", {})
                if "cvssMetricV31" in metrics:
                    m        = metrics["cvssMetricV31"][0]["cvssData"]
                    score    = m.get("baseScore", "N/A")
                    severity = m.get("baseSeverity", "UNKNOWN")
                elif "cvssMetricV2" in metrics:
                    m     = metrics["cvssMetricV2"][0]["cvssData"]
                    score = m.get("baseScore", "N/A")

                desc = next(
                    (d["value"][:200] for d in cve.get("descriptions", [])
                     if d.get("lang") == "en"), ""
                )

                if product_lower in desc.lower():
                    results.append({
                        "cve_id":     cve_id,
                        "score":      score,
                        "severity":   severity,
                        "summary":    desc,
                        "confidence": "MEDIUM" if version else "LOW",
                    })

    except Exception as e:
        print(f"  [CVE] Error: {e}")

    return results


async def run_cve_checks(http_data: dict) -> list:
    findings = []
    server = http_data.get("server", "")
    techs  = http_data.get("technologies", {})

    targets = []

    # Only add server if it has version (contains "/")
    if server and "/" in server:
        parts = server.split("/", 1)
        targets.append((parts[0].strip(), parts[1].strip()))

    for _, tech_value in techs.items():
        parts = tech_value.split("/", 1)
        if len(parts) == 2:
            targets.append((parts[0].strip(), parts[1].strip()))

    if not targets:
        print("  [CVE] No versioned technologies found — skipping CVE lookup")
        return findings

    for product, version in targets:
        for cve in await lookup_cves(product, version):
            findings.append({
                "type":       "CVE_MATCH",
                "severity":   cve["severity"],
                "confidence": cve["confidence"],
                "detail":     f"{cve['cve_id']} (CVSS {cve['score']}): {cve['summary']}",
                "product":    f"{product} {version}".strip(),
            })

    return findings
