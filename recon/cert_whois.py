import httpx
import whois
import time


async def get_cert_subdomains(domain: str) -> list:
    print(f"  [CERT] Querying crt.sh for: {domain}")
    subdomains = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"

    try:
        async with httpx.AsyncClient(
            timeout=30,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; security-research)",
                "Accept": "application/json",
            },
            follow_redirects=True,
        ) as client:
            r = await client.get(url)
            print(f"  [CERT] HTTP status: {r.status_code}, size: {len(r.text)} bytes")

            if r.status_code != 200:
                print(f"  [CERT] Non-200 response — skipping")
                return []

            if not r.text.strip():
                print(f"  [CERT] Empty response from crt.sh")
                return []

            try:
                data = r.json()
            except Exception as e:
                print(f"  [CERT] JSON parse failed: {e}")
                print(f"  [CERT] Response preview: {r.text[:300]}")
                return []

            print(f"  [CERT] Got {len(data)} certificate entries")

            for entry in data:
                for field in ("name_value", "common_name"):
                    name = entry.get(field, "")
                    for sub in name.splitlines():
                        sub = sub.strip().lstrip("*.")
                        if sub and sub.endswith(domain) and " " not in sub:
                            subdomains.add(sub)

    except Exception as e:
        print(f"  [CERT] Request failed: {type(e).__name__}: {e}")

    result = sorted(subdomains)
    print(f"  [CERT] Found {len(result)} unique subdomains")
    return result


def get_whois(domain: str) -> dict:
    print(f"  [WHOIS] Looking up: {domain}")
    for attempt in range(3):
        try:
            w = whois.whois(domain)
            return {
                "registrar":   str(w.registrar or "Unknown"),
                "created":     str(w.creation_date),
                "expires":     str(w.expiration_date),
                "nameservers": w.name_servers if isinstance(w.name_servers, list) else [],
                "org":         str(w.org or "Not disclosed"),
                "status":      "success",
            }
        except Exception as e:
            print(f"  [WHOIS] Attempt {attempt+1} failed: {e}")
            time.sleep(2)
    return {"status": "failed", "error": "WHOIS lookup failed after 3 attempts"}
