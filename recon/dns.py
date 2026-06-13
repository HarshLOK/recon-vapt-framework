import dns.resolver


def get_a_records(domain: str) -> list:
    """Get IP addresses for the domain."""
    try:
        answers = dns.resolver.resolve(domain, "A")
        return [str(r) for r in answers]
    except Exception:
        return []


def get_mx_records(domain: str) -> list:
    """Get mail server records."""
    try:
        answers = dns.resolver.resolve(domain, "MX")
        return [str(r.exchange) for r in answers]
    except Exception:
        return []


def get_txt_records(domain: str) -> list:
    """Get TXT records — often contains SPF, DMARC, verification tokens."""
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        return [str(r) for r in answers]
    except Exception:
        return []


def get_ns_records(domain: str) -> list:
    """Get nameserver records."""
    try:
        answers = dns.resolver.resolve(domain, "NS")
        return [str(r) for r in answers]
    except Exception:
        return []


def run_dns_recon(domain: str) -> dict:
    """Run all DNS lookups and return combined results."""
    print(f"  [DNS] Querying records for: {domain}")
    return {
        "A":   get_a_records(domain),
        "MX":  get_mx_records(domain),
        "TXT": get_txt_records(domain),
        "NS":  get_ns_records(domain),
    }