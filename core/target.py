from urllib.parse import urlparse
import sys


def validate_url(url: str) -> str:
    """Check URL is valid and return cleaned version."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        print(f"[ERROR] Invalid URL: '{url}' — must start with http:// or https://")
        sys.exit(1)
    if not parsed.netloc:
        print(f"[ERROR] No domain found in URL: '{url}'")
        sys.exit(1)
    return url.rstrip("/")


def get_domain(url: str) -> str:
    """Extract just the domain from a URL. e.g. https://example.com → example.com"""
    return urlparse(url).netloc


def permission_check(url: str):
    """Force user to confirm they have permission before scanning."""
    print("\n" + "="*50)
    print("  ⚠  LEGAL DISCLAIMER")
    print("="*50)
    print(f"  Target : {url}")
    print("  You must own this domain OR have explicit")
    print("  written permission to scan it.")
    print("  Unauthorized scanning is illegal.")
    print("="*50)
    answer = input("\n  Do you confirm? (y/n): ").strip().lower()
    if answer != "y":
        print("Exiting.")
        sys.exit(0)
    print()