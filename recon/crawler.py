
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="bs4")
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="bs4")


def is_same_domain(url: str, base_domain: str) -> bool:
    """Check if a URL belongs to the same domain."""
    return urlparse(url).netloc == base_domain


def parse_page(html: str, base_url: str) -> dict:
    """Extract links, forms, scripts, and hidden inputs from a page."""
    soup = BeautifulSoup(html, "html.parser")
    base_domain = urlparse(base_url).netloc

    # Extract all links
    links = set()
    for tag in soup.find_all("a", href=True):
        full_url = urljoin(base_url, tag["href"])
        if is_same_domain(full_url, base_domain):
            links.add(full_url)

    # Extract all forms
    forms = []
    for form in soup.find_all("form"):
        form_data = {
            "action": urljoin(base_url, form.get("action", "")),
            "method": form.get("method", "get").upper(),
            "inputs": []
        }
        for inp in form.find_all(["input", "textarea", "select"]):
            form_data["inputs"].append({
                "name":  inp.get("name", ""),
                "type":  inp.get("type", "text"),
                "value": inp.get("value", "")
            })
        forms.append(form_data)

    # Extract script sources (JS files)
    scripts = []
    for script in soup.find_all("script", src=True):
        scripts.append(urljoin(base_url, script["src"]))

    # Extract inline JS for endpoint hunting
    inline_js = []
    for script in soup.find_all("script", src=False):
        if script.string:
            inline_js.append(script.string[:500])  # first 500 chars only

    return {
        "links":     list(links),
        "forms":     forms,
        "scripts":   scripts,
        "inline_js": inline_js,
    }


async def fetch_robots_and_sitemap(base_url: str, session: httpx.AsyncClient) -> dict:
    """Fetch robots.txt and sitemap.xml."""
    results = {"robots": [], "sitemap": []}

    # robots.txt
    try:
        r = await session.get(f"{base_url}/robots.txt")
        if r.status_code == 200:
            for line in r.text.splitlines():
                if line.lower().startswith(("disallow:", "allow:", "sitemap:")):
                    results["robots"].append(line.strip())
    except Exception:
        pass

    # sitemap.xml
    try:
        r = await session.get(f"{base_url}/sitemap.xml")
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser") if "<html" in r.text.lower() else BeautifulSoup(r.text, "xml")
            for loc in soup.find_all("loc"):
                results["sitemap"].append(loc.text.strip())
    except Exception:
        pass

    return results


async def crawl(
    start_url: str,
    session: httpx.AsyncClient,
    max_pages: int = 20,
) -> dict:
    """Crawl a site up to max_pages pages and collect all findings."""
    import asyncio

    visited   = set()
    to_visit  = [start_url]
    all_links   = set()
    all_forms   = []
    all_scripts = set()

    semaphore = asyncio.Semaphore(3)  # max 3 concurrent requests

    async def fetch_one(url: str):
        async with semaphore:
            try:
                await asyncio.sleep(0.5)  # polite delay
                r = await session.get(url)
                return r.text
            except Exception:
                return None

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)

        print(f"  [CRAWL] {url}")
        html = await fetch_one(url)
        if not html:
            continue

        parsed = parse_page(html, url)
        all_links.update(parsed["links"])
        all_forms.extend(parsed["forms"])
        all_scripts.update(parsed["scripts"])

        # Queue new links
        for link in parsed["links"]:
            if link not in visited:
                to_visit.append(link)

    # Also fetch robots.txt and sitemap
    base = f"{urlparse(start_url).scheme}://{urlparse(start_url).netloc}"
    robots_sitemap = await fetch_robots_and_sitemap(base, session)

    return {
        "pages_crawled": list(visited),
        "links_found":   list(all_links),
        "forms":         all_forms,
        "js_files":      list(all_scripts),
        "robots":        robots_sitemap["robots"],
        "sitemap_urls":  robots_sitemap["sitemap"],
    }
