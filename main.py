import typer
import asyncio
import yaml
import os
from datetime import datetime
from rich.console import Console
from rich.table import Table

from core.target import validate_url, get_domain, permission_check
from core.session import get_session
from recon.dns import run_dns_recon
from recon.http_fingerprint import run_http_fingerprint
from recon.crawler import crawl
from recon.js_render import render_page
from recon.port_scan import run_port_scan
from recon.cert_whois import get_cert_subdomains, get_whois

from recon.vuln.headers import check_security_headers
from recon.vuln.cors import check_cors
from recon.vuln.injection import run_injection_tests
from recon.vuln.ssrf import check_ssrf
from recon.vuln.cve_lookup import run_cve_checks

from reporting.json_report import save_json
from reporting.html_report import save_html
from reporting.severity import sort_findings, count_by_severity

console = Console()


def print_banner(url: str):
    console.print("\n[bold cyan]" + "═"*50 + "[/bold cyan]")
    console.print(f"[bold cyan]  RECON TOOL v0.3  |  {url}[/bold cyan]")
    console.print("[bold cyan]" + "═"*50 + "[/bold cyan]\n")


def print_dns(dns_data: dict):
    console.print("[bold blue]\n[DNS RECON][/bold blue]")
    table = Table(show_header=True, header_style="bold")
    table.add_column("Record Type")
    table.add_column("Values")
    for record_type, values in dns_data.items():
        val = ", ".join(values) if values else "[dim]none found[/dim]"
        table.add_row(record_type, val)
    console.print(table)


def print_http(http_data: dict):
    console.print("[bold blue]\n[HTTP FINGERPRINT][/bold blue]")
    console.print(f"  Server       : {http_data['server']}")
    techs = http_data.get("technologies", {})
    if techs:
        for k, v in techs.items():
            console.print(f"  {k} : {v}")
    else:
        console.print("  Technologies : [dim]none detected[/dim]")
    console.print("\n[bold blue][SECURITY HEADERS][/bold blue]")
    for header, present in http_data["security_headers"].items():
        if present:
            console.print(f"  [green]✓ {header}[/green]")
        else:
            console.print(f"  [red]✗ {header} — MISSING[/red]")


def print_crawl(crawl_data: dict):
    console.print("[bold blue]\n[CRAWLER][/bold blue]")
    console.print(f"  Pages crawled : {len(crawl_data['pages_crawled'])}")
    console.print(f"  Links found   : {len(crawl_data['links_found'])}")
    console.print(f"  Forms found   : {len(crawl_data['forms'])}")
    console.print(f"  JS files      : {len(crawl_data['js_files'])}")
    console.print(f"  robots.txt    : {len(crawl_data['robots'])} rules")
    console.print(f"  sitemap URLs  : {len(crawl_data['sitemap_urls'])}")
    if crawl_data["forms"]:
        console.print("\n  [yellow]Forms discovered:[/yellow]")
        for form in crawl_data["forms"]:
            console.print(f"    {form['method']} → {form['action']}")
            for inp in form["inputs"]:
                console.print(f"      input: {inp['name']} ({inp['type']})")


def print_ports(port_data: dict):
    console.print("[bold blue]\n[PORT SCAN][/bold blue]")
    if not port_data:
        console.print("  [dim]No open ports found or scan failed[/dim]")
        return
    for host, protos in port_data.items():
        for proto, ports in protos.items():
            for port, info in ports.items():
                console.print(
                    f"  [green]{port}/{proto}[/green]  "
                    f"{info['service']}  {info['product']} {info['version']}"
                )


def print_cert(subdomains: list, whois_data: dict):
    console.print("[bold blue]\n[CERT TRANSPARENCY + WHOIS][/bold blue]")
    console.print(f"  Subdomains found via crt.sh: {len(subdomains)}")
    for sub in subdomains[:20]:
        console.print(f"    {sub}")
    if whois_data:
        console.print("\n  [yellow]WHOIS:[/yellow]")
        for k, v in whois_data.items():
            console.print(f"    {k:15}: {v}")


def print_findings(findings: list, section: str):
    console.print(f"[bold blue]\n[{section}][/bold blue]")
    if not findings:
        console.print("  [dim]No issues found[/dim]")
        return
    for f in findings:
        color = {
            "CRITICAL":      "red",
            "HIGH":          "red",
            "MEDIUM":        "yellow",
            "LOW":           "cyan",
            "INFORMATIONAL": "dim",
            "UNKNOWN":       "white",
            "N/A":           "white",
        }.get(f.get("severity", ""), "white")
        confidence = f.get("confidence", "")
        conf_str   = f" [dim][{confidence} confidence][/dim]" if confidence else ""
        console.print(
            f"  [{color}][{f.get('severity','?')}][/{color}]"
            f"{conf_str} "
            f"{f.get('type')} — {f.get('detail','')[:120]}"
        )


async def _run(url: str, config: dict):
    domain = get_domain(url)

    async with get_session(config.get("timeout", 10)) as session:
        # Phase 1
        dns_data  = run_dns_recon(domain)
        http_data = await run_http_fingerprint(url, session)

        # Phase 2
        crawl_data = await crawl(
            url, session, max_pages=config.get("max_pages", 20)
        )

        # Phase 3
        header_findings    = check_security_headers(http_data.get("raw_headers", {}))
        cors_findings      = await check_cors(url, session)
        injection_findings = await run_injection_tests(crawl_data.get("forms", []), session)
        ssrf_findings      = await check_ssrf(url, session)
        cve_findings       = await run_cve_checks(http_data)

    # JS render
    os.makedirs("output", exist_ok=True)
    screenshot_path = f"output/screenshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
    js_data = await render_page(url, screenshot_path=screenshot_path)

    # Port scan
    port_data = run_port_scan(domain, ports=config.get("ports", "22,80,443,8080"))

    # Cert + WHOIS
    subdomains = await get_cert_subdomains(domain)
    whois_data = get_whois(domain)

    # Print results
    print_banner(url)
    print_dns(dns_data)
    print_http(http_data)
    print_crawl(crawl_data)
    print_ports(port_data)
    print_cert(subdomains, whois_data)
    print_findings(header_findings,    "SECURITY HEADERS")
    print_findings(cors_findings,      "CORS")
    print_findings(injection_findings, "INJECTION TESTS")
    print_findings(ssrf_findings,      "SSRF + OPEN REDIRECT")
    print_findings(cve_findings,       "CVE MATCHES")

    # Save
    findings = {
        "headers":   header_findings,
        "cors":      cors_findings,
        "injection": injection_findings,
        "ssrf":      ssrf_findings,
        "cves":      cve_findings,
    }
    recon_data = {
        "dns":        dns_data,
        "http":       http_data,
        "crawl":      crawl_data,
        "ports":      port_data,
        "subdomains": subdomains,
        "whois":      whois_data,
    }
    json_path = save_json(url, recon_data, findings)
    html_path = save_html(url, recon_data, findings)
    console.print(f"\n[green]JSON → {json_path}[/green]")
    console.print(f"[green]HTML → {html_path}[/green]")


def scan(
    target: str = typer.Option(None, "--target", "-t", help="Target URL to scan"),
):
    """Run full recon on a target URL."""
    with open("config.yaml") as f:
        config = yaml.safe_load(f)
    url = validate_url(target or config["target"])
    permission_check(url)
    asyncio.run(_run(url, config))


if __name__ == "__main__":
    typer.run(scan)