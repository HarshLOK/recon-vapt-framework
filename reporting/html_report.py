import os
from datetime import datetime
from reporting.severity import (
    sort_findings, count_by_severity,
    SEVERITY_COLORS, SEVERITY_ORDER
)


def _finding_rows(findings: list) -> str:
    rows = ""
    for f in sort_findings(findings):
        sev   = f.get("severity", "?").upper()
        color = SEVERITY_COLORS.get(sev, "#fff")
        conf  = f.get("confidence", "")
        rows += f"""
        <tr>
          <td style='color:{color};font-weight:bold'>{sev}</td>
          <td>{f.get('type','')}</td>
          <td>{conf}</td>
          <td style='font-size:0.85em'>{f.get('detail','')[:300]}</td>
          <td>{f.get('url', f.get('header', f.get('product', '')))}</td>
        </tr>"""
    return rows or "<tr><td colspan='5' style='color:#666'>No findings</td></tr>"


def save_html(target: str, data: dict, findings: dict) -> str:
    os.makedirs("output", exist_ok=True)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"output/report_{ts}.html"

    all_findings = []
    for items in findings.values():
        all_findings.extend(items)

    counts  = count_by_severity(all_findings)
    rows    = _finding_rows(all_findings)

    # Recon summary rows
    dns      = data.get("dns", {})
    http     = data.get("http", {})
    crawl    = data.get("crawl", {})
    ports    = data.get("ports", {})
    whois    = data.get("whois", {})
    subs     = data.get("subdomains", [])

    open_ports = []
    for host, protos in ports.items():
        for proto, port_data in protos.items():
            for port, info in port_data.items():
                open_ports.append(f"{port}/{proto} {info.get('service','')} {info.get('product','')}")

    summary_boxes = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        color = SEVERITY_COLORS[sev]
        summary_boxes += f"""
        <div style='display:inline-block;padding:1rem 2rem;margin:0.5rem;
                    border-radius:6px;background:{color};text-align:center;min-width:80px'>
          <div style='font-size:2.5rem;font-weight:bold'>{counts[sev]}</div>
          <div>{sev}</div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>VAPT Report — {target}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Segoe UI', monospace;
      background: #0f1117;
      color: #e0e0e0;
      padding: 2rem;
      line-height: 1.6;
    }}
    h1 {{ color: #00d4ff; font-size: 1.8rem; margin-bottom: 0.25rem; }}
    h2 {{
      color: #00d4ff;
      font-size: 1.1rem;
      margin: 2rem 0 0.75rem;
      padding-bottom: 4px;
      border-bottom: 1px solid #1e2a3a;
    }}
    .meta {{ color: #888; font-size: 0.9rem; margin-bottom: 1.5rem; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 0.5rem;
      font-size: 0.88rem;
    }}
    th {{
      background: #161d2e;
      color: #00d4ff;
      padding: 8px 10px;
      text-align: left;
      font-weight: 600;
    }}
    td {{
      padding: 7px 10px;
      border-bottom: 1px solid #1a2030;
      vertical-align: top;
    }}
    tr:hover td {{ background: #161d2e; }}
    .tag {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 3px;
      font-size: 0.75rem;
      font-weight: bold;
    }}
    .disclaimer {{
      margin-top: 3rem;
      padding: 1rem;
      border: 1px solid #1e2a3a;
      border-radius: 4px;
      color: #666;
      font-size: 0.8rem;
    }}
  </style>
</head>
<body>

<h1>VAPT Framework — Security Assessment Report</h1>
<div class="meta">
  <strong>Target:</strong> {target} &nbsp;|&nbsp;
  <strong>Date:</strong> {ts} &nbsp;|&nbsp;
  <strong>Tool:</strong> VAPT Framework v0.3
</div>

<h2>Executive Summary</h2>
<div>{summary_boxes}</div>
<p style="margin-top:1rem;color:#aaa;font-size:0.9rem">
  Total findings: {len(all_findings)} &nbsp;|&nbsp;
  Pages crawled: {len(crawl.get('pages_crawled',[]))} &nbsp;|&nbsp;
  Forms tested: {len(crawl.get('forms',[]))} &nbsp;|&nbsp;
  Subdomains: {len(subs)}
</p>

<h2>Reconnaissance Summary</h2>
<table>
  <tr><th>Item</th><th>Value</th></tr>
  <tr><td>A Records</td><td>{', '.join(dns.get('A',[]) or ['none'])}</td></tr>
  <tr><td>MX Records</td><td>{', '.join((dns.get('MX') or ['none'])[:3])}</td></tr>
  <tr><td>NS Records</td><td>{', '.join((dns.get('NS') or ['none'])[:3])}</td></tr>
  <tr><td>Server</td><td>{http.get('server','unknown')}</td></tr>
  <tr><td>Open Ports</td><td>{' | '.join(open_ports) or 'none detected'}</td></tr>
  <tr><td>Registrar</td><td>{whois.get('registrar','unknown')}</td></tr>
  <tr><td>Domain Created</td><td>{whois.get('created','unknown')}</td></tr>
  <tr><td>Domain Expires</td><td>{whois.get('expires','unknown')}</td></tr>
  <tr><td>Subdomains (crt.sh)</td><td>{', '.join(subs[:10]) or 'none found'}</td></tr>
  <tr><td>Links Discovered</td><td>{len(crawl.get('links_found',[]))}</td></tr>
  <tr><td>JS Files</td><td>{len(crawl.get('js_files',[]))}</td></tr>
  <tr><td>robots.txt Rules</td><td>{len(crawl.get('robots',[]))}</td></tr>
</table>

<h2>Vulnerability Findings</h2>
<table>
  <tr>
    <th>Severity</th>
    <th>Type</th>
    <th>Confidence</th>
    <th>Detail</th>
    <th>Location</th>
  </tr>
  {rows}
</table>

<h2>Manual Validation Recommendations</h2>
<table>
  <tr><th>Finding Type</th><th>Recommended Action</th></tr>
  <tr><td>SSTI (High/Critical)</td><td>Manually submit payload in browser, verify template evaluation in response source</td></tr>
  <tr><td>CORS Wildcard</td><td>Test with authenticated session — check if sensitive data exposed cross-origin</td></tr>
  <tr><td>CVE Match</td><td>Verify exact version matches CVE affected range before reporting</td></tr>
  <tr><td>XSS Reflected</td><td>Confirm payload executes in browser without WAF blocking</td></tr>
  <tr><td>SQLi Error</td><td>Use sqlmap to confirm and determine database type</td></tr>
</table>

<div class="disclaimer">
  This report was generated by an automated tool for authorized security testing only.
  All findings require manual validation before being reported as confirmed vulnerabilities.
  Unauthorized use of this tool or its findings is illegal.
</div>

</body>
</html>"""

    with open(path, "w") as f:
        f.write(html)

    return path