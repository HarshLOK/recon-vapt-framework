# Automated Web Attack Surface & Security Assessment Platform

A Python-based reconnaissance and vulnerability assessment framework designed to automate web application attack surface mapping and basic security analysis.

## Features

### Reconnaissance

* DNS Enumeration (A, AAAA, MX, TXT, NS)
* HTTP Fingerprinting
* Technology Detection
* WHOIS Lookup
* Certificate Transparency Enumeration
* Port Scanning using Nmap

### Attack Surface Discovery

* Website Crawling
* robots.txt Analysis
* sitemap.xml Parsing
* Form Discovery
* JavaScript File Extraction

### Vulnerability Analysis

* Security Header Analysis
* CORS Misconfiguration Detection
* Injection Testing (SQLi, XSS, SSTI)
* SSRF/Open Redirect Checks
* CVE Matching using NVD

### Reporting

* JSON Reports
* HTML Reports

## Tech Stack

* Python 3.13
* Asyncio
* HTTPX
* BeautifulSoup4
* Nmap
* Rich
* Typer

## Installation

```bash
git clone https://github.com/HarshLOK/recon-vapt-framework.git
cd recon-vapt-framework
pip install -r requirements.txt
```

## Usage

```bash
python main.py --target https://example.com
```

## Legal Disclaimer

Use this tool only on systems you own or have explicit written permission to test.

Unauthorized scanning is illegal.

## Author

Harsh Singh
