# 🔍 Recon-VAPT Framework

A Python-based **Web Attack Surface Mapping and Vulnerability Assessment Framework** designed to automate reconnaissance, attack surface discovery, vulnerability analysis, and professional report generation for authorized security assessments.

> ⚠️ **Disclaimer:** This tool is intended for educational purposes and authorized security testing only. Do **NOT** scan systems without explicit permission.

---

## 🚀 Features

### 🌐 Reconnaissance

* DNS Enumeration (A, AAAA, MX, TXT, NS)
* HTTP Fingerprinting
* Technology Detection
* WHOIS Lookup
* Certificate Transparency Enumeration
* Port Scanning using Nmap

### 🕸️ Attack Surface Discovery

* Website Crawling
* `robots.txt` Analysis
* `sitemap.xml` Parsing
* Form Discovery
* JavaScript File Extraction

### 🛡️ Vulnerability Assessment

* Security Header Analysis
* CORS Misconfiguration Detection
* Injection Testing (SQLi, XSS, SSTI)
* SSRF/Open Redirect Checks
* CVE Matching using NVD

### 📊 Reporting

* JSON Report Generation
* Professional HTML Report Generation

---

## 🏗️ Project Architecture

```text
Target URL
    ↓
Reconnaissance Phase
(DNS • HTTP Fingerprinting • Port Scan • WHOIS)
    ↓
Attack Surface Discovery
(Crawler • Forms • JS Files • robots.txt • Sitemap)
    ↓
Vulnerability Analysis
(Security Headers • CORS • Injection • SSRF • CVEs)
    ↓
Report Generation
(JSON + HTML Reports)
```

---

## 🛠️ Tech Stack

* **Language:** Python 3.13
* **CLI:** Typer
* **Async Networking:** HTTPX, Asyncio
* **Web Parsing:** BeautifulSoup4
* **Port Scanning:** Nmap (`python-nmap`)
* **Reporting:** Rich, HTML, JSON
* **Configuration:** YAML

---

## 📁 Project Structure

```text
recon-vapt-framework/
├── core/
├── recon/
│   ├── dns.py
│   ├── http_fingerprint.py
│   ├── crawler.py
│   ├── port_scan.py
│   ├── cert_whois.py
│   └── vuln/
│       ├── headers.py
│       ├── cors.py
│       ├── injection.py
│       ├── ssrf.py
│       └── cve_lookup.py
├── reporting/
│   ├── json_report.py
│   └── html_report.py
├── output/
├── main.py
├── config.yaml
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation

### Clone the repository

```bash
git clone https://github.com/HarshLOK/recon-vapt-framework.git
cd recon-vapt-framework
```

### Create a virtual environment

#### Linux / WSL

```bash
python -m venv .venv
source .venv/bin/activate
```

#### Windows

```powershell
python -m venv .venv
.venv\Scripts\activate
```

### Install dependencies

```bash
pip install -r requirements.txt
```

---

## 🚀 Usage

### Basic Scan

```bash
python main.py --target https://example.com
```

### Example

```bash
python main.py --target https://owasp.org
```

---

## 📸 Screenshots

### CLI Scan Output

Displays reconnaissance results, attack surface discovery, and vulnerability findings.

![CLI Scan](images/cli_scan.png)

### HTML Report

Professional HTML report generated after the assessment.

![HTML Report](images/html_report.png)

---

## ✅ Implemented Modules

### Phase 1 – Reconnaissance

* DNS Reconnaissance
* HTTP Fingerprinting
* Target Validation
* Permission Checks

### Phase 2 – Attack Surface Mapping

* Website Crawling
* Form Discovery
* `robots.txt` Parsing
* Sitemap Analysis
* Port Scanning
* WHOIS & Certificate Transparency

### Phase 3 – Vulnerability Assessment

* Security Header Analysis
* CORS Analysis
* Injection Testing
* SSRF/Open Redirect Detection
* CVE Matching

---

## 🔮 Future Improvements

* Playwright-based JavaScript Rendering
* Directory & File Exposure Detection
* Subdomain Enumeration (Subfinder / Amass)
* Nuclei Integration
* PDF Report Generation
* Streamlit Dashboard

---

## 📚 Learning Outcomes

Through this project, I gained hands-on experience with:

* Web Application Reconnaissance
* OWASP Top 10 Security Concepts
* Python Asynchronous Programming
* Secure Coding Practices
* Vulnerability Detection Logic
* Security Report Generation
* Git & GitHub Workflow

---

## ⚖️ Legal Disclaimer

This tool must only be used against systems you own or have **explicit written authorization** to assess.

The author assumes **no responsibility or liability** for misuse of this software.

---

## 👨‍💻 Author

**Harsh Singh**

* GitHub: https://github.com/HarshLOK

---

⭐ If you found this project interesting, consider giving it a star!

