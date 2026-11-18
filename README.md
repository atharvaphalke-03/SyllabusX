# SyllabusX – Interactive Kali Linux Ethical Hacking Toolkit

A **menu-driven Python command-line toolkit** that organises the standard ethical-hacking workflow into eight phases, from reconnaissance to reporting. It wraps well-known Kali Linux tools (Nmap, WHOIS, dig, OpenSSL, smbclient, enum4linux-ng) behind one consistent interface, shows their **real output**, and can save every result to a timestamped report.

> **Safe by design:** SyllabusX performs reconnaissance, scanning, enumeration and analysis only. It contains **no exploitation, password cracking or guessing, stealth, persistence or denial-of-service functions**, and every active check requires an explicit authorization confirmation.

**Version:** 0.4.0 · **Language:** Python 3 (standard library only) · **Platform:** Kali Linux (works on any Linux with the tools installed)

---

## Table of Contents

1. [Features](#features)
2. [Requirements](#requirements)
3. [Installation and Quick Start](#installation-and-quick-start)
4. [How It Works](#how-it-works)
5. [Phases and Tools](#phases-and-tools)
6. [Authorization and Safety Model](#authorization-and-safety-model)
7. [Reports](#reports)
8. [Project Structure](#project-structure)
9. [Behaviour When Tools Are Missing](#behaviour-when-tools-are-missing)
10. [Limitations](#limitations)
11. [Roadmap](#roadmap)
12. [Skills Demonstrated](#skills-demonstrated)
13. [Legal Disclaimer](#legal-disclaimer)

---

## Features

* **8 phases, 34 tools** covering the full authorized-testing lifecycle
* **No third-party Python packages**: only the standard library
* **Input validation** for hostnames, IP addresses, URLs, ports and file paths
* **Authorization gate**: active network checks need you to type `AUTHORIZED`
* **Graceful degradation**: missing tools are reported, not crashed on, and many checks fall back to pure-Python implementations
* **Timeouts on every external command** so a hung tool cannot freeze the menu
* **Optional report saving** to `reports/` with timestamped file names
* **Report analysis**: triage, compare baseline vs. retest, extract findings, and generate a consolidated summary
* **Offline utilities**: password-strength estimate and hash identification never send data anywhere

---

## Requirements

* Python **3.8+**
* Recommended Kali / Debian packages:

```bash
sudo apt update
sudo apt install python3 whois dnsutils curl openssl nmap
```

Optional tools that unlock extra features:

```bash
sudo apt install smbclient whatweb
# enum4linux-ng and SpiderFoot: install from the official Kali package or project page
```

---

## Installation and Quick Start

```bash
git clone https://github.com/<your-username>/SyllabusX.git
cd SyllabusX
python3 -m syllabusx
```

The toolkit starts directly at the main menu:

```text
╔══════════════════════════════════════════════════════════╗
║                         SYLLABUSX                        ║
║              Kali Linux Ethical Hacking Toolkit          ║
╚══════════════════════════════════════════════════════════╝

[1] Information Gathering
[2] Network Scanning
[3] Enumeration
[4] Vulnerability Analysis
[5] Web Security Testing
[6] Password and Authentication Security
[7] Cryptography and File Integrity
[8] Reporting and Analysis
[0] Exit
```

Run it from the folder where you want the `reports/` directory to be created.

---

## How It Works

1. Choose a **phase** from the main menu.
2. Choose a **tool** inside that phase.
3. Enter the target, URL, file or value when prompted. Input is validated first.
4. For active checks, **confirm authorization** by typing `AUTHORIZED`.
5. Read the real output, optionally **save it to `reports/`**, then return to the tool menu or main menu.

`Ctrl+C` during a tool cancels it and returns to the phase menu. `0` always goes back one level.

---

## Phases and Tools

### Phase 1 – Information Gathering (passive / low-impact)

| # | Tool | What it does |
| --- | --- | --- |
| 1 | WHOIS lookup | Registration data for a domain or IP (`whois`) |
| 2 | DNS record lookup | A, AAAA, MX, NS, TXT, CNAME or SOA records (`dig`, falls back to `nslookup`, then Python) |
| 3 | Reverse DNS lookup | Hostname for an IP address |
| 4 | HTTP response headers | Headers via `curl` (follows up to 3 redirects) or a built-in HTTP client |
| 5 | TLS certificate inspection | Handshake and certificate details via `openssl`, or Python `ssl` as fallback |
| 6 | Web technology hints | Reads `Server`, `X-Powered-By`, `X-Generator` and `Via` headers (clearly labelled as hints, not proof) |
| 7 | SpiderFoot guidance | Detects SpiderFoot and shows how to launch it locally; does not run it for you |

### Phase 2 – Network Scanning (active, requires authorization)

| # | Tool | Nmap options used |
| --- | --- | --- |
| 1 | Host discovery | `-sn` |
| 2 | Common TCP ports | `-T3 --top-ports 100` |
| 3 | Service / version detection | `-sV -T3 --top-ports 100` |
| 4 | Service scan + XML output | `-sV -T3 --top-ports 100 -oX reports/<target>_nmap.xml` |

### Phase 3 – Enumeration

| # | Tool | Notes |
| --- | --- | --- |
| 1 | DNS enumeration | A, AAAA, MX, NS, TXT and SOA in one pass (no authorization prompt, as it is ordinary DNS querying) |
| 2 | Nmap service / script enumeration | `-sV -sC -T3 --top-ports 100`, requires authorization |
| 3 | SMB share listing | `smbclient -L` with anonymous (`-N`) access, requires authorization |
| 4 | SMB / RPC enumeration | `enum4linux-ng -A` (or `enum4linux -a`), requires authorization |

### Phase 4 – Vulnerability Analysis

| # | Tool | Notes |
| --- | --- | --- |
| 1 | Import / parse Nmap XML or read a report | Summarises hosts, open ports, services and script output from Nmap XML; shows text, CSV or HTML exports (OpenVAS, Nessus) as plain text |
| 2 | Nmap `vuln` category checks | `-sV -T3 --script vuln --top-ports 50`, requires authorization. **Detects only; does not exploit** |
| 3 | Report keyword triage | Lists lines mentioning severity, CVEs, findings or risk (up to 300) |

### Phase 5 – Web Security Testing (non-exploit checks)

| # | Tool | What it does |
| --- | --- | --- |
| 1 | HTTP headers | Status code, final URL and all response headers |
| 2 | Security header review | Checks for `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` and `Permissions-Policy` |
| 3 | TLS configuration / certificate review | Same engine as Phase 1, saved as a web review |
| 4 | robots.txt review | Retrieves and displays the first 12,000 characters |

### Phase 6 – Password and Authentication Security (defensive utilities)

| # | Tool | What it does |
| --- | --- | --- |
| 1 | Offline password-strength estimate | Heuristic score out of 100 based on length, character groups, common words and repeats. Input is hidden (`getpass`), never printed, saved or transmitted |
| 2 | Hash format identification | Guesses MD5, SHA-1, SHA-256/384/512, bcrypt, Argon2, yescrypt and Unix crypt formats by pattern |
| 3 | Local Linux password-policy review | Read-only look at `/etc/login.defs`, `pwquality.conf` and `common-password` |

No password guessing, cracking or brute-forcing is included.

### Phase 7 – Cryptography and File Integrity

| # | Tool | What it does |
| --- | --- | --- |
| 1 | Calculate SHA-256 | Streams the file in 1 MB chunks, so large files are fine |
| 2 | Verify file SHA-256 | Compares against an expected digest and reports `MATCH` or `MISMATCH` |
| 3 | Inspect X.509 certificate | Subject, issuer, validity dates, serial and SHA-256 fingerprint via `openssl x509` |
| 4 | Local file metadata | Absolute path, size, modified time, readable / executable flags |

### Phase 8 – Reporting and Analysis

| # | Tool | What it does |
| --- | --- | --- |
| 1 | List saved report history | Newest-first listing of everything in `reports/` |
| 2 | Summarize / triage a report | Counts of Critical, High, Medium, Low, Informational, CVE references and finding keywords, plus excerpts |
| 3 | Compare baseline and retest reports | Unified diff of two reports (first 500 lines) |
| 4 | Extract potential finding lines | Pulls lines with CVEs, severities and exposure keywords |
| 5 | Generate consolidated report summary | Writes a Markdown index of every saved report to `reports/` |

---

## Authorization and Safety Model

* **Authorization gate.** Active checks (Nmap scans, service enumeration, SMB and RPC enumeration, Nmap `vuln` scripts) show the target and require you to type `AUTHORIZED` exactly. Anything else cancels the action.
* **A prompt is not permission.** The confirmation is a safeguard against accidents. It is **not** proof that you are allowed to test the target. Always obtain written authorization first.
* **Conservative scan profiles.** Nmap runs at timing `-T3` and limits itself to the top 50 to 100 ports.
* **No offensive capability.** There are no exploit modules, password attacks, evasion techniques, persistence or denial-of-service functions.
* **Honest reporting.** Every analysis output ends with a limitation note: imported results are not independently verified, header checks show presence only, and keyword triage can double-count or miss findings.
* **Input validation.** Hostnames, IPs, URLs and ports are validated before any command runs, and commands are executed as argument lists (never through a shell), which prevents shell injection through user input.

---

## Reports

When a tool finishes, you are asked **`Save output to reports/? [y/N]`**. Saved files are named:

```text
reports/YYYYMMDD_HHMMSS_<tool_name>.txt
```

Each file contains the tool name, the input, a timestamp and the full output:

```text
SYLLABUSX REPORT
Tool: SHA-256 File Hash
Input: /home/kali/evidence.bin
Generated: 2026-11-18T12:30:00

File: /home/kali/evidence.bin
Size: 5 bytes
SHA-256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
```

Phase 2 option 4 additionally writes Nmap XML to `reports/<target>_nmap.xml`, which Phase 4 can parse later. The `reports/` folder is listed in `.gitignore` so scan results for real targets are not committed by accident.

---

## Project Structure

```text
SyllabusX/
├── syllabusx/
│   ├── __init__.py     # package version (0.4.0) and main() export
│   ├── __main__.py     # enables `python3 -m syllabusx`
│   └── cli.py          # menus, validation, tool wrappers, report handling
├── .gitignore
└── README.md
```

The tool catalogue is a single `PHASES` dictionary in `cli.py`, mapping each phase to a list of `(name, function)` pairs. To add a tool, write a function and add one entry to that list.

---

## Behaviour When Tools Are Missing

SyllabusX checks for every external program before running it and tells you what to install instead of crashing:

```text
[Tool unavailable] 'nmap' is not installed. Install it or select another tool.
```

| Missing tool | Fallback |
| --- | --- |
| `dig` | `nslookup`, then Python's resolver for A and AAAA records |
| `curl` | Built-in Python HTTP client |
| `openssl` | Python `ssl` module for live TLS inspection |
| `nmap`, `whois`, `smbclient`, `enum4linux-ng` | Clear install message |

---

## Limitations

* Designed for **Linux / Kali**. The password-policy review reads Linux files, and the external tools are Linux-oriented.
* Results are only as good as the underlying tools. SyllabusX displays their output; it does not interpret or validate vulnerabilities.
* Report triage and finding extraction are **keyword-based** and can produce false positives and false negatives.
* The password-strength score is a simple heuristic, not a breach check.
* Hash identification is by pattern and length only, and formats can overlap.
* Scans are intentionally limited to common ports; this is a learning and assessment aid, not a full scanner.
* Tool options may differ across Kali versions.

---

## Roadmap

- [ ] Command-line arguments (`argparse`) for non-interactive and scripted use
- [ ] Automated tests for validators, parsers and report functions
- [ ] Scope file support (allowed targets) as a stronger authorization control
- [ ] JSON and HTML report export
- [ ] Nmap XML to Markdown findings table
- [ ] Configurable scan profiles (ports, timing)
- [ ] Packaging with `pyproject.toml` and a `syllabusx` console command
- [ ] Logging of every active action for an audit trail

---

## Skills Demonstrated

**Python:** modular CLI design, subprocess handling, regular expressions, XML parsing, file I/O, exception handling, input validation

**Security:** penetration-testing methodology, reconnaissance and enumeration, vulnerability triage, TLS and header review, file integrity and hashing, secure coding (no shell injection, timeouts, safe defaults)

**Tools:** Nmap, WHOIS, dig, OpenSSL, curl, smbclient, enum4linux-ng, Kali Linux

**Practices:** responsible disclosure mindset, authorization-first design, reporting and documentation

---

## Legal Disclaimer

SyllabusX is developed for **education and authorized security testing only**. Use it only on systems and networks that you **own** or for which you have **explicit written permission** to test. Unauthorized scanning or access may be illegal in your jurisdiction. The author accepts no liability for misuse or damage resulting from the use of this software.
