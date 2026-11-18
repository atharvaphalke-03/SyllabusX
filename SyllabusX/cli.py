import csv
import hashlib
import ipaddress
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

REPORT_DIR = Path("reports")

def banner():
    print(r"""
╔══════════════════════════════════════════════════════════╗
║                         SYLLABUSX                        ║
║              Kali Linux Ethical Hacking Toolkit          ║
╚══════════════════════════════════════════════════════════╝
""")

def pause():
    input("\nPress Enter to continue...")

def ask(prompt, default=""):
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or default

def run_cmd(args, timeout=45):
    if not shutil.which(args[0]):
        return f"[Tool unavailable] '{args[0]}' is not installed. Install it or select another tool."
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        out = (p.stdout or "").strip()
        err = (p.stderr or "").strip()
        if err:
            out = (out + "\n" + err).strip()
        return out or f"(Command completed with exit code {p.returncode}; no output.)"
    except subprocess.TimeoutExpired:
        return "[Timeout] Command exceeded its time limit."
    except (OSError, ValueError) as exc:
        return f"[Execution error] {exc}"

def host_value(prompt="Domain or IP address"):
    raw = ask(prompt)
    if not raw:
        print("Input is required.")
        pause()
        return None
    if "://" in raw:
        raw = urlparse(raw).hostname or ""
    raw = raw.strip().rstrip(".")
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        if ":" in raw or len(raw) > 253 or not re.fullmatch(
            r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*",
            raw
        ):
            print("Invalid hostname/IP format.")
            pause()
            return None
        return raw

def url_value():
    raw = ask("Website URL (e.g. https://example.org)")
    if not raw:
        print("Input is required.")
        pause()
        return None
    if "://" not in raw:
        raw = "https://" + raw
    p = urlparse(raw)
    if p.scheme not in ("http", "https") or not p.hostname:
        print("Enter a valid http:// or https:// URL.")
        pause()
        return None
    try:
        # validate hostname syntax
        hostname = p.hostname
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            if not re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*", hostname):
                raise ValueError()
    except ValueError:
        print("Invalid URL hostname.")
        pause()
        return None
    return raw

def active_confirmation(target, action="active check"):
    print(f"\nAuthorization check: {action} against {target}")
    print("Continue only if you own the target or have explicit permission.")
    return ask("Type AUTHORIZED to continue", "") == "AUTHORIZED"

def save_result(title, target, output):
    print("\n" + "=" * 72)
    print(f"{title} | Input: {target}")
    print("=" * 72)
    print(output or "(No output returned.)")
    if ask("\nSave output to reports/? [y/N]", "N").lower() == "y":
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", title).strip("_") or "report"
        path = REPORT_DIR / f"{stamp}_{safe}.txt"
        path.write_text(
            f"SYLLABUSX REPORT\nTool: {title}\nInput: {target}\n"
            f"Generated: {datetime.now().isoformat(timespec='seconds')}\n\n{output}\n",
            encoding="utf-8"
        )
        print(f"[Saved] {path}")
    pause()

def ask_path(prompt="File path"):
    raw = ask(prompt)
    if not raw:
        print("A path is required.")
        pause()
        return None
    path = Path(raw).expanduser()
    if not path.is_file():
        print(f"File not found: {path}")
        pause()
        return None
    return path

def dns_command(host, record):
    if shutil.which("dig"):
        return run_cmd(["dig", "+time=3", "+tries=1", host, record], 12)
    if shutil.which("nslookup"):
        return run_cmd(["nslookup", "-type=" + record, host], 12)
    if record in ("A", "AAAA"):
        try:
            family = socket.AF_INET if record == "A" else socket.AF_INET6
            return "\n".join(sorted({x[4][0] for x in socket.getaddrinfo(host, None, family)}))
        except socket.gaierror as exc:
            return f"[DNS error] {exc}"
    return "Install dnsutils for dig/nslookup to query this record type."

# PHASE 1 — Information Gathering
def p1_whois():
    h = host_value()
    if h: save_result("WHOIS Lookup", h, run_cmd(["whois", h], 45))

def p1_dns():
    h = host_value()
    if not h: return
    record = ask("Record type (A/AAAA/MX/NS/TXT/CNAME/SOA)", "A").upper()
    if record not in {"A","AAAA","MX","NS","TXT","CNAME","SOA"}:
        print("Unsupported record type."); pause(); return
    save_result(f"DNS Lookup {record}", h, dns_command(h, record))

def p1_reverse():
    h = host_value("IP address")
    if not h: return
    try: ipaddress.ip_address(h)
    except ValueError: print("Reverse lookup requires an IP address."); pause(); return
    try:
        name, aliases, addresses = socket.gethostbyaddr(h)
        out = f"Name: {name}\nAliases: {aliases}\nAddresses: {addresses}"
    except (socket.herror, socket.gaierror) as exc: out = f"Lookup failed: {exc}"
    save_result("Reverse DNS", h, out)

def http_request(url, method="HEAD", timeout=12):
    headers = {"User-Agent": "SyllabusX/0.4 (authorized security learning)"}
    try:
        req = Request(url, headers=headers, method=method)
        with urlopen(req, timeout=timeout) as response:
            return response.status, response.geturl(), dict(response.headers.items()), response.read(4096).decode("utf-8", "replace")
    except HTTPError as exc:
        return exc.code, url, dict(exc.headers.items()), ""
    except (URLError, TimeoutError, OSError) as exc:
        return None, url, {}, f"[Request failed] {exc}"

def p1_headers():
    u = url_value()
    if not u: return
    if shutil.which("curl"):
        out = run_cmd(["curl", "-sSIL", "--max-time", "15", "--max-redirs", "3", u], 20)
    else:
        status, final, headers, body = http_request(u)
        out = f"Status: {status}\nFinal URL: {final}\n" + "\n".join(f"{k}: {v}" for k,v in headers.items())
        if status is None: out = body
    save_result("HTTP Headers", u, out)

def p1_tls():
    h = host_value("TLS hostname")
    if not h: return
    port = ask("Port", "443")
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        print("Port must be 1–65535."); pause(); return
    if shutil.which("openssl"):
        out = run_cmd(["openssl","s_client","-connect",f"{h}:{port}","-servername",h,"-brief"], 15)
    else:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((h,int(port)),timeout=8) as s:
                with ctx.wrap_socket(s,server_hostname=h) as t:
                    cert=t.getpeercert()
                    out=f"TLS: {t.version()}\nCipher: {t.cipher()}\nSubject: {cert.get('subject')}\nIssuer: {cert.get('issuer')}\nExpires: {cert.get('notAfter')}"
        except Exception as exc: out=f"TLS inspection failed: {exc}"
    save_result("TLS Certificate", f"{h}:{port}", out)

def p1_tech():
    u = url_value()
    if not u: return
    if shutil.which("curl"): out=run_cmd(["curl","-sSI","--max-time","15",u],20)
    else:
        status, final, headers, body=http_request(u)
        out=f"Status: {status}\n"+"\n".join(f"{k}: {v}" for k,v in headers.items()) if status is not None else body
    hints=[line for line in out.splitlines() if line.lower().startswith(("server:","x-powered-by:","x-generator:","via:"))]
    out += "\n\nTechnology-identifying header hints:\n"+("\n".join(hints) if hints else "No common hints found.")
    out += "\nThese headers are hints, not proof of the technology stack."
    save_result("Web Technology Hints",u,out)

def p1_spiderfoot():
    exe=shutil.which("spiderfoot") or shutil.which("sf.py")
    out=(f"SpiderFoot found: {exe}\nLaunch it manually and set scope in its own interface after checking authorization.\nSuggested local UI command: {exe} -l 127.0.0.1:5001" if exe else "SpiderFoot was not found in PATH. Install it from its official project if needed.")
    save_result("SpiderFoot Guidance","local tool",out)

# PHASE 2 — Network Scanning
def p2_nmap(mode):
    h=host_value("Target IP/hostname")
    if not h: return
    if not active_confirmation(h, "Nmap network scan"): print("Cancelled."); pause(); return
    if mode=="1": args=["nmap","-sn",h]
    elif mode=="2": args=["nmap","-T3","--top-ports","100",h]
    elif mode=="3": args=["nmap","-sV","-T3","--top-ports","100",h]
    else:
        REPORT_DIR.mkdir(parents=True,exist_ok=True)
        output_path=REPORT_DIR / (re.sub(r"[^A-Za-z0-9_.-]+","_",h)+"_nmap.xml")
        args=["nmap","-sV","-T3","--top-ports","100","-oX",str(output_path),h]
    out=run_cmd(args,180)
    if mode=="4": out += f"\n\nXML output path: {output_path}"
    save_result("Nmap "+{"1":"Host Discovery","2":"Common TCP Ports","3":"Service/Version Scan","4":"Service Scan + XML"}[mode],h,out)

# PHASE 3 — Enumeration
def p3_dns():
    h=host_value()
    if not h:return
    out="\n\n".join(f"===== {rec} =====\n{dns_command(h,rec)}" for rec in ("A","AAAA","MX","NS","TXT","SOA"))
    save_result("DNS Enumeration",h,out)

def p3_nmap():
    h=host_value("Authorized target IP/hostname")
    if not h:return
    if not active_confirmation(h,"service enumeration"): print("Cancelled.");pause();return
    save_result("Nmap Service Enumeration",h,run_cmd(["nmap","-sV","-sC","-T3","--top-ports","100",h],180))

def p3_smb():
    h=host_value("Authorized SMB server IP/hostname")
    if not h:return
    if not active_confirmation(h,"SMB share enumeration"): print("Cancelled.");pause();return
    if shutil.which("smbclient"):
        out=run_cmd(["smbclient","-L",f"//{h}/","-N"],45)
    else:
        out="smbclient is not installed. Install with: sudo apt install smbclient"
    save_result("SMB Share Listing",h,out)

def p3_enum4linux():
    h=host_value("Authorized target IP/hostname")
    if not h:return
    if not active_confirmation(h,"SMB/RPC enumeration"): print("Cancelled.");pause();return
    exe=shutil.which("enum4linux-ng") or shutil.which("enum4linux")
    if not exe: out="enum4linux-ng/enum4linux not found. Install from a trusted Kali package/source."
    elif Path(exe).name=="enum4linux-ng": out=run_cmd([exe,"-A",h],120)
    else: out=run_cmd([exe,"-a",h],120)
    save_result("SMB/RPC Enumeration",h,out)

# PHASE 4 — Vulnerability Analysis
def parse_nmap_xml(path):
    try:
        tree=ET.parse(path)
        root=tree.getroot()
        lines=[]
        for host in root.findall("host"):
            addr=host.find("address")
            hostname=host.find("./hostnames/hostname")
            ident=(addr.get("addr","unknown") if addr is not None else "unknown")
            if hostname is not None: ident += f" ({hostname.get('name','')})"
            lines.append(f"Host: {ident}")
            for port in host.findall("./ports/port"):
                state=port.find("state")
                if state is not None and state.get("state")=="open":
                    svc=port.find("service")
                    desc=f"{port.get('protocol')}/{port.get('portid')} open"
                    if svc is not None: desc += f" — {svc.get('name','')} {svc.get('product','')} {svc.get('version','')}".rstrip()
                    lines.append("  "+desc)
                    for script in port.findall("script"):
                        lines.append(f"    Script {script.get('id')}: {script.get('output','')}")
        return "\n".join(lines) if lines else "No open ports/host entries were found in this XML."
    except (ET.ParseError, OSError) as exc: return f"Could not parse Nmap XML: {exc}"

def p4_import():
    path=ask_path("Path to Nmap XML, Nessus/OpenVAS export, or text report")
    if not path:return
    if path.suffix.lower()==".xml":
        out=parse_nmap_xml(path)
    else:
        try:
            out=path.read_text(encoding="utf-8",errors="replace")[:200000]
            if path.suffix.lower()==".csv":
                out="CSV preview (first 200 KB):\n"+out
            elif path.suffix.lower() in {".html",".htm"}:
                out=re.sub(r"(?is)<(script|style).*?>.*?</\1>"," ",out)
                out=re.sub(r"(?s)<[^>]+>"," ",out)
                out=re.sub(r"\s+"," ",out)
        except OSError as exc: out=f"Read failed: {exc}"
    out += "\n\nNote: imported results are not independently verified by SyllabusX."
    save_result("Imported Vulnerability/Scan Report",str(path),out)

def p4_nmap_vuln():
    h=host_value("Authorized target IP/hostname")
    if not h:return
    print("This runs Nmap NSE scripts in the 'vuln' category. Review scope and impact first.")
    if not active_confirmation(h,"Nmap vulnerability-script checks"): print("Cancelled.");pause();return
    out=run_cmd(["nmap","-sV","-T3","--script","vuln","--top-ports","50",h],180)
    save_result("Nmap Vulnerability Checks",h,out)

def p4_report_text():
    path=ask_path("Path to text/CSV/HTML vulnerability report")
    if not path:return
    try:
        data=path.read_text(encoding="utf-8",errors="replace")[:200000]
        if path.suffix.lower() in {".html",".htm"}:
            data=re.sub(r"(?is)<(script|style).*?>.*?</\1>"," ",data)
            data=re.sub(r"(?s)<[^>]+>"," ",data)
            data=re.sub(r"\s+"," ",data)
        lines=data.splitlines()
        matches=[(i+1,line.strip()) for i,line in enumerate(lines) if re.search(r"critical|high|medium|low|severity|cve-|vulnerability|finding|risk",line,re.I)]
        out="\n".join(f"Line {i}: {line[:500]}" for i,line in matches[:300]) or "No common finding/severity keywords detected."
        out += "\n\nThis is keyword triage only, not a validated vulnerability assessment."
    except OSError as exc: out=f"Read failed: {exc}"
    save_result("Report Keyword Triage",str(path),out)

# PHASE 5 — Web Security Testing (non-exploit checks)
SEC_HEADERS=("Content-Security-Policy","Strict-Transport-Security","X-Content-Type-Options","X-Frame-Options","Referrer-Policy","Permissions-Policy")
def p5_headers():
    u=url_value()
    if not u:return
    status,final,headers,body=http_request(u)
    if status is None: out=body
    else:
        out=f"HTTP status: {status}\nFinal URL: {final}\n\nResponse headers:\n"+"\n".join(f"{k}: {v}" for k,v in headers.items())
    save_result("Web Header Inspection",u,out)

def p5_security_headers():
    u=url_value()
    if not u:return
    status,final,headers,body=http_request(u)
    if status is None: out=body
    else:
        lowered={k.lower():v for k,v in headers.items()}
        rows=[f"HTTP status: {status}",f"Final URL: {final}",""]
        for name in SEC_HEADERS:
            value=lowered.get(name.lower())
            rows.append(f"{name}: {value if value else 'NOT PRESENT (review applicability)'}")
        rows.append("\nAutomated presence check only; absence does not by itself prove a vulnerability.")
        out="\n".join(rows)
    save_result("Security Header Review",u,out)

def p5_robots():
    u=url_value()
    if not u:return
    base=urlparse(u)
    robots=f"{base.scheme}://{base.netloc}/robots.txt"
    status,final,headers,body=http_request(robots,"GET")
    save_result("robots.txt Review",robots,f"HTTP status: {status}\nFinal URL: {final}\n\n{body[:12000]}")

def p5_tls():
    h=host_value("TLS hostname")
    if not h:return
    port=ask("Port","443")
    if not port.isdigit() or not 1<=int(port)<=65535: print("Invalid port.");pause();return
    if shutil.which("openssl"):
        out=run_cmd(["openssl","s_client","-connect",f"{h}:{port}","-servername",h,"-brief"],15)
    else:
        try:
            ctx=ssl.create_default_context()
            with socket.create_connection((h,int(port)),timeout=8) as sock:
                with ctx.wrap_socket(sock,server_hostname=h) as tls:
                    cert=tls.getpeercert()
                    out=f"TLS: {tls.version()}\nCipher: {tls.cipher()}\nSubject: {cert.get('subject')}\nIssuer: {cert.get('issuer')}\nExpires: {cert.get('notAfter')}"
        except Exception as exc: out=f"TLS inspection failed: {exc}"
    save_result("Web TLS Review",f"{h}:{port}",out)

# PHASE 6 — Password/authentication safety utilities
def p6_strength():
    print("Offline password-strength estimate. Input is hidden and is never transmitted or saved.")
    import getpass
    try: pw=getpass.getpass("Enter sample password (leave blank to cancel): ")
    except (EOFError,KeyboardInterrupt): print("Cancelled.");pause();return
    if not pw: print("Cancelled.");pause();return
    classes=sum([bool(re.search(r"[a-z]",pw)),bool(re.search(r"[A-Z]",pw)),bool(re.search(r"\d",pw)),bool(re.search(r"[^A-Za-z0-9]",pw))])
    score=0
    score += min(len(pw)*4,40)
    if classes>=2: score+=10
    if classes>=3: score+=15
    if classes==4: score+=10
    if len(pw)>=16: score+=15
    if len(pw)<8: score-=20
    if re.search(r"(password|qwerty|admin|letmein|welcome|123456|iloveyou)",pw,re.I): score-=30
    if re.search(r"(.)\1{2,}",pw): score-=10
    score=max(0,min(100,score))
    label="Weak" if score<35 else "Moderate" if score<65 else "Stronger (heuristic only)"
    out=f"Length: {len(pw)} characters\nCharacter groups present: {classes}/4\nHeuristic score: {score}/100\nAssessment: {label}\n\nThis is a simple offline heuristic, not a breach check or guarantee. Do not enter a real password if you are uncomfortable doing so."
    pw=None
    save_result("Offline Password Strength Estimate","local input",out)

def p6_hash_identify():
    value=ask("Paste hash value (not a password)")
    if not value: print("Input required.");pause();return
    v=value.strip()
    if re.fullmatch(r"[a-fA-F0-9]{32}",v): guess="MD5 or another 128-bit hex digest"
    elif re.fullmatch(r"[a-fA-F0-9]{40}",v): guess="SHA-1 or another 160-bit hex digest"
    elif re.fullmatch(r"[a-fA-F0-9]{64}",v): guess="SHA-256 or another 256-bit hex digest"
    elif re.fullmatch(r"[a-fA-F0-9]{96}",v): guess="SHA-384 or another 384-bit hex digest"
    elif re.fullmatch(r"[a-fA-F0-9]{128}",v): guess="SHA-512 or another 512-bit hex digest"
    elif v.startswith(("$2a$","$2b$","$2y$")): guess="bcrypt password hash format"
    elif v.startswith("$argon2"): guess="Argon2 password hash format"
    elif v.startswith("$6$"): guess="Unix SHA-512 crypt format"
    elif v.startswith("$5$"): guess="Unix SHA-256 crypt format"
    elif v.startswith("$y$"): guess="yescrypt format (common on modern Linux)"
    else: guess="Unknown format from this simple heuristic"
    save_result("Hash Format Identification","local input",f"Likely format: {guess}\nThis is heuristic only; formats can overlap and a hash cannot reliably be identified by length alone.")

def p6_policy():
    candidates=[Path("/etc/login.defs"),Path("/etc/security/pwquality.conf"),Path("/etc/pam.d/common-password")]
    parts=[]
    for p in candidates:
        if p.is_file():
            try:
                lines=p.read_text(encoding="utf-8",errors="replace").splitlines()
                filtered=[line for line in lines if line.strip() and not line.lstrip().startswith("#") and re.search(r"PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|minlen|difok|retry|pam_pwquality|pam_pwhistory",line,re.I)]
                parts.append(f"--- {p} ---\n"+("\n".join(filtered) if filtered else "No matching active settings found."))
            except OSError as exc: parts.append(f"{p}: read error {exc}")
    out="\n\n".join(parts) if parts else "No standard password policy files were readable on this system."
    out += "\n\nRead-only local configuration inspection; it does not change policy."
    save_result("Local Password Policy Review","local system",out)

# PHASE 7 — Cryptography and File Integrity
def p7_sha():
    path=ask_path("File to hash")
    if not path:return
    try:
        digest=hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda:f.read(1024*1024),b""): digest.update(chunk)
        out=f"File: {path}\nSize: {path.stat().st_size} bytes\nSHA-256: {digest.hexdigest()}"
    except OSError as exc: out=f"Hashing failed: {exc}"
    save_result("SHA-256 File Hash",str(path),out)

def p7_verify():
    path=ask_path("File to verify")
    if not path:return
    expected=ask("Expected SHA-256 digest").lower().strip()
    if not re.fullmatch(r"[a-f0-9]{64}",expected):
        print("Expected value must be exactly 64 hexadecimal characters.");pause();return
    try:
        digest=hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda:f.read(1024*1024),b""): digest.update(chunk)
        actual=digest.hexdigest()
        out=f"Expected: {expected}\nActual:   {actual}\nResult:   {'MATCH' if actual==expected else 'MISMATCH'}"
    except OSError as exc: out=f"Verification failed: {exc}"
    save_result("SHA-256 Verification",str(path),out)

def p7_openssl_cert():
    path=ask_path("Certificate file (PEM/CRT)")
    if not path:return
    if shutil.which("openssl"):
        out=run_cmd(["openssl","x509","-in",str(path),"-noout","-subject","-issuer","-dates","-serial","-fingerprint","-sha256"],20)
    else:
        out="OpenSSL is not installed. Install it with: sudo apt install openssl"
    save_result("Certificate Details",str(path),out)

def p7_file_info():
    path=ask_path("File path")
    if not path:return
    try:
        st=path.stat()
        out=f"Path: {path.resolve()}\nSize: {st.st_size} bytes\nModified: {datetime.fromtimestamp(st.st_mtime).isoformat(timespec='seconds')}\nReadable: {os.access(path,os.R_OK)}\nExecutable: {os.access(path,os.X_OK)}"
    except OSError as exc: out=f"File inspection failed: {exc}"
    save_result("Local File Metadata",str(path),out)


# PHASE 8 — Reporting and Analysis
def p8_list_reports():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    files = sorted([p for p in REPORT_DIR.iterdir() if p.is_file()], key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        out = "No saved reports found yet. Run a tool and choose to save its output first."
    else:
        rows = []
        for p in files[:100]:
            try:
                st = p.stat()
                rows.append(f"{p.name} | {st.st_size} bytes | modified {datetime.fromtimestamp(st.st_mtime).isoformat(timespec='seconds')}")
            except OSError:
                rows.append(p.name)
        out = "Saved reports (newest first):\n" + "\n".join(rows)
    save_result("Saved Report History", str(REPORT_DIR.resolve()), out)

def p8_summarize_report():
    path = ask_path("Path to report file")
    if not path:
        return
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")[:500000]
        lines = raw.splitlines()
        patterns = {
            "Critical": re.compile(r"\bcritical\b", re.I),
            "High": re.compile(r"\bhigh\b", re.I),
            "Medium": re.compile(r"\bmedium\b", re.I),
            "Low": re.compile(r"\blow\b", re.I),
            "Informational": re.compile(r"\b(info|informational)\b", re.I),
            "CVE references": re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I),
            "Potential findings": re.compile(r"\b(vulnerability|finding|risk|exposure|misconfiguration|open port)\b", re.I),
        }
        counts = {label: sum(len(rx.findall(line)) for line in lines) for label, rx in patterns.items()}
        excerpts = []
        for idx, line in enumerate(lines, 1):
            if re.search(r"\b(critical|high|medium|low|CVE-\d{4}-\d{4,}|vulnerability|finding|misconfiguration)\b", line, re.I):
                excerpts.append(f"Line {idx}: {line.strip()[:300]}")
        out = f"File: {path}\nLines: {len(lines)}\nCharacters analyzed: {len(raw)}\n\nKeyword counts (heuristic, not validated severity counts):\n"
        out += "\n".join(f"- {k}: {v}" for k, v in counts.items())
        out += "\n\nRelevant excerpts:\n" + ("\n".join(excerpts[:80]) if excerpts else "No common finding keywords detected.")
        out += "\n\nLimitations: this is keyword-based triage. It may double-count terms, miss findings, or misread context; verify results in the original scanner report."
    except OSError as exc:
        out = f"Could not read report: {exc}"
    save_result("Report Summary and Triage", str(path), out)

def p8_compare_reports():
    print("Compare two saved reports or scan outputs. This compares text only; it does not prove a vulnerability was fixed.")
    first = ask_path("Path to earlier/baseline report")
    if not first:
        return
    second = ask_path("Path to later/retest report")
    if not second:
        return
    try:
        import difflib
        a = first.read_text(encoding="utf-8", errors="replace").splitlines()
        b = second.read_text(encoding="utf-8", errors="replace").splitlines()
        diff = list(difflib.unified_diff(a, b, fromfile=str(first), tofile=str(second), lineterm=""))
        out = "\n".join(diff[:500]) if diff else "No textual differences found."
        out += "\n\nInterpretation: review changed target scope, tool versions, scan options, and timestamps before concluding that a finding is resolved."
    except OSError as exc:
        out = f"Could not compare reports: {exc}"
    save_result("Baseline vs Retest Comparison", f"{first} -> {second}", out)

def p8_extract_findings():
    path = ask_path("Path to scanner/report output")
    if not path:
        return
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")[:500000]
        lines = raw.splitlines()
        keywords = re.compile(r"\b(CVE-\d{4}-\d{4,}|critical|high|medium|low|vulnerability|misconfiguration|finding|exposed|open port|certificate expired)\b", re.I)
        selected = []
        for idx, line in enumerate(lines, 1):
            if keywords.search(line):
                selected.append(f"{idx}: {line.strip()[:400]}")
        out = "Potential finding-related lines:\n" + ("\n".join(selected[:300]) if selected else "No matching lines found.")
        out += "\n\nThis extraction is a review aid only; it does not validate severity or exploitability."
    except OSError as exc:
        out = f"Could not read report: {exc}"
    save_result("Potential Finding Extraction", str(path), out)

def p8_generate_summary():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    reports = sorted([p for p in REPORT_DIR.iterdir() if p.is_file() and p.suffix.lower() not in {".png", ".jpg", ".jpeg"}])
    if not reports:
        save_result("Consolidated Report Summary", str(REPORT_DIR.resolve()), "No saved reports found. Save tool outputs first.")
        return
    rows = [
        "# SyllabusX Consolidated Report Summary",
        f"Generated: {datetime.now().isoformat(timespec='seconds')}",
        f"Report directory: {REPORT_DIR.resolve()}",
        "",
        "## Included files",
    ]
    for p in reports:
        try:
            text_content = p.read_text(encoding="utf-8", errors="replace")[:200000]
            lines = text_content.splitlines()
            keywords = sum(1 for line in lines if re.search(r"\b(CVE-\d{4}-\d{4,}|critical|high|medium|vulnerability|finding|misconfiguration)\b", line, re.I))
            rows.append(f"- **{p.name}** — {p.stat().st_size} bytes; keyword-matching lines: {keywords}")
        except OSError as exc:
            rows.append(f"- **{p.name}** — unable to read: {exc}")
    rows.extend([
        "",
        "## Review guidance",
        "- Confirm each finding against the original scanner output.",
        "- Check target scope, scan time, tool version, and scan options before comparing results.",
        "- Prioritize by validated impact, exposure, exploitability, and business context.",
        "- Record remediation owner, action, due date, and retest evidence separately.",
        "",
        "This summary indexes local report files; it does not merge or independently validate scanner findings."
    ])
    output = "\n".join(rows)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = REPORT_DIR / f"{stamp}_consolidated_summary.md"
    try:
        dest.write_text(output, encoding="utf-8")
        save_result("Consolidated Report Summary", str(dest), output + f"\n\n[Saved automatically] {dest}")
    except OSError as exc:
        save_result("Consolidated Report Summary", str(REPORT_DIR), output + f"\n\nCould not save summary: {exc}")


PHASES = {
"1": ("Information Gathering", [
("WHOIS lookup",p1_whois),("DNS record lookup",p1_dns),("Reverse DNS lookup",p1_reverse),
("HTTP response headers",p1_headers),("TLS certificate inspection",p1_tls),
("Web technology hints",p1_tech),("SpiderFoot integration guidance",p1_spiderfoot)]),
"2": ("Network Scanning", [
("Nmap host discovery",lambda:p2_nmap("1")),("Nmap common TCP ports",lambda:p2_nmap("2")),
("Nmap service/version detection",lambda:p2_nmap("3")),("Nmap scan + XML output",lambda:p2_nmap("4"))]),
"3": ("Enumeration", [
("DNS enumeration (common records)",p3_dns),("Nmap service/script enumeration",p3_nmap),
("SMB share listing (smbclient)",p3_smb),("SMB/RPC enumeration (enum4linux)",p3_enum4linux)]),
"4": ("Vulnerability Analysis", [
("Import/parse Nmap XML or read report",p4_import),("Nmap vuln-category checks (authorized only)",p4_nmap_vuln),
("Report keyword triage",p4_report_text)]),
"5": ("Web Security Testing", [
("HTTP headers",p5_headers),("Security header review",p5_security_headers),
("TLS configuration/certificate review",p5_tls),("robots.txt review",p5_robots)]),
"6": ("Password and Authentication Security", [
("Offline password-strength estimate",p6_strength),("Hash format identification",p6_hash_identify),
("Local Linux password-policy review",p6_policy)]),
"7": ("Cryptography and File Integrity", [
("Calculate SHA-256",p7_sha),("Verify file SHA-256",p7_verify),
("Inspect X.509 certificate with OpenSSL",p7_openssl_cert),("Local file metadata",p7_file_info)]),
"8": ("Reporting and Analysis", [
("List saved report history",p8_list_reports),("Summarize/triage a report",p8_summarize_report),
("Compare baseline and retest reports",p8_compare_reports),("Extract potential finding lines",p8_extract_findings),
("Generate consolidated report summary",p8_generate_summary)])
}

def phase_menu(key):
    title, tools=PHASES[key]
    while True:
        print(f"\n--- PHASE {key}: {title.upper()} ---")
        for i,(name,_) in enumerate(tools,1): print(f"[{i}] {name}")
        print("[0] Return to main menu")
        choice=input("Select a tool: ").strip()
        if choice=="0": return
        if not choice.isdigit() or not 1<=int(choice)<=len(tools):
            print("Invalid selection. Try again."); continue
        try:
            tools[int(choice)-1][1]()
        except KeyboardInterrupt:
            print("\n[Cancelled] Returning to phase menu.")
        except Exception as exc:
            print(f"\n[Error] {type(exc).__name__}: {exc}")
            pause()

def main():
    while True:
        banner()
        print("""[1] Information Gathering
[2] Network Scanning
[3] Enumeration
[4] Vulnerability Analysis
[5] Web Security Testing
[6] Password and Authentication Security
[7] Cryptography and File Integrity
[8] Reporting and Analysis
[0] Exit
""")
        try: choice=input("Select a phase: ").strip()
        except (EOFError,KeyboardInterrupt): print("\nSyllabusX closed.");return
        if choice=="0": print("Exiting SyllabusX. Stay ethical.");return
        if choice in PHASES: phase_menu(choice)
        else: print("Invalid selection. Choose 0–8.")

if __name__=="__main__":
    main()
