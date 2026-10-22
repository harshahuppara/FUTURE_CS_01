import socket
import ssl
import json
import urllib.request
import urllib.error
from datetime import datetime

TARGET_HOST = "testfire.net"
TARGET_PORT = 80

COMMON_PORTS = [
    (21, "FTP"),
    (22, "SSH"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (110, "POP3"),
    (143, "IMAP"),
    (443, "HTTPS"),
    (8080, "HTTP-Proxy/Alt"),
    (8443, "HTTPS-Alt"),
    (3306, "MySQL")
]

RECOMMENDED_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "Medium",
        "category": "Transport Security",
        "description": "Enforces HTTPS connections and prevents SSL-stripping man-in-the-middle attacks."
    },
    "Content-Security-Policy": {
        "severity": "High",
        "category": "Client-Side Protection",
        "description": "Restricts execution of unauthorized scripts, styles, and plugins, mitigating Cross-Site Scripting (XSS) and code injection."
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "category": "UI Redressing",
        "description": "Protects users from Clickjacking by preventing the website from being loaded in hidden <iframe> elements."
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "category": "MIME Sniffing",
        "description": "Prevents web browsers from MIME-sniffing a response away from the declared content-type, stopping drive-by script execution."
    },
    "Referrer-Policy": {
        "severity": "Low",
        "category": "Information Disclosure",
        "description": "Controls how much sensitive URL referrer information is transmitted to third-party domains."
    },
    "Permissions-Policy": {
        "severity": "Low",
        "category": "Feature Restriction",
        "description": "Restricts browser device features (camera, microphone, geolocation) that pages or embedded iframes can activate."
    }
}

def resolve_ipv4(host):
    try:
        ip = socket.gethostbyname(host)
        return ip
    except Exception as e:
        print(f"[-] Could not resolve host {host}: {e}")
        return None

def scan_ports(ip, host):
    print(f"[*] Starting Passive TCP Port Scan on {host} ({ip})...")
    open_ports = []
    closed_ports = []
    
    for port, service in COMMON_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        try:
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append({"port": port, "service": service, "status": "OPEN"})
                print(f"    [+] Port {port:5d} ({service:15s}): OPEN")
            else:
                closed_ports.append({"port": port, "service": service, "status": "CLOSED/FILTERED"})
        except Exception as e:
            closed_ports.append({"port": port, "service": service, "status": f"ERROR: {e}"})
        finally:
            s.close()
            
    return open_ports, closed_ports

def inspect_http_endpoint(host, port=80, path="/", is_ssl=False):
    scheme = "https" if is_ssl else "http"
    port_str = f":{port}" if (is_ssl and port != 443) or (not is_ssl and port != 80) else ""
    url = f"{scheme}://{host}{port_str}{path}"
    print(f"[*] Inspecting HTTP Endpoint: {url}")
    
    headers_dict = {}
    cookies = []
    status_code = None
    response_body_sample = ""
    
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; CybersecurityAssessment/1.0)"}
    )
    
    # Handle SSL verification for testing
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    try:
        with urllib.request.urlopen(req, timeout=8, context=ctx if is_ssl else None) as response:
            status_code = response.getcode()
            for key, val in response.info().items():
                headers_dict[key] = val
                if key.lower() == "set-cookie":
                    cookies.append(val)
            sample = response.read(1024)
            response_body_sample = sample.decode("latin1", errors="ignore")
    except urllib.error.HTTPError as e:
        status_code = e.code
        for key, val in e.headers.items():
            headers_dict[key] = val
            if key.lower() == "set-cookie":
                cookies.append(val)
    except Exception as e:
        print(f"    [-] Endpoint connection failed: {e}")
        return None, {}, [], ""
        
    return status_code, headers_dict, cookies, response_body_sample

def main():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("=" * 70)
    print("  CYBERSECURITY READ-ONLY VULNERABILITY ASSESSMENT")
    print(f"  Target Application: Altoro Mutual ({TARGET_HOST})")
    print(f"  Timestamp: {timestamp}")
    print("=" * 70)
    
    target_ip = resolve_ipv4(TARGET_HOST)
    if not target_ip:
        print("[-] Exiting due to DNS resolution failure.")
        return
        
    print(f"[+] Target IP (IPv4): {target_ip}")
    
    # 1. Port scan
    open_ports, closed_ports = scan_ports(target_ip, TARGET_HOST)
    
    # 2. HTTP Root inspection
    status_http, headers_http, cookies_http, body_sample = inspect_http_endpoint(TARGET_HOST, 80, "/", is_ssl=False)
    
    # 3. Check HTTPS availability & redirect
    status_https, headers_https, _, _ = inspect_http_endpoint(TARGET_HOST, 443, "/", is_ssl=True)
    
    findings = []
    
    # Check transport security (Cleartext HTTP)
    if status_http == 200:
        findings.append({
            "id": "SEC-FIND-01",
            "title": "Cleartext HTTP Transmission (Missing HTTPS Redirection)",
            "severity": "High",
            "category": "Transport Security",
            "risk_score": "7.5 (CVSS 3.1)",
            "description": "The application serves online banking and account functions over unencrypted plain HTTP (Port 80). There is no automatic redirection to HTTPS, allowing network eavesdroppers to intercept credentials and session cookies via Man-in-the-Middle (MitM) attacks.",
            "remediation": "Configure web server to return HTTP 301 Permanent Redirect to HTTPS for all incoming port 80 traffic, and deploy a valid TLS certificate."
        })
        
    # Check missing security headers
    header_checklist = {}
    for header_name, meta in RECOMMENDED_HEADERS.items():
        present = any(k.lower() == header_name.lower() for k in headers_http)
        header_checklist[header_name] = {
            "status": "PRESENT" if present else "MISSING",
            "severity": meta["severity"],
            "description": meta["description"]
        }
        if not present:
            findings.append({
                "id": f"SEC-FIND-0{len(findings)+1}",
                "title": f"Missing Security Header: {header_name}",
                "severity": meta["severity"],
                "category": meta["category"],
                "risk_score": "6.1 (CVSS 3.1)" if meta["severity"] == "High" else ("4.3 (CVSS 3.1)" if meta["severity"] == "Medium" else "3.1 (CVSS 3.1)"),
                "description": f"The response header '{header_name}' is not implemented. {meta['description']}",
                "remediation": f"Configure the web server (e.g. Apache/Nginx/Tomcat) to include '{header_name}' with strict security parameters in all HTTP responses."
            })
            
    # Check Server Information Disclosure
    server_header = headers_http.get("Server") or headers_http.get("server")
    if server_header:
        findings.append({
            "id": f"SEC-FIND-0{len(findings)+1}",
            "title": "Server Banner Information Disclosure",
            "severity": "Low",
            "category": "Information Gathering",
            "risk_score": "3.3 (CVSS 3.1)",
            "description": f"The HTTP response leaks the internal web server software ('{server_header}'). Attackers use this software banner to tailor exploits targeting known vulnerabilities in this specific server engine.",
            "remediation": "Suppress server version tokens in the web server configuration (e.g. Set ServerTokens Prod in Apache or hide server header in reverse proxy)."
        })
        
    # Check Cookie Security
    cookie_analysis = []
    for c in cookies_http:
        c_lower = c.lower()
        has_httponly = "httponly" in c_lower
        has_secure = "secure" in c_lower
        has_samesite = "samesite" in c_lower
        
        cookie_analysis.append({
            "raw": c,
            "HttpOnly": has_httponly,
            "Secure": has_secure,
            "SameSite": has_samesite
        })
        
        missing_flags = []
        if not has_secure:
            missing_flags.append("Secure")
        if not has_samesite:
            missing_flags.append("SameSite")
        if not has_httponly:
            missing_flags.append("HttpOnly")
            
        if missing_flags:
            findings.append({
                "id": f"SEC-FIND-0{len(findings)+1}",
                "title": f"Insecure Session Cookie Flags ({', '.join(missing_flags)} missing)",
                "severity": "Medium",
                "category": "Session Management",
                "risk_score": "5.3 (CVSS 3.1)",
                "description": f"Session cookies ('{c.split(';')[0]}') lack critical protective security flags: {', '.join(missing_flags)}. Without 'Secure', cookies can leak across unencrypted connections; without 'SameSite', the site is vulnerable to Cross-Site Request Forgery (CSRF).",
                "remediation": "Ensure the application server issues all session cookies with 'Secure; HttpOnly; SameSite=Lax' (or 'Strict') attributes."
            })

    # Summary Output
    print("\n" + "=" * 70)
    print("  EXECUTIVE FINDINGS SUMMARY")
    print("=" * 70)
    for f in findings:
        print(f"[{f['severity'].upper():6s}] {f['id']}: {f['title']}")
        print(f"         Impact: {f['description']}")
        print(f"         Remediation: {f['remediation']}")
        print("-" * 70)
        
    # Write Port Scan Evidence Log
    with open("evidence/logs/port_scan_results.txt", "w", encoding="utf-8") as pf:
        pf.write("============================================================\n")
        pf.write("VULNERABILITY ASSESSMENT - NETWORK PORT SCAN EVIDENCE\n")
        pf.write(f"Target Host: {TARGET_HOST}\n")
        pf.write(f"Target IP: {target_ip}\n")
        pf.write(f"Date & Time: {timestamp}\n")
        pf.write("Methodology: Passive TCP Connect Probing (Read-Only)\n")
        pf.write("============================================================\n\n")
        pf.write("OPEN PORTS DETECTED:\n")
        for p in open_ports:
            pf.write(f"  [+] Port {p['port']:<5} TCP | Service: {p['service']:<15} | Status: OPEN\n")
        pf.write("\nCLOSED / FILTERED PORTS:\n")
        for p in closed_ports:
            pf.write(f"  [-] Port {p['port']:<5} TCP | Service: {p['service']:<15} | Status: {p['status']}\n")
            
    # Write HTTP Headers Evidence Log
    with open("evidence/logs/http_headers_analysis.txt", "w", encoding="utf-8") as hf:
        hf.write("============================================================\n")
        hf.write("VULNERABILITY ASSESSMENT - HTTP RESPONSE HEADER EVIDENCE\n")
        hf.write(f"Target URL: http://{TARGET_HOST}/\n")
        hf.write(f"Target IP: {target_ip}\n")
        hf.write(f"Date & Time: {timestamp}\n")
        hf.write(f"HTTP Status: {status_http}\n")
        hf.write("============================================================\n\n")
        hf.write("RAW SERVER RESPONSE HEADERS:\n")
        for k, v in headers_http.items():
            hf.write(f"  {k}: {v}\n")
            
        hf.write("\nSECURITY HEADER AUDIT CHECKLIST:\n")
        hf.write(f"{'Header Name':<30} {'Status':<12} {'Severity':<10}\n")
        hf.write("-" * 55 + "\n")
        for h, data in header_checklist.items():
            hf.write(f"{h:<30} {data['status']:<12} {data['severity']:<10}\n")
            
    # Write Cookie Security Evidence Log
    with open("evidence/logs/cookie_security_analysis.txt", "w", encoding="utf-8") as cf:
        cf.write("============================================================\n")
        cf.write("VULNERABILITY ASSESSMENT - COOKIE SECURITY AUDIT EVIDENCE\n")
        cf.write(f"Target Host: {TARGET_HOST}\n")
        cf.write(f"Date & Time: {timestamp}\n")
        cf.write("============================================================\n\n")
        if cookie_analysis:
            for idx, c in enumerate(cookie_analysis, 1):
                cf.write(f"Cookie #{idx}: {c['raw']}\n")
                cf.write(f"  - HttpOnly Flag: {'[PASS] Present' if c['HttpOnly'] else '[FAIL] Missing'}\n")
                cf.write(f"  - Secure Flag:   {'[PASS] Present' if c['Secure'] else '[FAIL] Missing'}\n")
                cf.write(f"  - SameSite Flag: {'[PASS] Present' if c['SameSite'] else '[FAIL] Missing'}\n\n")
        else:
            cf.write("No session cookies detected on base request.\n")
            
    # Write JSON Summary
    full_audit = {
        "metadata": {
            "target_host": TARGET_HOST,
            "target_ip": target_ip,
            "scan_timestamp": timestamp,
            "scope": "Read-Only Passive Security Assessment"
        },
        "open_ports": open_ports,
        "closed_ports": closed_ports,
        "raw_headers": headers_http,
        "header_audit": header_checklist,
        "cookie_audit": cookie_analysis,
        "findings": findings
    }
    with open("evidence/logs/full_passive_scan_summary.json", "w", encoding="utf-8") as jf:
        json.dump(full_audit, jf, indent=2)
        
    print("\n[+] Audit scan complete! All evidence logs saved in 'evidence/logs/' directory.")

if __name__ == "__main__":
    main()
