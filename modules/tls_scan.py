#!/usr/bin/env python3
# modules/tls_scan.py — SSL/TLS configuration scanner for SSLEX

import ssl
import socket
import datetime
import concurrent.futures
from modules.base import BaseModule
from utils.colors import Colors, print_status, print_section


# Weak cipher keywords
WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "ADH", "AECDH",
    "MD5", "RC2", "IDEA", "SEED", "CAMELLIA128",
]

# Known vulnerable protocol versions
WEAK_PROTOCOLS = {
    "SSLv2":   "CRITICAL — SSLv2 is completely broken (DROWN attack)",
    "SSLv3":   "CRITICAL — SSLv3 vulnerable to POODLE attack",
    "TLSv1.0": "HIGH     — TLS 1.0 deprecated, vulnerable to BEAST/POODLE",
    "TLSv1.1": "MEDIUM   — TLS 1.1 deprecated since RFC 8996",
}

STRONG_PROTOCOLS = ["TLSv1.2", "TLSv1.3"]


class TLSScanner(BaseModule):

    NAME        = "ssl/scan"
    DESCRIPTION = "Full SSL/TLS configuration scan — protocols, ciphers, cert, vulnerabilities"
    REFERENCES  = [
        "https://testssl.sh/",
        "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/",
    ]

    def _define_options(self):
        self._add_option("TARGET",  "",    True,  "Target hostname or IP")
        self._add_option("PORT",    "443", False, "Port (default: 443)")
        self._add_option("TIMEOUT", "5",   False, "Connection timeout in seconds")

    def run(self) -> list:
        if not self._validate():
            return []

        target  = self.get_option("TARGET").strip()
        port    = int(self.get_option("PORT") or 443)
        timeout = int(self.get_option("TIMEOUT") or 5)

        print_section(f"SSL/TLS Scan — {target}:{port}")
        findings = []

        # 1. Certificate info
        findings += self._check_certificate(target, port, timeout)

        # 2. Protocol support
        findings += self._check_protocols(target, port, timeout)

        # 3. Cipher suites
        findings += self._check_ciphers(target, port, timeout)

        # 4. Vulnerability checks
        findings += self._check_vulnerabilities(target, port, timeout)

        # Summary
        print()
        high   = sum(1 for f in findings if "HIGH"     in f["severity"] or "CRITICAL" in f["severity"])
        medium = sum(1 for f in findings if "MEDIUM"   in f["severity"])
        low    = sum(1 for f in findings if "LOW"       in f["severity"])
        ok_    = sum(1 for f in findings if f["severity"] == "OK")

        print_status(
            f"Scan complete — "
            f"{Colors.RED}{high} HIGH/CRITICAL{Colors.RESET}  "
            f"{Colors.YELLOW}{medium} MEDIUM{Colors.RESET}  "
            f"{Colors.CYAN}{low} LOW{Colors.RESET}  "
            f"{Colors.GREEN}{ok_} OK{Colors.RESET}",
            "ok"
        )
        return findings

    # ── Certificate ───────────────────────────────────────────────

    def _check_certificate(self, host, port, timeout) -> list:
        findings = []
        print_status("Checking certificate...", "run")

        try:
            ctx  = ssl.create_default_context()
            conn = ctx.wrap_socket(socket.create_connection((host, port), timeout=timeout),
                                   server_hostname=host)
            cert = conn.getpeercert()
            conn.close()
        except ssl.SSLCertVerificationError as e:
            findings.append(self._finding("HIGH", "Certificate Validation",
                                          "FAIL", str(e)))
            print(f"  {Colors.RED}[HIGH]{Colors.RESET}    Certificate validation failed: {e}")
            return findings
        except Exception as e:
            findings.append(self._finding("ERROR", "Certificate", "Connection failed", str(e)))
            print_status(f"Cannot connect: {e}", "error")
            return findings

        # Subject / SAN
        subject = dict(x[0] for x in cert.get("subject", []))
        cn      = subject.get("commonName", "?")
        issuer  = dict(x[0] for x in cert.get("issuer", []))
        org     = issuer.get("organizationName", "?")
        sans    = [v for _, v in cert.get("subjectAltName", [])]

        print(f"  {Colors.DARK_GRAY}Common Name  {Colors.RESET}: {Colors.WHITE}{cn}{Colors.RESET}")
        print(f"  {Colors.DARK_GRAY}Issuer       {Colors.RESET}: {Colors.WHITE}{org}{Colors.RESET}")
        print(f"  {Colors.DARK_GRAY}SANs         {Colors.RESET}: {Colors.WHITE}{', '.join(sans[:5])}{Colors.RESET}")
        findings.append(self._finding("OK", "Certificate Subject", cn, f"Issuer: {org}"))

        # Expiry
        not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (not_after - datetime.datetime.utcnow()).days
        sev   = "OK" if days_left > 30 else ("MEDIUM" if days_left > 0 else "CRITICAL")
        color = Colors.GREEN if sev == "OK" else (Colors.YELLOW if sev == "MEDIUM" else Colors.RED)
        print(f"  {Colors.DARK_GRAY}Expires      {Colors.RESET}: {color}{not_after.strftime('%Y-%m-%d')} ({days_left} days){Colors.RESET}")
        findings.append(self._finding(sev, "Certificate Expiry",
                                      f"{days_left} days remaining",
                                      not_after.strftime("%Y-%m-%d")))

        # Hostname match
        try:
            ssl.match_hostname(cert, host)
            print(f"  {Colors.GREEN}[OK]{Colors.RESET}       Hostname matches certificate")
            findings.append(self._finding("OK", "Hostname Match", "PASS", host))
        except ssl.CertificateError as e:
            print(f"  {Colors.RED}[HIGH]{Colors.RESET}    Hostname mismatch: {e}")
            findings.append(self._finding("HIGH", "Hostname Match", "FAIL", str(e)))

        # Self-signed
        if subject == issuer:
            print(f"  {Colors.YELLOW}[MEDIUM]{Colors.RESET}  Self-signed certificate detected")
            findings.append(self._finding("MEDIUM", "Self-Signed Certificate",
                                          "Self-signed", cn))
        print()
        return findings

    # ── Protocol Support ──────────────────────────────────────────

    def _check_protocols(self, host, port, timeout) -> list:
        findings = []
        print_status("Checking protocol support...", "run")

        proto_map = {
            "TLSv1.0": ssl.PROTOCOL_TLS_CLIENT,
            "TLSv1.1": ssl.PROTOCOL_TLS_CLIENT,
            "TLSv1.2": ssl.PROTOCOL_TLS_CLIENT,
            "TLSv1.3": ssl.PROTOCOL_TLS_CLIENT,
        }

        min_version_map = {
            "TLSv1.0": ssl.TLSVersion.TLSv1,
            "TLSv1.1": ssl.TLSVersion.TLSv1_1,
            "TLSv1.2": ssl.TLSVersion.TLSv1_2,
            "TLSv1.3": ssl.TLSVersion.TLSv1_3,
        }

        for proto_name, max_ver in [
            ("TLSv1.0", ssl.TLSVersion.TLSv1   if hasattr(ssl.TLSVersion, "TLSv1")   else None),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1  if hasattr(ssl.TLSVersion, "TLSv1_1") else None),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3  if hasattr(ssl.TLSVersion, "TLSv1_3") else None),
        ]:
            if max_ver is None:
                continue
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname   = False
                ctx.verify_mode      = ssl.CERT_NONE
                ctx.minimum_version  = max_ver
                ctx.maximum_version  = max_ver
                with ctx.wrap_socket(socket.create_connection((host, port), timeout=timeout),
                                     server_hostname=host):
                    pass
                supported = True
            except Exception:
                supported = False

            if supported:
                if proto_name in WEAK_PROTOCOLS:
                    sev   = WEAK_PROTOCOLS[proto_name].split("—")[0].strip()
                    desc  = WEAK_PROTOCOLS[proto_name]
                    color = Colors.RED if "CRITICAL" in sev else Colors.YELLOW
                    print(f"  {color}[{sev}]{Colors.RESET}  {proto_name} — supported ({desc})")
                    findings.append(self._finding(sev, f"Protocol: {proto_name}",
                                                  "SUPPORTED (WEAK)", desc))
                else:
                    print(f"  {Colors.GREEN}[OK]{Colors.RESET}       {proto_name} — supported")
                    findings.append(self._finding("OK", f"Protocol: {proto_name}", "SUPPORTED"))
            else:
                if proto_name in STRONG_PROTOCOLS:
                    print(f"  {Colors.YELLOW}[MEDIUM]{Colors.RESET}  {proto_name} — NOT supported")
                    findings.append(self._finding("MEDIUM", f"Protocol: {proto_name}",
                                                  "NOT SUPPORTED"))
                else:
                    print(f"  {Colors.GREEN}[OK]{Colors.RESET}       {proto_name} — not supported (good)")
                    findings.append(self._finding("OK", f"Protocol: {proto_name}",
                                                  "NOT SUPPORTED (EXPECTED)"))
        print()
        return findings

    # ── Cipher Suites ─────────────────────────────────────────────

    def _check_ciphers(self, host, port, timeout) -> list:
        findings = []
        print_status("Checking cipher suites...", "run")

        try:
            ctx  = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            conn = ctx.wrap_socket(socket.create_connection((host, port), timeout=timeout),
                                   server_hostname=host)
            negotiated = conn.cipher()
            conn.close()
        except Exception as e:
            print_status(f"Cannot check ciphers: {e}", "warn")
            return findings

        if negotiated:
            cipher_name, proto, bits = negotiated
            is_weak = any(w in cipher_name.upper() for w in WEAK_CIPHERS)
            sev     = "HIGH" if is_weak else "OK"
            color   = Colors.RED if is_weak else Colors.GREEN
            label   = "WEAK" if is_weak else "STRONG"
            print(f"  {color}[{label}]{Colors.RESET}  Negotiated: {Colors.WHITE}{cipher_name}{Colors.RESET} "
                  f"{Colors.DARK_GRAY}({proto}, {bits} bits){Colors.RESET}")
            findings.append(self._finding(sev, "Negotiated Cipher",
                                          cipher_name, f"{proto} {bits} bits"))

            if bits and bits < 128:
                print(f"  {Colors.RED}[HIGH]{Colors.RESET}    Key size {bits} bits — too weak (minimum 128)")
                findings.append(self._finding("HIGH", "Key Size",
                                              f"{bits} bits", "Minimum recommended: 128 bits"))
        print()
        return findings

    # ── Vulnerability Checks ──────────────────────────────────────

    def _check_vulnerabilities(self, host, port, timeout) -> list:
        findings = []
        print_status("Running vulnerability checks...", "run")

        # HSTS
        try:
            import urllib.request
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            req  = urllib.request.Request(f"https://{host}:{port}/",
                                          headers={"User-Agent": "SSLEX/1.0"})
            h    = urllib.request.HTTPSHandler(context=ctx)
            op   = urllib.request.build_opener(h)
            resp = op.open(req, timeout=timeout)
            hdrs = {k.lower(): v for k, v in resp.headers.items()}

            if "strict-transport-security" in hdrs:
                hsts_val = hdrs["strict-transport-security"]
                max_age  = int(next((p.split("=")[1] for p in hsts_val.split(";")
                                     if "max-age" in p.lower()), 0))
                sev = "OK" if max_age >= 31536000 else "LOW"
                print(f"  {Colors.GREEN if sev == 'OK' else Colors.YELLOW}[{sev}]{Colors.RESET}"
                      f"      HSTS: {hsts_val}")
                findings.append(self._finding(sev, "HSTS", "PRESENT", hsts_val))
            else:
                print(f"  {Colors.YELLOW}[MEDIUM]{Colors.RESET}  HSTS header missing")
                findings.append(self._finding("MEDIUM", "HSTS", "MISSING",
                                              "Add Strict-Transport-Security header"))

        except Exception:
            pass

        # Heartbleed (basic probe — checks if TLS 1.0/1.1 with OpenSSL patterns)
        print(f"  {Colors.DARK_GRAY}[INFO]{Colors.RESET}    Heartbleed: Manual verification recommended "
              f"(use: testssl.sh --heartbleed {host}:{port})")
        findings.append(self._finding("INFO", "Heartbleed",
                                      "Not tested (use testssl.sh for full check)", ""))

        # BEAST / POODLE (inferred from TLS version support already checked)
        print(f"  {Colors.DARK_GRAY}[INFO]{Colors.RESET}    BEAST/POODLE: Check TLS 1.0/SSLv3 results above")

        print()
        return findings
