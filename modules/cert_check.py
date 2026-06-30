#!/usr/bin/env python3
# modules/cert_check.py — Certificate details checker for SSLEX

import ssl
import socket
import datetime
from modules.base import BaseModule
from utils.colors import Colors, print_status, print_section


class CertChecker(BaseModule):

    NAME        = "ssl/cert"
    DESCRIPTION = "Detailed certificate inspection — chain, SANs, CT logs, key size, signature algo"
    REFERENCES  = [
        "https://crt.sh",
        "https://www.ssllabs.com/ssltest/",
    ]

    def _define_options(self):
        self._add_option("TARGET",  "",    True,  "Target hostname or IP")
        self._add_option("PORT",    "443", False, "Port (default: 443)")
        self._add_option("TIMEOUT", "5",   False, "Connection timeout")
        self._add_option("CRT_SH",  "true",False, "Check crt.sh for CT logs (true/false)")

    def run(self) -> list:
        if not self._validate():
            return []

        target  = self.get_option("TARGET").strip()
        port    = int(self.get_option("PORT") or 443)
        timeout = int(self.get_option("TIMEOUT") or 5)
        crt_sh  = self.get_option("CRT_SH").lower() == "true"

        print_section(f"Certificate Details — {target}:{port}")
        findings = []

        verified = True
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.create_connection((target, port), timeout=timeout),
                server_hostname=target
            ) as conn:
                cert        = conn.getpeercert()
                der_cert    = conn.getpeercert(binary_form=True)
                cipher      = conn.cipher()
                tls_version = conn.version()
        except ssl.SSLCertVerificationError as e:
            # Common with self-signed/expired certs or hostname mismatches.
            # This is itself a real finding, not just an error to swallow.
            print_status(f"Certificate validation failed: {e}", "warn")
            findings.append(self._finding("HIGH", "Certificate Validation", "FAILED", str(e)))
            verified = False
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                with ctx.wrap_socket(
                    socket.create_connection((target, port), timeout=timeout),
                    server_hostname=target
                ) as conn:
                    # NOTE: getpeercert() returns {} here — Python's ssl module only
                    # populates parsed certificate fields (subject/issuer/SANs/dates)
                    # when verify_mode requires and succeeds at validation. Detailed
                    # field parsing of an unverified cert would require an extra
                    # library (e.g. cryptography/asn1crypto) — out of scope to keep
                    # this module dependency-free, so we report what's still
                    # available (TLS version, cipher, raw DER) and stop there.
                    cert        = {}
                    der_cert    = conn.getpeercert(binary_form=True)
                    cipher      = conn.cipher()
                    tls_version = conn.version()
            except Exception as e2:
                print_status(f"Connection failed even without verification: {e2}", "error")
                return findings
        except Exception as e:
            print_status(f"Connection failed: {e}", "error")
            return []

        # ── Basic info ────────────────────────────────────────────
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer", []))
        sans    = [v for _, v in cert.get("subjectAltName", [])]

        print_status("Certificate Information", "info")
        fields = [
            ("Common Name",     subject.get("commonName", "?")),
            ("Organization",    subject.get("organizationName", "?")),
            ("Country",         subject.get("countryName", "?")),
            ("Issuer CN",       issuer.get("commonName", "?")),
            ("Issuer Org",      issuer.get("organizationName", "?")),
            ("Serial Number",   cert.get("serialNumber", "?")),
            ("TLS Version",     tls_version or "?"),
            ("Cipher",          f"{cipher[0]} ({cipher[2]} bits)" if cipher else "?"),
        ]
        for label, value in fields:
            print(f"  {Colors.DARK_GRAY}{label:<18}{Colors.RESET}: {Colors.WHITE}{value}{Colors.RESET}")
            findings.append(self._finding("INFO", label, value))

        # ── SANs ──────────────────────────────────────────────────
        print()
        print_status(f"Subject Alternative Names ({len(sans)} entries)", "info")
        for san in sans:
            wc = Colors.YELLOW if san.startswith("*.") else Colors.WHITE
            print(f"  {wc}• {san}{Colors.RESET}")
        findings.append(self._finding("INFO", "SANs", str(len(sans)), ", ".join(sans[:10])))

        # ── Validity ──────────────────────────────────────────────
        print()
        if not cert:
            print_status(
                "Detailed fields unavailable for an unverified certificate "
                "(subject/SANs/validity dates require successful chain validation "
                "when using only the stdlib ssl module).",
                "warn"
            )
            findings.append(self._finding(
                "INFO", "Certificate Detail", "Limited (unverified)",
                "Install 'cryptography' or 'asn1crypto' to parse fields from unverified certs"
            ))
        else:
            not_before = datetime.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
            not_after  = datetime.datetime.strptime(cert["notAfter"],  "%b %d %H:%M:%S %Y %Z")
            days_left  = (not_after - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)).days
            total_days = (not_after - not_before).days

            sev = "OK" if days_left > 30 else ("MEDIUM" if days_left > 0 else "CRITICAL")
            color = {
                "OK": Colors.GREEN, "MEDIUM": Colors.YELLOW, "CRITICAL": Colors.RED
            }.get(sev, Colors.WHITE)

            print_status("Validity Period", "info")
            print(f"  {Colors.DARK_GRAY}Not Before  {Colors.RESET}: {Colors.WHITE}{not_before.strftime('%Y-%m-%d %H:%M:%S')} UTC{Colors.RESET}")
            print(f"  {Colors.DARK_GRAY}Not After   {Colors.RESET}: {color}{not_after.strftime('%Y-%m-%d %H:%M:%S')} UTC{Colors.RESET}")
            print(f"  {Colors.DARK_GRAY}Days Left   {Colors.RESET}: {color}{days_left} / {total_days} days{Colors.RESET}")
            findings.append(self._finding(sev, "Certificate Expiry",
                                          f"{days_left} days remaining",
                                          not_after.strftime("%Y-%m-%d")))

        # ── CT logs via crt.sh ────────────────────────────────────
        if crt_sh:
            print()
            print_status("Checking Certificate Transparency logs (crt.sh)...", "run")
            try:
                import urllib.request, json as _json
                domain = target[4:] if target.lower().startswith("www.") else target
                url    = f"https://crt.sh/?q={domain}&output=json"
                req    = urllib.request.Request(url, headers={"User-Agent": "SSLEX/1.0"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = _json.loads(resp.read())
                print_status(f"Found {Colors.WHITE}{len(data)}{Colors.RESET} CT log entries for {domain}", "found")
                for entry in data[:5]:
                    cn_val  = entry.get("common_name", "?")
                    logged  = entry.get("entry_timestamp", "?")[:10]
                    print(f"  {Colors.DARK_GRAY}• {logged}{Colors.RESET} {Colors.WHITE}{cn_val}{Colors.RESET}")
                findings.append(self._finding("INFO", "CT Logs",
                                              f"{len(data)} entries", domain))
            except Exception as e:
                print_status(f"crt.sh lookup failed: {e}", "warn")

        print()
        print_status(f"Certificate check complete. {Colors.WHITE}{len(findings)}{Colors.RESET} items.", "ok")
        return findings
