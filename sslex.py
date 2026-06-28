#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSLEX - SSL/TLS Scanner
Author: NeiveZ | github.com/NeiveZ/SSLEX
"""

import cmd, sys, os, json, shutil
from datetime import datetime
from utils.colors import Colors, print_status
from utils.session import Session
from modules.tls_scan   import TLSScanner
from modules.cert_check import CertChecker
from modules.report_gen import ReportGenerator


class SSLEXShell(cmd.Cmd):

    intro  = ""
    prompt = f"{Colors.BOLD}{Colors.RED}sslex{Colors.RESET} {Colors.WHITE}>{Colors.RESET} "

    def __init__(self):
        super().__init__()
        self.session = Session()
        self.modules = {
            "ssl/scan": TLSScanner,
            "ssl/cert": CertChecker,
        }
        self.active_module      = None
        self.active_module_name = None
        self._show_header()

    def _show_header(self):
        stats = self.session.get_stats()
        print(f"\n  {Colors.BOLD}{Colors.RED}SSLEX{Colors.RESET}  "
              f"{Colors.DARK_GRAY}SSL/TLS Scanner{Colors.RESET}  {Colors.WHITE}v1.0.0{Colors.RESET}")
        print(f"  {Colors.DARK_GRAY}Author: NeiveZ  |  For authorized testing only{Colors.RESET}")
        print(f"  {Colors.DARK_GRAY}Scans: {Colors.WHITE}{stats['scans']}"
              f"  {Colors.DARK_GRAY}Findings: {Colors.WHITE}{stats['findings']}"
              f"  {Colors.DARK_GRAY}Reports: {Colors.WHITE}{stats['reports']}{Colors.RESET}")
        print(f"\n  {Colors.DARK_GRAY}Type {Colors.CYAN}help{Colors.DARK_GRAY} to list commands.{Colors.RESET}\n")

    def _update_prompt(self):
        if self.active_module_name:
            self.prompt = (f"{Colors.BOLD}{Colors.RED}sslex{Colors.RESET}"
                           f"{Colors.DARK_GRAY}({Colors.RESET}{Colors.YELLOW}{self.active_module_name}{Colors.RESET}"
                           f"{Colors.DARK_GRAY}){Colors.RESET} {Colors.WHITE}>{Colors.RESET} ")
        else:
            self.prompt = f"{Colors.BOLD}{Colors.RED}sslex{Colors.RESET} {Colors.WHITE}>{Colors.RESET} "

    def default(self, line): print_status(f"Unknown: '{line}'. Type 'help'.", "error")
    def emptyline(self): pass

    def do_use(self, name):
        """Load a module.\n  Usage: use <module>"""
        name = name.strip()
        if name not in self.modules:
            print_status(f"Module '{name}' not found. Run 'show modules'.", "error"); return
        self.active_module_name = name
        self.active_module = self.modules[name]()
        self._update_prompt()
        print_status(f"Module loaded: {Colors.YELLOW}{name}{Colors.RESET}", "ok")
        print(); self.active_module.show_info()

    def do_set(self, args):
        """Set option.\n  Usage: set <OPTION> <value>"""
        if not self.active_module: print_status("No module loaded.", "warn"); return
        parts = args.strip().split(None, 1)
        if len(parts) < 2: print_status("Usage: set <OPTION> <value>", "warn"); return
        opt, val = parts[0].upper(), parts[1]
        if self.active_module.set_option(opt, val):
            print_status(f"{Colors.CYAN}{opt}{Colors.RESET} => {Colors.WHITE}{val}{Colors.RESET}", "ok")
        else:
            print_status(f"Unknown option: {opt}.", "error")

    def do_run(self, _):
        """Execute module.\n  Usage: run"""
        if not self.active_module: print_status("No module loaded.", "warn"); return
        print()
        try:
            results = self.active_module.run()
            if results:
                self.session.add_findings(self.active_module_name, results)
                self._auto_save(results)
        except KeyboardInterrupt:
            print(); print_status("Interrupted.", "warn")
        except Exception as e:
            print_status(f"Module error: {e}", "error")

    def do_options(self, _):
        if not self.active_module: print_status("No module loaded.", "warn"); return
        self.active_module.show_options()

    def do_info(self, _):
        if not self.active_module: print_status("No module loaded.", "warn"); return
        self.active_module.show_info()

    def do_back(self, _):
        if self.active_module:
            print_status(f"Unloaded: {self.active_module_name}", "info")
            self.active_module = None; self.active_module_name = None; self._update_prompt()
        else:
            print_status("No module loaded.", "warn")

    def do_show(self, args):
        arg = args.strip().lower()
        if arg == "modules":
            col_w = shutil.get_terminal_size((80, 20)).columns
            print(f"\n  {Colors.BOLD}{Colors.WHITE}Available Modules{Colors.RESET}\n")
            print(f"  {'─'*(col_w-4)}")
            for name, desc in {
                "ssl/scan": "Full SSL/TLS scan — protocols, ciphers, vulns, HSTS",
                "ssl/cert": "Certificate details — SANs, expiry, CT logs, chain",
            }.items():
                print(f"  {Colors.CYAN}{name:<14}{Colors.RESET}{Colors.WHITE}{desc}{Colors.RESET}")
            print(f"  {'─'*(col_w-4)}\n")
        elif arg in ("results", "findings"):
            all_f = self.session.get_all_findings()
            if not all_f: print_status("No findings yet.", "warn"); return
            for module, items in all_f.items():
                print(f"\n  {Colors.YELLOW}[{module}]{Colors.RESET}")
                for item in (items if isinstance(items, list) else [items]):
                    if isinstance(item, dict):
                        sev = item.get("severity","?")
                        c   = Colors.RED if sev in ("HIGH","CRITICAL") else Colors.YELLOW if sev == "MEDIUM" else Colors.GREEN if sev == "OK" else Colors.DARK_GRAY
                        print(f"    {c}[{sev}]{Colors.RESET} {item.get('check','')} — {item.get('result','')}")
        elif arg == "session":
            s = self.session.get_stats()
            print(f"\n  {Colors.DARK_GRAY}Session {Colors.RESET}: {Colors.CYAN}{s['id']}{Colors.RESET}  "
                  f"{Colors.DARK_GRAY}Scans {Colors.RESET}: {s['scans']}  "
                  f"{Colors.DARK_GRAY}Findings {Colors.RESET}: {s['findings']}\n")
        else:
            print_status("Usage: show [modules|findings|session]", "warn")

    def do_report(self, args):
        parts = args.strip().split()
        fmt   = parts[0].lower() if parts else "html"
        fname = parts[1] if len(parts) > 1 else None
        all_f = self.session.get_all_findings()
        if not all_f: print_status("No findings to report.", "warn"); return
        gen  = ReportGenerator(all_f, self.session.get_stats())
        path = gen.generate(fmt=fmt, filename=fname)
        if path:
            self.session.increment_reports()
            print_status(f"Report saved: {Colors.CYAN}{path}{Colors.RESET}", "ok")

    def _auto_save(self, results):
        os.makedirs("reports", exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = f"reports/auto_{self.active_module_name.replace('/','_')}_{ts}.json"
        try:
            with open(path, "w") as f:
                json.dump({"module": self.active_module_name, "timestamp": ts, "results": results},
                          f, indent=2, default=str)
        except Exception:
            pass

    def do_clear(self, _): os.system("clear"); self._show_header()
    def do_exit(self, _):
        print(f"\n  {Colors.DARK_GRAY}Goodbye. Stay ethical.{Colors.RESET}\n"); return True
    def do_quit(self, _): return self.do_exit(_)

    def do_help(self, arg):
        if arg: super().do_help(arg); return
        print(f"""
  {Colors.BOLD}{Colors.WHITE}Core Commands{Colors.RESET}
  {'─'*40}
  {Colors.CYAN}use <module>{Colors.RESET}            Load a module
  {Colors.CYAN}set <OPTION> <value>{Colors.RESET}    Set option
  {Colors.CYAN}run{Colors.RESET}                     Execute module
  {Colors.CYAN}options / info / back{Colors.RESET}   Module management

  {Colors.BOLD}{Colors.WHITE}Show{Colors.RESET}
  {'─'*40}
  {Colors.CYAN}show modules{Colors.RESET}            List modules
  {Colors.CYAN}show findings{Colors.RESET}           Scan findings
  {Colors.CYAN}show session{Colors.RESET}            Session info

  {Colors.BOLD}{Colors.WHITE}Output{Colors.RESET}
  {'─'*40}
  {Colors.CYAN}report [txt|json|html]{Colors.RESET}  Generate report
  {Colors.CYAN}clear / exit{Colors.RESET}            Utility
""")


def main():
    try:
        SSLEXShell().cmdloop()
    except KeyboardInterrupt:
        print(f"\n\n  {Colors.DARK_GRAY}Interrupted.{Colors.RESET}\n"); sys.exit(0)


if __name__ == "__main__":
    main()
