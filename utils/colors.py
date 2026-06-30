#!/usr/bin/env python3
# utils/colors.py — Terminal color system for HSHX

import sys


class Colors:
    RED       = "\033[91m"
    GREEN     = "\033[92m"
    YELLOW    = "\033[93m"
    CYAN      = "\033[96m"
    WHITE     = "\033[97m"
    DARK_GRAY = "\033[90m"
    BOLD      = "\033[1m"
    RESET     = "\033[0m"

    @staticmethod
    def disable():
        for attr in vars(Colors):
            if not attr.startswith("_") and isinstance(getattr(Colors, attr), str):
                setattr(Colors, attr, "")


if not sys.stdout.isatty():
    Colors.disable()

STATUS_ICONS = {
    "ok":      (Colors.GREEN,     "[+]"),
    "error":   (Colors.RED,       "[-]"),
    "warn":    (Colors.YELLOW,    "[!]"),
    "info":    (Colors.CYAN,      "[*]"),
    "run":     (Colors.DARK_GRAY, "[~]"),
    "found":   (Colors.GREEN,     "[>]"),
    "cracked": (Colors.RED,       "[CRACKED]"),
}


def print_status(msg: str, kind: str = "info", indent: int = 2):
    color, icon = STATUS_ICONS.get(kind, (Colors.WHITE, "[?]"))
    print(f"{'  '}{Colors.BOLD}{color}{icon}{Colors.RESET} {msg}")


def print_section(title: str):
    print(f"\n  {Colors.BOLD}{Colors.WHITE}── {title} {'─' * max(0, 38 - len(title))}{Colors.RESET}\n")


def print_table(headers: list, rows: list, indent: int = 2):
    if not rows:
        print_status("No data.", "warn")
        return
    pad = " " * indent
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))
    sep = pad + "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"
    print(sep)
    print(pad + "|" + "|".join(
        f" {Colors.BOLD}{Colors.WHITE}{h.ljust(col_widths[i])}{Colors.RESET} "
        for i, h in enumerate(headers)) + "|")
    print(sep)
    for row in rows:
        cells = [str(c) for c in row]
        print(pad + "|" + "|".join(f" {c.ljust(col_widths[i])} " for i, c in enumerate(cells)) + "|")
    print(sep)
    print()
