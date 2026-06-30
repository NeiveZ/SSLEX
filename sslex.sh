#!/usr/bin/env bash
# sslex.sh — Launcher for SSLEX (SSL/TLS Scanner)
# Resolves its own directory so it can be run from anywhere,
# checks the Python version, and hands off to the interactive console.

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

if ! command -v python3 >/dev/null 2>&1; then
    echo "[-] python3 not found. Install Python 3.10+ and try again."
    exit 1
fi

PY_VERSION="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
REQUIRED="3.10"
if [ "$(printf '%s\n%s\n' "$REQUIRED" "$PY_VERSION" | sort -V | head -n1)" != "$REQUIRED" ]; then
    echo "[!] Warning: SSLEX targets Python $REQUIRED+, found $PY_VERSION. Continuing anyway."
fi

mkdir -p reports

exec python3 sslex.py "$@"
