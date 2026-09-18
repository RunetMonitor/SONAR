#!/usr/bin/env bash
cd "$(dirname "$0")"

if ! command -v python3 &>/dev/null; then
    echo "Error: python3 is not installed. Please install Python 3.7+ and try again."
    exit 1
fi

if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 7) else 1)'; then
    echo "Error: Python 3.7 or newer is required. This is:"
    python3 -V
    exit 1
fi

python3 run.py
