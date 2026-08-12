#!/usr/bin/env bash
cd "$(dirname "$0")"

if ! command -v python3 &>/dev/null; then
    echo "Error: python3 is not installed. Please install Python 3.6+ and try again."
    exit 1
fi

python3 run.py
