"""Committed defaults for SONAR (safe for public clone).

Upload auth is a one-time token prompted at run time (see upload_token.py).
No live API keys, zip passwords, or auth tokens belong in this file.

Operator/dev overrides: optional config.local.py (gitignored) or environment.
Volunteers never edit config or create local secret files.
"""

from __future__ import annotations

import os
import runpy
from datetime import datetime
from pathlib import Path

# Uses system DNS servers by default, set to custom DNS server if needed
DNS_SERVER = ""

URL_CHECK_LISTS_DIR = "app/url_check_lists"
RESULTS_DIR = "results"

CHECK_LIMIT_N = 0
DNS_TIMEOUT = 5
HTTP_TIMEOUT = 10
MAX_WORKERS = 20

OUTPUT_CSV = "check_results_{}.csv".format(datetime.now().strftime("%Y%m%d_%H%M%S"))

# extra DNS lookups against the list in DNS_PROBE_SERVERS_FILE
DNS_PROBE_ENABLED = True
DNS_PROBE_SERVERS_FILE = "app/dns_servers.txt"
DNS_PROBE_TIMEOUT = 1.5
DNS_PROBE_ATTEMPTS = 3
# q/s per resolver. keep russian/isp ones slower so we don't get blocked
DNS_PROBE_QPS_GLOBAL = 40.0
DNS_PROBE_QPS_RUSSIAN = 15.0
DNS_PROBE_MAX_INFLIGHT = 600
DNS_PROBE_MAX_INFLIGHT_PER_SERVER = 100
# drop a resolver if it stays silent this many times in a row
DNS_PROBE_BREAKER_FAILURES = 15
DNS_PROBE_MAX_SECONDS = 300.0

# Legacy operator flag. Volunteers do not flip this; upload is driven by the
# interactive one-time token prompt (empty token = local CSV only).
SEND_RESULT = False

SKIP_CHECK = False

# Hop-first, then direct monitor fallback. Assume the main monitor host is often
# unreachable; hops are the primary path. Hop hosts are expected to rotate.
SEND_METHODS_ORDER = ["receiver", "direct"]

# Non-secret direct HTTPS endpoint (auth = prompted one-time token as X-Web-Token).
SEND_RESULT_DOMAIN = "https://monitor-ru.net"
SEND_RESULT_PATH = "/api/submit_dns_check_result_zip"
SEND_RESULT_ENDPOINT = SEND_RESULT_DOMAIN + SEND_RESULT_PATH
SEND_RESULT_DIRECT_TIMEOUT_SEC = 10.0

# Non-secret hop list (tried in order). Hosts/IPs may change over time so traffic
# does not permanently fingerprint a single upload address. Volunteers never
# configure this list; auth is only the prompted one-time token (X-Web-Token).
RECEIVER_HOPS = [
    {
        "host": "45.143.203.252",
        "port": 5000,
        "scheme": "http",
        "path": "/upload",
        "timeout_sec": 300.0,
        "insecure_tls": False,
    },
]

# Same wording as README.md - where volunteers get the one-time token.
TOKEN_SOURCE_TEXT = (
    "Get a one-time upload token from Na Svyazi Helpdesk "
    "(nasvyazi.org / your usual support channel)."
)

# Latest app/version.txt. GitHub is often blocked in Russia, so try public
# CDNs of the same file first. Failures are silent; the scan still runs.
VERSION_CHECK_TIMEOUT = 2.0
VERSION_CHECK_URLS = [
    "https://cdn.jsdelivr.net/gh/RunetMonitor/SONAR@main/app/version.txt",
    "https://cdn.statically.io/gh/RunetMonitor/SONAR/main/app/version.txt",
    "https://raw.githubusercontent.com/RunetMonitor/SONAR/main/app/version.txt",
]

# Optional operator/dev overrides from environment (not used by volunteers).
_ENV_ENDPOINT = (os.environ.get("SEND_RESULT_ENDPOINT") or "").strip()
if _ENV_ENDPOINT:
    SEND_RESULT_ENDPOINT = _ENV_ENDPOINT


def _apply_local_overrides() -> None:
    """Load UPPER_CASE assignments from optional config.local.py if present."""
    local_path = Path(__file__).resolve().parent / "config.local.py"
    if not local_path.is_file():
        return
    ns = runpy.run_path(str(local_path))
    g = globals()
    for key, value in ns.items():
        if key.isupper() and not key.startswith("_"):
            g[key] = value


_apply_local_overrides()
