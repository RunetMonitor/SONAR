"""Operator/dev example overrides - not for volunteers.

Copy to config.local.py (gitignored) only if you need local endpoint overrides.
Volunteers use the interactive one-time token prompt; they never edit config.
"""

# Example: override hop list (non-secret hosts; expected to rotate over time).
# RECEIVER_HOPS = [
#     {
#         "host": "203.0.113.10",
#         "port": 5000,
#         "scheme": "http",
#         "path": "/upload",
#         "timeout_sec": 300.0,
#         "insecure_tls": False,
#     },
# ]

# Example: override direct monitor URL.
# SEND_RESULT_ENDPOINT = "https://test.example/api/submit_dns_check_result_zip"

# SEND_METHODS_ORDER = ["receiver", "direct"]
# SKIP_CHECK = False

# DNS_PROBE_ENABLED = False
# DNS_PROBE_QPS_GLOBAL = 40.0
# DNS_PROBE_QPS_RUSSIAN = 15.0
# DNS_PROBE_MAX_SECONDS = 300.0

# Version notice: a Russia-reachable copy of app/version.txt, tried first.
# VERSION_CHECK_URLS = [
#     "https://cdn.jsdelivr.net/gh/RunetMonitor/SONAR@main/app/version.txt",
#     "https://cdn.statically.io/gh/RunetMonitor/SONAR/main/app/version.txt",
#     "https://raw.githubusercontent.com/RunetMonitor/SONAR/main/app/version.txt",
# ]
