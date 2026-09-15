#!/usr/bin/env python3

import csv
import glob
import hashlib
import json
import os
import random
import re
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse

_APP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app")
if _APP_DIR not in sys.path:
    sys.path.insert(0, _APP_DIR)

from config import (
    CHECK_LIMIT_N,
    DNS_PROBE_ATTEMPTS,
    DNS_PROBE_BREAKER_FAILURES,
    DNS_PROBE_ENABLED,
    DNS_PROBE_MAX_INFLIGHT,
    DNS_PROBE_MAX_INFLIGHT_PER_SERVER,
    DNS_PROBE_MAX_SECONDS,
    DNS_PROBE_QPS_GLOBAL,
    DNS_PROBE_QPS_RUSSIAN,
    DNS_PROBE_SERVERS_FILE,
    DNS_PROBE_TIMEOUT,
    DNS_SERVER,
    DNS_TIMEOUT,
    HTTP_TIMEOUT,
    MAX_WORKERS,
    OUTPUT_CSV,
    RESULTS_DIR,
    SKIP_CHECK,
    TOKEN_SOURCE_TEXT,
    URL_CHECK_LISTS_DIR,
    VERSION_CHECK_TIMEOUT,
    VERSION_CHECK_URLS,
)
from upload_token import normalize_pasted_token, verify_upload_token

try:
    import dns_probe
except ImportError:
    dns_probe = None


def pause_if_windows():
    if sys.platform == "win32":
        try:
            input("Press Enter to exit...")
        except EOFError:
            pass


def prompt_upload_token_before_scan(for_resend=False):
    """Ask for one-time token before scanning (or before re-send).

    Returns:
      None  - empty/skip: local CSV only, no upload
      str   - validated token: scan then upload (or upload only on re-send)
    Exits the process on bad format (after Windows pause).
    """
    print("Important: run without VPN so the path matches a normal user.")
    print()
    print(TOKEN_SOURCE_TEXT)
    if for_resend:
        print(
            "Enter your one-time upload token to send this CSV "
            "(or leave empty to cancel upload)."
        )
    else:
        print(
            "Enter your one-time upload token before the scan "
            "(or leave empty for local CSV only, no upload)."
        )
    try:
        raw = input("One-time token: ")
    except EOFError:
        raw = ""
    token = normalize_pasted_token(raw)
    if not token:
        if for_resend:
            print("No token entered - upload cancelled. CSV kept.")
        else:
            print("No token entered - local scan only (CSV). No upload.")
        print()
        return None
    ok, reason = verify_upload_token(token)
    if not ok:
        print("ERROR: bad token format ({})".format(reason))
        print("Aborted. {}".format(TOKEN_SOURCE_TEXT))
        pause_if_windows()
        sys.exit(2)
    if for_resend:
        print("Token format OK. Uploading (hop-first).")
    else:
        print("Token format OK. Starting scan, then upload (hop-first).")
    print()
    return token


def _run_send_results(script_dir, csv_path, upload_token):
    send_script = os.path.join(script_dir, "app", "send_results.py")
    # Import and call main with token to avoid a second interactive prompt.
    app_dir = os.path.join(script_dir, "app")
    if app_dir not in sys.path:
        sys.path.insert(0, app_dir)
    import send_results as sr  # type: ignore

    old_argv = sys.argv
    try:
        sys.argv = [send_script, csv_path]
        return sr.main(upload_token=upload_token)
    finally:
        sys.argv = old_argv

def _build_dns_query(domain):
    tx_id = random.randint(0, 0xFFFF)
    flags = 0x0100
    header = struct.pack(">HHHHHH", tx_id, flags, 1, 0, 0, 0)

    qname = b""
    for label in domain.rstrip(".").split("."):
        raw = label.encode("ascii")
        qname += struct.pack("B", len(raw)) + raw
    qname += b"\x00"
    qname += struct.pack(">HH", 1, 1)

    return tx_id, header + qname

def _skip_name(data, offset):
    while offset < len(data):
        b = data[offset]
        if b == 0:
            return offset + 1
        if (b & 0xC0) == 0xC0:
            return offset + 2
        offset += 1 + b
    return offset

def _parse_dns_response(data, expected_tx_id):
    if len(data) < 12:
        return []
    tx_id, flags, qd, an = struct.unpack(">HHHH", data[:8])
    if tx_id != expected_tx_id or (flags & 0x0F) != 0:
        return []

    offset = 12
    for _ in range(qd):
        offset = _skip_name(data, offset)
        offset += 4

    ips = []
    for _ in range(an):
        if offset >= len(data):
            break
        offset = _skip_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _, _, rdlen = struct.unpack(">HHIH", data[offset : offset + 10])
        offset += 10
        if rtype == 1 and rdlen == 4:
            ips.append(".".join(str(b) for b in data[offset : offset + 4]))
        offset += rdlen
    return ips

def resolve_dns_custom(domain, server, timeout):
    tx_id, query = _build_dns_query(domain)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (server, 53))
        data, _ = sock.recvfrom(4096)
        return _parse_dns_response(data, tx_id)
    finally:
        sock.close()

def resolve_dns_system(domain, timeout):
    infos = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
    return list({info[4][0] for info in infos})

def resolve_dns(domain, server=None, timeout=DNS_TIMEOUT):
    if server:
        return resolve_dns_custom(domain, server, timeout)
    return resolve_dns_system(domain, timeout)

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE

def check_http(domain, timeout=HTTP_TIMEOUT):
    last_err = ""
    for scheme in ("https", "http"):
        url = "{}://{}/".format(scheme, domain)
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (compatible; DomainChecker/1.0)",
                },
            )
            resp = urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx)
            body = resp.read(64 * 1024)
            redirect_url = resp.geturl()
            return {
                "status": resp.getcode(),
                "size": len(body),
                "url": url,
                "redirect_url": redirect_url,
                "error": "",
                "body": body,
                "protocol": scheme,
            }
        except urllib.error.HTTPError as e:
            return {
                "status": e.code,
                "size": 0,
                "url": url,
                "redirect_url": url,
                "error": str(e.reason if hasattr(e, "reason") else e),
                "body": b"",
                "protocol": scheme,
            }
        except urllib.error.URLError as e:
            last_err = str(e.reason)
        except Exception as e:
            last_err = str(e)
    return {
        "status": 0,
        "size": 0,
        "url": "https://{}/".format(domain),
        "redirect_url": "",
        "error": last_err,
        "body": b"",
        "protocol": "",
    }

def check_ssl(domain, timeout=HTTP_TIMEOUT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    t0 = time.monotonic()
    try:
        sock.connect((domain, 443))
        tcp_ms = (time.monotonic() - t0) * 1000
    except Exception as e:
        tcp_ms = (time.monotonic() - t0) * 1000
        try:
            sock.close()
        except Exception:
            pass
        return tcp_ms, False, "", "tcp: " + str(e).replace("\n", " ")

    ctx = ssl.create_default_context()
    try:
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()
            issuer_parts = []
            for rdn in cert.get("issuer", ()):
                for attr_type, attr_value in rdn:
                    if attr_type in ("organizationName", "commonName"):
                        issuer_parts.append(attr_value)
            return tcp_ms, True, "; ".join(issuer_parts), ""
    except Exception as e:
        return tcp_ms, False, "", str(e).replace("\n", " ")
    finally:
        try:
            sock.close()
        except Exception:
            pass

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

def _extract_title(body):
    if not body:
        return ""
    try:
        text = body.decode("utf-8", errors="ignore")
    except Exception:
        return ""
    m = _TITLE_RE.search(text)
    if m:
        title = m.group(1).strip()
        title = re.sub(r"\s+", " ", title)
        return title[:200]
    return ""

def _content_hash(body):
    if not body:
        return ""
    return hashlib.sha256(body).hexdigest()[:16]

def _read_version_text(script_dir):
    p = os.path.join(script_dir, "app", "version.txt")
    try:
        with open(p, encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return ""
    for line in text.splitlines():
        s = line.strip()
        if s:
            return s
    return ""


_VERSION_RE = re.compile(r"^v?(\d+(?:\.\d+){0,3})$", re.IGNORECASE)


def _parse_version_text(text):
    if not text:
        return ""
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        match = _VERSION_RE.match(s)
        if not match:
            return ""
        return match.group(1)
    return ""


def _version_key(text):
    parsed = _parse_version_text(text)
    if not parsed:
        return None
    return tuple(int(part) for part in parsed.split("."))


def _is_remote_newer(local, remote):
    local_key = _version_key(local)
    remote_key = _version_key(remote)
    if local_key is None or remote_key is None:
        return False
    size = max(len(local_key), len(remote_key))
    local_key = local_key + (0,) * (size - len(local_key))
    remote_key = remote_key + (0,) * (size - len(remote_key))
    return remote_key > local_key


def _fetch_one_version(url, timeout):
    url = (url or "").strip()
    if not url:
        return ""
    resp = None
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "WhiteListChecker"}
        )
        resp = urllib.request.urlopen(req, timeout=timeout)
        body = resp.read(65)
    except Exception:
        return ""
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass
    if not body or len(body) > 64:
        return ""
    return _parse_version_text(body.decode("utf-8", errors="replace"))


def _newest_version(versions):
    best = ""
    for ver in versions:
        if not _version_key(ver):
            continue
        if not best or _is_remote_newer(best, ver):
            best = ver
    return best


def _fetch_latest_version(urls=None, timeout=None):
    """Return the newest remote version, or empty if every URL fails."""
    if urls is None:
        urls = VERSION_CHECK_URLS
    if timeout is None:
        timeout = VERSION_CHECK_TIMEOUT
    urls = [(u or "").strip() for u in urls]
    urls = [u for u in urls if u]
    if not urls:
        return ""
    found = []
    workers = min(3, len(urls))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(_fetch_one_version, url, timeout) for url in urls]
        for fut in as_completed(futs):
            try:
                ver = fut.result()
            except Exception:
                continue
            if ver:
                found.append(ver)
    return _newest_version(found)


def _print_update_notice(local, remote):
    if not _is_remote_newer(local, remote):
        return
    print()
    print(
        "A NEWER VERSION OF THIS SCRIPT IS AVAILABLE ({}). YOU HAVE {}.".format(
            remote, local
        )
    )
    print(
        "ASK NASVYAZI HELPDESK (NASVYAZI.ORG) OR SEE "
        "GITHUB.COM/RUNETMONITOR/WHITELISTCHECKERSCRIPT"
    )
    print()


def _print_version_block(local, remote):
    print("Version: {}".format(local if local else "-"))
    _print_update_notice(local, remote)


def check_domain(domain, source_file, server=None, original=None):
    row = {
        "domain": original if original is not None else domain,
        "source_file": source_file,
        "check_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dns_resolved_ips": "",
        "dns_time_ms": "",
        "dns_error": "",
        "tcp_connect_time_ms": "",
        "ssl_valid": "",
        "ssl_issuer": "",
        "ssl_error": "",
        "http_status": "",
        "http_url": "",
        "http_redirect_url": "",
        "http_time_ms": "",
        "http_content_bytes": "",
        "http_error": "",
        "protocol": "",
        "final_domain": "",
        "http_title": "",
        "content_hash": "",
        "accessible": "NO",
    }

    t0 = time.monotonic()
    try:
        ips = resolve_dns(domain, server)
        dns_ms = (time.monotonic() - t0) * 1000
        row["dns_resolved_ips"] = "; ".join(ips)
        row["dns_time_ms"] = "{:.1f}".format(dns_ms)
    except Exception as e:
        dns_ms = (time.monotonic() - t0) * 1000
        row["dns_time_ms"] = "{:.1f}".format(dns_ms)
        row["dns_error"] = str(e).replace("\n", " ")
        row["http_error"] = "skipped (DNS failed)"
        return row

    if not ips:
        row["dns_error"] = "no A records returned"
        row["http_error"] = "skipped (no A records)"
        return row

    try:
        tcp_ms, ssl_ok, ssl_issuer, ssl_err = check_ssl(domain)
        row["tcp_connect_time_ms"] = "{:.1f}".format(tcp_ms)
        row["ssl_valid"] = "YES" if ssl_ok else "NO"
        row["ssl_issuer"] = ssl_issuer
        row["ssl_error"] = ssl_err
    except Exception as e:
        row["ssl_valid"] = "NO"
        row["ssl_error"] = str(e).replace("\n", " ")

    t0 = time.monotonic()
    try:
        r = check_http(domain)
        http_ms = (time.monotonic() - t0) * 1000
        row["http_status"] = str(r["status"]) if r["status"] else ""
        row["http_url"] = r["url"]
        row["http_redirect_url"] = (
            r["redirect_url"] if r["redirect_url"] != r["url"] else ""
        )
        row["http_time_ms"] = "{:.1f}".format(http_ms)
        row["http_content_bytes"] = str(r["size"]) if r["size"] else ""
        row["http_error"] = r["error"].replace("\n", " ") if r["error"] else ""
        row["protocol"] = r["protocol"]

        if r["redirect_url"]:
            try:
                redir_host = urlparse(r["redirect_url"]).hostname
                if redir_host and redir_host != domain:
                    row["final_domain"] = redir_host
            except Exception:
                pass

        row["http_title"] = _extract_title(r["body"])
        row["content_hash"] = _content_hash(r["body"])

        status = r["status"]
        if 200 <= status < 400 and r["size"] > 0:
            row["accessible"] = "YES"
        elif 200 <= status < 400:
            row["accessible"] = "PARTIAL"
    except Exception as e:
        http_ms = (time.monotonic() - t0) * 1000
        row["http_time_ms"] = "{:.1f}".format(http_ms)
        row["http_error"] = str(e).replace("\n", " ")

    return row

_TRANSLIT_MAP = {
    "а": "a",
    "б": "b",
    "в": "v",
    "г": "g",
    "д": "d",
    "е": "e",
    "ё": "yo",
    "ж": "zh",
    "з": "z",
    "и": "i",
    "й": "y",
    "к": "k",
    "л": "l",
    "м": "m",
    "н": "n",
    "о": "o",
    "п": "p",
    "р": "r",
    "с": "s",
    "т": "t",
    "у": "u",
    "ф": "f",
    "х": "kh",
    "ц": "ts",
    "ч": "ch",
    "ш": "sh",
    "щ": "shch",
    "ъ": "",
    "ы": "y",
    "ь": "",
    "э": "e",
    "ю": "yu",
    "я": "ya",
}

def _translit(text):

    text = text.replace("\u0301", "")
    out = []
    for ch in text:
        lo = ch.lower()
        if lo in _TRANSLIT_MAP:
            t = _TRANSLIT_MAP[lo]
            if t and ch.isupper():
                t = t[0].upper() + t[1:]
            out.append(t)
        else:
            out.append(ch)
    result = "".join(out)

    _ENGLISH_NAMES = {
        "Rossiya": "Russia",
        "Ukraina": "Ukraine",
        "Belorussiya": "Belarus",
        "Kazahstan": "Kazakhstan",
        "Gruziya": "Georgia",
        "Armeniya": "Armenia",
        "Azerbaydzhan": "Azerbaijan",
        "Moldova": "Moldova",
        "Kirgiziya": "Kyrgyzstan",
        "Tadzhikistan": "Tajikistan",
        "Turkmenistan": "Turkmenistan",
        "Uzbekistan": "Uzbekistan",
    }
    return _ENGLISH_NAMES.get(result, result)

def detect_location(timeout=5):
    try:
        url = "http://ip-api.com/json/?fields=country,regionName,city,isp,query&lang=ru"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; DomainChecker/1.0)",
            },
        )
        resp = urllib.request.urlopen(req, timeout=timeout)
        data = json.loads(resp.read().decode("utf-8", errors="replace"))
        parts = []
        city = data.get("city", "").strip()
        region = data.get("regionName", "").strip()
        country = data.get("country", "").strip()
        isp = data.get("isp", "").strip()

        def _norm(s):
            return s.lower().replace("\u0301", "")

        def _is_cyrillic(s):
            return any("\u0400" <= c <= "\u04FF" for c in s)

        city_cyrillic = _is_cyrillic(city)
        region_cyrillic = _is_cyrillic(region)

        cross_script_dup = city_cyrillic != region_cyrillic and abs(
            len(city) - len(region)
        ) <= max(2, len(region) // 3)
        if city and _norm(city) != _norm(region) and not cross_script_dup:
            parts.append(city)
        if region:
            parts.append(region)
        if country:
            parts.append(country)
        if parts:
            ip = data.get("query", "")
            location = ", ".join(parts)

            if any("\u0400" <= c <= "\u04FF" for c in location):
                location = ", ".join(_translit(p) for p in parts)
            # Do not append public IP to location - not persisted in CSV/upload.
            return location, isp, ip
    except Exception:
        pass
    return "", "", ""

def get_system_dns_servers():
    servers = []

    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8") as rc:
            for line in rc:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    servers.append(parts[1])
    except Exception:
        pass

    if not servers and sys.platform == "darwin":
        try:
            out = subprocess.check_output(
                ["scutil", "--dns"],
                universal_newlines=True,
                errors="ignore",
            )
            for line in out.splitlines():
                m = re.match(r"\s*nameserver\[\d+\]\s*:\s*(\d+\.\d+\.\d+\.\d+)", line)
                if m and m.group(1) not in servers:
                    servers.append(m.group(1))
        except Exception:
            pass

    if not servers and sys.platform == "win32":
        try:
            popen_kw = {"creationflags": 0x08000000}
            out = subprocess.check_output(
                ["ipconfig", "/all"],
                universal_newlines=True,
                errors="ignore",
                **popen_kw,
            )
            for line in out.splitlines():
                line = line.strip()
                if "DNS" in line and ":" in line:
                    addr = line.split(":", 1)[1].strip()
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", addr):
                        servers.append(addr)
        except Exception:
            pass

    return servers

def find_list_files(directory):
    pattern = os.path.join(directory, URL_CHECK_LISTS_DIR, "list_*")
    return sorted(glob.glob(pattern))

def _to_punycode(domain):
    try:
        return domain.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return domain

def read_domains(filepath):
    domains = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            for prefix in ("https://", "http://", "//"):
                if line.startswith(prefix):
                    line = line[len(prefix) :]
            line = line.split("/")[0].strip()
            if line:
                domains.append((line, _to_punycode(line)))
    return domains


LIST_WHITE_FILENAME = "list_white_domains.txt"


def _row_reachable_verdict(row):
    return row.get("accessible") in ("YES", "PARTIAL")


def _print_final_verdict(results, script_dir):
    """Summarize whitelist vs control reachability and heuristic whitelist verdict."""
    white_name = LIST_WHITE_FILENAME
    white_path = os.path.join(script_dir, URL_CHECK_LISTS_DIR, white_name)

    white_in_file = 0
    if os.path.isfile(white_path):
        white_in_file = len(read_domains(white_path))

    white_rows = [r for r in results if r.get("source_file") == white_name]
    control_rows = [r for r in results if r.get("source_file") != white_name]

    n_white = len(white_rows)
    n_control = len(control_rows)

    reachable_white = sum(1 for r in white_rows if _row_reachable_verdict(r))
    reachable_control = sum(1 for r in control_rows if _row_reachable_verdict(r))

    pct_w = round(100.0 * reachable_white / n_white) if n_white else 0
    pct_c = round(100.0 * reachable_control / n_control) if n_control else 0

    line1 = "{}% of sites from the whitelist are accessible, {}% of sites from the control list are accessible.".format(
        pct_w, pct_c
    )

    suggests_whitelist = (
        white_in_file >= 80
        and n_control > 0
        and reachable_control <= 0.02 * n_control
    )
    if suggests_whitelist:
        line2 = 'IMPORTANT: There is a high probability that your network uses whitelists!'
    else:
        line2 = "It seems your network doesn't use whitelists."

    print()
    print("  FINAL VERDICT: {} {}".format(line1, line2))


class _ProbeHandle(object):
    __slots__ = ("thread", "box", "stop", "resolvers", "started", "total")

    def __init__(self, thread, box, stop, resolvers, started, total):
        self.thread = thread
        self.box = box
        self.stop = stop
        self.resolvers = resolvers
        self.started = started
        self.total = total


def _probe_servers_path(script_dir):
    return os.path.join(script_dir, *DNS_PROBE_SERVERS_FILE.split("/"))


def _probe_domains(tasks):
    seen = set()
    domains = []
    for _original, ascii_domain, _src in tasks:
        name = (ascii_domain or "").strip().rstrip(".").lower()
        if name and name not in seen:
            seen.add(name)
            domains.append(name)
    return domains


def _start_dns_probe(script_dir, tasks):
    if dns_probe is None or not DNS_PROBE_ENABLED:
        return None
    resolvers = dns_probe.load_resolvers(_probe_servers_path(script_dir))
    if not resolvers:
        return None
    domains = _probe_domains(tasks)
    if not domains:
        return None

    box = {}
    stop = threading.Event()
    qps = {
        dns_probe.KIND_GLOBAL: DNS_PROBE_QPS_GLOBAL,
        dns_probe.KIND_RUSSIAN: DNS_PROBE_QPS_RUSSIAN,
        dns_probe.KIND_NSDI: DNS_PROBE_QPS_RUSSIAN,
    }

    def worker():
        try:
            box["result"] = dns_probe.probe(
                domains,
                resolvers,
                timeout=DNS_PROBE_TIMEOUT,
                attempts=DNS_PROBE_ATTEMPTS,
                qps_by_kind=qps,
                max_inflight=DNS_PROBE_MAX_INFLIGHT,
                max_inflight_per_server=DNS_PROBE_MAX_INFLIGHT_PER_SERVER,
                breaker_failures=DNS_PROBE_BREAKER_FAILURES,
                max_seconds=DNS_PROBE_MAX_SECONDS,
                stop_event=stop,
            )
        except Exception as exc:
            box["error"] = str(exc).replace("\n", " ")

    thread = threading.Thread(target=worker, name="dns-probe")
    thread.daemon = True
    thread.start()
    return _ProbeHandle(
        thread, box, stop, resolvers, time.monotonic(), len(domains)
    )


def _finish_dns_probe(handle):
    if handle is None:
        return None

    def _join(timeout):
        try:
            handle.thread.join(timeout)
            return True
        except KeyboardInterrupt:
            return False

    interrupted = False
    if handle.thread.is_alive():
        remaining = DNS_PROBE_MAX_SECONDS - (time.monotonic() - handle.started)
        print(
            "  Finishing DNS probe ({} resolvers, up to {}s left) ...".format(
                len(handle.resolvers), max(0, int(remaining))
            )
        )
        if not _join(max(5.0, remaining + 15.0)):
            interrupted = True
    if handle.thread.is_alive() or interrupted:
        if interrupted:
            print("  DNS probe interrupted; keeping whatever finished")
        handle.stop.set()
        _join(2.0 if interrupted else 20.0)
    error = handle.box.get("error")
    if error:
        print("  DNS probe failed: {}".format(error))
    return handle.box.get("result")


def _apply_dns_probe(results, probe_result):
    if dns_probe is None:
        return
    blank = dict(dns_probe.EMPTY_COLUMNS)
    if probe_result is None:
        for row in results:
            row.update(blank)
        return
    resolvers = probe_result.resolvers
    for row in results:
        outcomes = probe_result.by_domain.get(row.get("probe_key", ""))
        if outcomes:
            row.update(dns_probe.format_columns(outcomes, resolvers))
        else:
            row.update(blank)


def _print_dns_probe_summary(probe_result):
    if probe_result is None:
        return
    print()
    print(
        "  DNS probe   : {}/{} lookups over {} resolvers in {:.1f}s".format(
            probe_result.queries_done,
            probe_result.queries_total,
            len(probe_result.resolvers),
            probe_result.elapsed,
        )
    )
    if probe_result.dead:
        print(
            "  Stopped     : {} (no replies for a while)".format(
                ", ".join(probe_result.dead)
            )
        )
    if probe_result.conflicts:
        print(
            "  Disagreed   : {} (later packet for the same query)".format(
                probe_result.conflicts
            )
        )
    if probe_result.stopped_early:
        print("  Note        : probe hit its time limit")


def _resolve_skip_check_csv_path(results_dir):
    """Prefer OUTPUT_CSV if that file exists; otherwise newest results/check_results_*.csv.

    Returns (path_or_None, meta): meta is 'explicit', 'latest', or missing OUTPUT_CSV path.
    """
    if os.path.isabs(OUTPUT_CSV):
        explicit = OUTPUT_CSV
    else:
        explicit = os.path.join(results_dir, OUTPUT_CSV)
    if os.path.isfile(explicit):
        return explicit, "explicit"
    pattern = os.path.join(results_dir, "check_results_*.csv")
    paths = sorted(
        glob.glob(pattern),
        key=lambda p: os.path.getmtime(p),
        reverse=True,
    )
    if paths:
        return paths[0], "latest"
    return None, explicit

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__)) or "."
    results_dir = os.path.join(script_dir, RESULTS_DIR)

    ver = _read_version_text(script_dir)
    remote = _fetch_latest_version()
    _print_version_block(ver, remote)
    print()

    if SKIP_CHECK:
        out_path, resolve_meta = _resolve_skip_check_csv_path(results_dir)
        if not out_path:
            hint = ""
            if resolve_meta is not None:
                hint = " (OUTPUT_CSV not found: {})".format(resolve_meta)
            print(
                "ERROR: SKIP_CHECK: no check_results_*.csv in {}{}".format(
                    results_dir, hint
                )
            )
            pause_if_windows()
            sys.exit(1)
        print("Domain Checker - SKIP_CHECK (send only / re-send)")
        print("=" * 55)
        print("  CSV        : {}".format(out_path))
        if resolve_meta == "latest":
            print(
                "  Note       : OUTPUT_CSV not found; using newest check_results_*.csv"
            )
        print()
        # Re-send asks for the token again (no re-scan, no config editing).
        upload_token = prompt_upload_token_before_scan(for_resend=True)
        if upload_token:
            print("  Sending results ...")
            code = _run_send_results(script_dir, out_path, upload_token)
            if code != 0:
                pause_if_windows()
                sys.exit(code)
        else:
            print("  No token; nothing to upload. CSV kept.")
        print()
        if not remote:
            remote = _fetch_latest_version()
        _print_version_block(ver, remote)
        return

    # Volunteer UX: token before scan. Empty = local CSV only.
    upload_token = prompt_upload_token_before_scan()

    server = DNS_SERVER if DNS_SERVER else None

    sys_nameservers = get_system_dns_servers() if not server else []

    # Lookup may return public IP for console debug only; never persist it.
    location, isp, _ip_address = detect_location()

    print("Domain Checker")
    print("=" * 55)
    if location:
        print("  Location   : {}".format(location))
    if isp:
        print("  Provider   : {}".format(isp))
    if server:
        print("  DNS server : {}".format(server))
    else:
        print(
            "  DNS server : system default ({})".format(
                ", ".join(sys_nameservers) if sys_nameservers else "unknown"
            )
        )
    print("  Workers    : {}".format(MAX_WORKERS))
    print("  Output     : {}/{}".format(RESULTS_DIR, OUTPUT_CSV))
    print()

    list_files = find_list_files(script_dir)
    if not list_files:
        print(
            "ERROR: no files starting with 'list_' found in {}/{}".format(
                script_dir, URL_CHECK_LISTS_DIR
            )
        )
        pause_if_windows()
        sys.exit(1)

    tasks = []
    seen = set()
    for fpath in list_files:
        fname = os.path.basename(fpath)
        domains = read_domains(fpath)
        print("  {} - {} domains".format(fname, len(domains)))
        for original, ascii_domain in domains:
            key = (ascii_domain, fname)
            if key not in seen:
                seen.add(key)
                tasks.append((original, ascii_domain, fname))

    if CHECK_LIMIT_N > 0:
        tasks = tasks[:CHECK_LIMIT_N]

    total = len(tasks)
    print(
        "\nTotal: {} domain checks{}\n".format(
            total, " (limited to {})".format(CHECK_LIMIT_N) if CHECK_LIMIT_N > 0 else ""
        )
    )

    probe_handle = _start_dns_probe(script_dir, tasks)
    if probe_handle is not None:
        print(
            "  DNS probe  : {} resolvers x {} unique domains (in background)\n".format(
                len(probe_handle.resolvers), probe_handle.total
            )
        )

    # No check_ip_address column - end-user public IP is not persisted.
    fieldnames = [
        "domain",
        "check_timestamp",
        "dns_resolved_ips",
        "dns_time_ms",
        "dns_error",
        "tcp_connect_time_ms",
        "ssl_valid",
        "ssl_issuer",
        "ssl_error",
        "http_status",
        "http_url",
        "http_redirect_url",
        "http_time_ms",
        "http_content_bytes",
        "http_error",
        "protocol",
        "final_domain",
        "http_title",
        "content_hash",
        "source_file",
        "accessible",
        "check_location",
        "check_provider",
        "check_version",
    ]
    if dns_probe is not None:
        fieldnames.extend(dns_probe.COLUMNS)
        fieldnames.extend(dns_probe.META_COLUMNS)

    results = []
    done = 0
    t_start = time.monotonic()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {}
        for original, ascii_domain, src in tasks:
            f = pool.submit(check_domain, ascii_domain, src, server, original)
            futures[f] = (original, ascii_domain, src)

        for f in as_completed(futures):
            original, ascii_domain, src = futures[f]
            done += 1
            try:
                row = f.result()
                row["probe_key"] = (ascii_domain or "").strip().rstrip(".").lower()
                results.append(row)
                flag = {"YES": "+", "PARTIAL": "~", "NO": "-"}.get(
                    row["accessible"], "!"
                )
                print(
                    "  [{:>4}/{}] {} {:<40s}  dns={:>7s}ms  http={:>8s}ms  [{}]".format(
                        done,
                        total,
                        flag,
                        original,
                        row["dns_time_ms"] or "-",
                        row["http_time_ms"] or "-",
                        src,
                    )
                )
            except Exception as exc:
                results.append({k: "" for k in fieldnames})
                results[-1].update(
                    domain=original,
                    source_file=src,
                    dns_error=str(exc),
                    accessible="ERROR",
                    probe_key=(ascii_domain or "").strip().rstrip(".").lower(),
                )
                print(
                    "  [{:>4}/{}] ! {:<40s}  ERROR: {}  [{}]".format(
                        done, total, original, exc, src
                    )
                )

    elapsed = time.monotonic() - t_start

    probe_result = _finish_dns_probe(probe_handle)
    _apply_dns_probe(results, probe_result)

    results.sort(key=lambda r: (r["source_file"], r["domain"]))

    os.makedirs(results_dir, exist_ok=True)
    out_path = os.path.join(results_dir, OUTPUT_CSV)
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        if results:
            results[0]["check_location"] = location
            results[0]["check_provider"] = isp
            results[0]["check_version"] = _read_version_text(script_dir)
            if dns_probe is not None and probe_result is not None:
                results[0]["dns_probe_resolvers"] = dns_probe.format_roster(
                    probe_result.resolvers
                )
                results[0]["dns_probe_meta"] = dns_probe.format_meta(probe_result)
        w.writerows(results)

    yes = sum(1 for r in results if r["accessible"] == "YES")
    part = sum(1 for r in results if r["accessible"] == "PARTIAL")
    no = sum(1 for r in results if r["accessible"] == "NO")
    errs = sum(1 for r in results if r["accessible"] == "ERROR")

    print()
    print("=" * 55)
    print("  Finished in {:.1f}s".format(elapsed))
    print("  Accessible   : {}".format(yes))
    print("  Partial      : {}".format(part))
    print("  Blocked/Down : {}".format(no))
    print("  Errors       : {}".format(errs))
    print("  Total        : {}".format(total))
    _print_dns_probe_summary(probe_result)
    print()
    print("  CSV saved to: {}".format(out_path))

    if upload_token:
        print()
        print("  Sending results (hop-first) ...")
        code = _run_send_results(script_dir, out_path, upload_token)
        if code != 0:
            print(
                "  Upload failed; CSV kept. Re-send later with "
                "python3 app/send_results.py (asks for token again)."
            )
            print(
                "  Helpdesk fallback: send the unencrypted CSV via support "
                "(not the zip)."
            )
            # Do not exit non-zero after a finished scan: hop-down must not
            # block the volunteer from keeping/using the CSV.
    else:
        print()
        print("  Local-only run. To upload later: python3 app/send_results.py")
        print("  (you will be asked for a one-time token)")
        print(
            "  Helpdesk fallback: send the unencrypted CSV via support "
            "(not the zip)."
        )

    print()
    if not remote:
        remote = _fetch_latest_version()
    _print_version_block(ver, remote)
    print()
    _print_final_verdict(results, script_dir)

if __name__ == "__main__":
    main()
