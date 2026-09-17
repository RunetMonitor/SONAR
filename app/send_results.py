#!/usr/bin/env python3
"""Build a payload zip from check_results CSV and upload it.

Tries each strategy listed in SEND_METHODS_ORDER (config.py), in order.
For "receiver": hop-first POST zip to each RECEIVER_HOPS entry with X-Web-Token.
For "direct": HTTPS POST to SEND_RESULT_ENDPOINT with X-Web-Token.

Auth is the one-time upload token (zip password and X-Web-Token). No separate
volunteer X-Auth-Token or shared ZIP_PASSWORD.

Usage:
    python send_results.py [csv_file]

If csv_file is omitted, the newest results/check_results_*.csv is used (by mtime).
run.py always passes the CSV path explicitly after a run.
Re-send asks for the one-time token again (no re-scan, no config editing).
"""

from __future__ import annotations

import csv
import glob
import io
import json
import re
import secrets
import ssl
import struct
import sys
import urllib.error
import urllib.request
import zipfile
import zlib
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_APP_DIR = Path(__file__).resolve().parent
_ROOT_DIR = _APP_DIR.parent
if str(_ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(_ROOT_DIR))
if str(_APP_DIR) not in sys.path:
    sys.path.insert(0, str(_APP_DIR))

from run import get_system_dns_servers
from config import (
    DNS_SERVER,
    RECEIVER_HOPS,
    RESULTS_DIR,
    SEND_METHODS_ORDER,
    SEND_RESULT_DIRECT_TIMEOUT_SEC,
    SEND_RESULT_ENDPOINT,
    TOKEN_SOURCE_TEXT,
)
from upload_token import (
    normalize_pasted_token,
    verify_upload_token,
)

try:
    import dns_probe
except ImportError:
    dns_probe = None

STRIP_EMPTY_DOMAIN_FIELDS = True

_SCRIPT_DIR = _ROOT_DIR

_JSON_KWARGS: Dict[str, Any] = {"separators": (",", ":"), "ensure_ascii": False}

STATUS_MAP = {
    "YES": "accessible",
    "PARTIAL": "partial",
    "NO": "blocked",
    "ERROR": "error",
}

PROBE_META_COLUMNS = ("dns_probe_resolvers", "dns_probe_meta")

_EXCLUDED = {
    "domain",
    "accessible",
    "check_location",
    "check_provider",
    "check_ip_address",
    "check_version",
    "probe_key",
}
_EXCLUDED.update(PROBE_META_COLUMNS)

# Trailing " (public IP)" on region strings from older clients.
_REGION_IP_SUFFIX_RE = re.compile(
    r"^(.*?)\s*\(\s*([0-9a-fA-F:.]+)\s*\)\s*$"
)
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _looks_like_public_ip(value: str) -> bool:
    s = (value or "").strip()
    if not s:
        return False
    if _IPV4_RE.match(s):
        return True
    if ":" in s and re.match(r"^[0-9a-fA-F:]+$", s):
        return True
    return False


def sanitize_region(region: str) -> str:
    """Drop trailing public-IP suffix from region; keep city/region/country text."""
    if not region:
        return ""
    text = str(region).strip()
    m = _REGION_IP_SUFFIX_RE.match(text)
    if m and _looks_like_public_ip(m.group(2)):
        return m.group(1).strip()
    return text


def _json_dump_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, **_JSON_KWARGS).encode("utf-8")


_crctable: Optional[List[int]] = None


def _crc32_byte(ch: int, crc: int) -> int:
    global _crctable
    if _crctable is None:

        def _gen_crc(c: int) -> int:
            for _ in range(8):
                if c & 1:
                    c = (c >> 1) ^ 0xEDB88320
                else:
                    c >>= 1
            return c

        _crctable = list(map(_gen_crc, range(256)))
    return (crc >> 8) ^ _crctable[(crc ^ ch) & 0xFF]


def _zipcrypto_encrypt(pwd: bytes, plaintext: bytes) -> bytes:
    """PKWARE traditional ZipCrypto (same keystream as zipfile decryption)."""
    key0 = 305419896
    key1 = 591751049
    key2 = 878082192

    def update_keys(c: int) -> None:
        nonlocal key0, key1, key2
        key0 = _crc32_byte(c, key0)
        key1 = (key1 + (key0 & 0xFF)) & 0xFFFFFFFF
        key1 = (key1 * 134775813 + 1) & 0xFFFFFFFF
        key2 = _crc32_byte(key1 >> 24, key2)

    for b in pwd:
        update_keys(b)

    out = bytearray()
    for p in plaintext:
        k = key2 | 2
        c = p ^ (((k * (k ^ 1)) >> 8) & 0xFF)
        update_keys(p)
        out.append(c)
    return bytes(out)


def _payload_zip_bytes(payload: Dict[str, Any], zip_password: str) -> bytes:
    raw = _json_dump_bytes(payload)
    pwd = zip_password.encode("utf-8")
    crc = zlib.crc32(raw) & 0xFFFFFFFF
    comp = zlib.compressobj(level=6, wbits=-zlib.MAX_WBITS)
    compressed = comp.compress(raw) + comp.flush()
    crypt_plain = secrets.token_bytes(11) + bytes([(crc >> 24) & 0xFF])
    encrypted_body = _zipcrypto_encrypt(pwd, crypt_plain + compressed)

    zinfo = zipfile.ZipInfo("payload.json", datetime.now().timetuple()[:6])
    zinfo.compress_type = zipfile.ZIP_DEFLATED
    zinfo.flag_bits = zipfile._MASK_ENCRYPTED
    zinfo.CRC = crc
    zinfo.compress_size = len(encrypted_body)
    zinfo.file_size = len(raw)
    zinfo.external_attr = 0o600 << 16

    buf = io.BytesIO()
    header_offset = 0
    buf.write(zinfo.FileHeader(zip64=False))
    buf.write(encrypted_body)

    cent_dir_offset = buf.tell()
    dt = zinfo.date_time
    dosdate = (dt[0] - 1980) << 9 | dt[1] << 5 | dt[2]
    dostime = dt[3] << 11 | dt[4] << 5 | (dt[5] // 2)
    filename, flag_bits = zinfo._encodeFilenameFlags()
    extra_data = zinfo.extra
    centdir = struct.pack(
        zipfile.structCentralDir,
        zipfile.stringCentralDir,
        zinfo.create_version,
        zinfo.create_system,
        zinfo.extract_version,
        zinfo.reserved,
        flag_bits,
        zinfo.compress_type,
        dostime,
        dosdate,
        zinfo.CRC,
        zinfo.compress_size,
        zinfo.file_size,
        len(filename),
        len(extra_data),
        len(zinfo.comment),
        0,
        zinfo.internal_attr,
        zinfo.external_attr,
        header_offset,
    )
    buf.write(centdir)
    buf.write(filename)
    buf.write(extra_data)
    buf.write(zinfo.comment)

    cent_dir_size = buf.tell() - cent_dir_offset
    buf.write(
        struct.pack(
            zipfile.structEndArchive,
            zipfile.stringEndArchive,
            0,
            0,
            1,
            1,
            cent_dir_size,
            cent_dir_offset,
            0,
        )
    )
    return buf.getvalue()


def _multipart_zip_body(
    zip_bytes: bytes,
    boundary: str,
    field_name: str = "file",
    filename: str = "results.zip",
) -> bytes:
    b = boundary.encode("ascii")
    nl = b"\r\n"
    disp = (
        b'Content-Disposition: form-data; name="'
        + field_name.encode("ascii")
        + b'"; filename="'
        + filename.encode("utf-8")
        + b'"'
    )
    head = nl.join(
        (
            b"--" + b,
            disp,
            b"Content-Type: application/zip",
            b"",
        )
    ) + nl
    tail = nl + b"--" + b + b"--" + nl
    return head + zip_bytes + tail


def _zip_multipart_body(zip_bytes: bytes, zip_filename: str) -> Tuple[bytes, str]:
    boundary = secrets.token_hex(16)
    body = _multipart_zip_body(zip_bytes, boundary, filename=zip_filename)
    ct = "multipart/form-data; boundary={}".format(boundary)
    return body, ct


def _try_direct_upload(
    endpoint: str,
    zip_bytes: bytes,
    zip_filename: str,
    web_token: str,
) -> Tuple[bool, str]:
    body, ct = _zip_multipart_body(zip_bytes, zip_filename)
    headers = {
        "X-Web-Token": web_token,
        "User-Agent": "DomainChecker/1.0",
        "Accept": "*/*",
        "Content-Type": ct,
    }
    req = urllib.request.Request(endpoint, data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(
            req, timeout=SEND_RESULT_DIRECT_TIMEOUT_SEC
        ) as resp:
            text = resp.read().decode("utf-8", errors="replace")
            if 200 <= resp.getcode() < 300:
                return True, "OK ({}): {}".format(resp.getcode(), text)
            return False, "HTTP {}: {}".format(resp.getcode(), text)
    except urllib.error.HTTPError as e:
        err = ""
        try:
            err = e.read().decode("utf-8", errors="replace")
        except Exception:
            err = str(e.reason or "")
        return False, "HTTP {}: {} {}".format(e.code, e.reason, err[:800])
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return False, str(e)


def _write_inspection_zip(zip_bytes: bytes, csv_path: Path) -> Path:
    out_dir = _SCRIPT_DIR / RESULTS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / (csv_path.stem + ".zip")
    path.write_bytes(zip_bytes)
    return path


def _delete_zip_quietly(zip_path: Optional[Path]) -> None:
    if zip_path is None:
        return
    try:
        if zip_path.is_file():
            zip_path.unlink()
    except OSError:
        pass


def get_dns_servers() -> List[str]:
    if DNS_SERVER:
        return [DNS_SERVER]
    return get_system_dns_servers()


def _resolve_csv_path() -> Path:
    if len(sys.argv) >= 2 and sys.argv[1].strip():
        p = Path(sys.argv[1].strip())
        return p if p.is_absolute() else (_SCRIPT_DIR / p)
    results = _SCRIPT_DIR / RESULTS_DIR
    pattern = str(results / "check_results_*.csv")
    paths = sorted(
        glob.glob(pattern),
        key=lambda x: Path(x).stat().st_mtime,
        reverse=True,
    )
    if not paths:
        raise FileNotFoundError("no check_results_*.csv in {}".format(results))
    return Path(paths[0])


def _probe_summary(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    roster = ""
    meta = ""
    for row in rows:
        roster = roster or (row.get("dns_probe_resolvers") or "").strip()
        meta = meta or (row.get("dns_probe_meta") or "").strip()
        if roster and meta:
            break
    if not roster and not meta:
        return {}

    summary: Dict[str, Any] = {}
    if roster:
        summary["resolvers_raw"] = roster
    if meta:
        summary["meta_raw"] = meta
    if dns_probe is not None:
        if roster:
            summary["resolvers"] = dns_probe.parse_roster(roster)
        if meta:
            summary["meta"] = dns_probe.parse_meta(meta)
    return summary


def _build_payload(rows: List[Dict[str, Any]], csv_path: Path) -> Dict[str, Any]:
    counts = {"YES": 0, "PARTIAL": 0, "NO": 0, "ERROR": 0}
    for r in rows:
        v = r.get("accessible", "")
        if v in counts:
            counts[v] += 1

    first = rows[0] if rows else {}
    domains = []
    for r in rows:
        if STRIP_EMPTY_DOMAIN_FIELDS:
            entry = {
                k: v
                for k, v in r.items()
                if k not in _EXCLUDED and v not in ("", None)
            }
        else:
            entry = {k: v for k, v in r.items() if k not in _EXCLUDED}
        entry["name"] = r["domain"]
        entry["status"] = STATUS_MAP.get(r.get("accessible", ""), "error")
        domains.append(entry)

    result_data: Dict[str, Any] = {"domains": domains}
    probe_summary = _probe_summary(rows)
    if probe_summary:
        result_data["dns_probe"] = probe_summary

    # Omit end-user ip_address from upload. Region is sanitized (no public IP suffix).
    return {
        "result_data": result_data,
        "dns_servers": get_dns_servers(),
        "region": sanitize_region(first.get("check_location", "")),
        "provider": first.get("check_provider", ""),
        "accessible": counts["YES"],
        "partial": counts["PARTIAL"],
        "blocked_down": counts["NO"],
        "errors": counts["ERROR"],
        "total": len(rows),
        "version": first.get("check_version", ""),
        "file_name": csv_path.name,
    }


def _hop_url(hop: Dict[str, Any]) -> str:
    return "{}://{}:{}{}".format(
        hop.get("scheme", "http"),
        hop["host"],
        hop.get("port", 80),
        hop.get("path", "/upload"),
    )


class _HttpResponse:
    """Minimal response object so hop handling can print JSON or text."""

    def __init__(self, status_code: int, body: str) -> None:
        self.status_code = status_code
        self.text = body

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300

    def json(self) -> Any:
        return json.loads(self.text)


def _ssl_context(verify: bool) -> Optional[ssl.SSLContext]:
    if verify:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _post_receiver_hop(
    hop: Dict[str, Any],
    upload_filename: str,
    zip_bytes: bytes,
    web_token: str,
) -> Tuple[int, Optional[_HttpResponse]]:
    url = _hop_url(hop)
    body, ct = _zip_multipart_body(zip_bytes, upload_filename)
    headers = {
        "X-Web-Token": web_token,
        "User-Agent": "DomainChecker/1.0",
        "Accept": "*/*",
        "Content-Type": ct,
    }
    timeout = float(hop.get("timeout_sec", 300.0))
    verify = not bool(hop.get("insecure_tls", False))
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(
            req, timeout=timeout, context=_ssl_context(verify)
        ) as resp:
            text = resp.read().decode("utf-8", errors="replace")
            response = _HttpResponse(resp.getcode(), text)
    except urllib.error.HTTPError as e:
        err = ""
        try:
            err = e.read().decode("utf-8", errors="replace")
        except Exception:
            err = str(e.reason or "")
        response = _HttpResponse(e.code, err)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        print("error: hop request failed: {}".format(e), file=sys.stderr)
        return 1, None
    return (0 if response.ok else 1), response


def _try_receiver_hops(
    upload_filename: str,
    zip_bytes: bytes,
    web_token: str,
) -> Tuple[bool, str]:
    if not RECEIVER_HOPS:
        return False, "no RECEIVER_HOPS configured"
    last_err = ""
    for idx, hop in enumerate(RECEIVER_HOPS):
        url = _hop_url(hop)
        print("POST (hop {}/{}) -> {}".format(idx + 1, len(RECEIVER_HOPS), url))
        exit_code, response = _post_receiver_hop(
            hop, upload_filename, zip_bytes, web_token
        )
        if response is None:
            last_err = "hop: request error (see above)"
            print("Hop upload failed: no response")
            continue
        print("status: {}".format(response.status_code))
        try:
            print(response.json())
        except ValueError:
            print(response.text)
        if response.ok:
            return True, "OK hop {}: {}".format(url, response.status_code)
        snippet = (
            response.text
            if len(response.text) < 500
            else response.text[:500] + "..."
        )
        last_err = "hop HTTP {}: {}".format(response.status_code, snippet)
        print("Hop upload failed: {}".format(last_err))
    return False, last_err or "all hops failed"


def prompt_upload_token_for_send() -> Optional[str]:
    """Ask for one-time token for upload/re-send. Empty -> None (abort upload)."""
    print()
    print(TOKEN_SOURCE_TEXT)
    print(
        "Enter your one-time upload token to send results "
        "(or leave empty to cancel upload)."
    )
    try:
        raw = input("One-time token: ")
    except EOFError:
        raw = ""
    token = normalize_pasted_token(raw)
    if not token:
        return None
    ok, reason = verify_upload_token(token)
    if not ok:
        print("error: bad token format ({})".format(reason), file=sys.stderr)
        print(TOKEN_SOURCE_TEXT, file=sys.stderr)
        return ""
    return token


def pause_if_windows() -> None:
    if sys.platform == "win32":
        try:
            input("Press Enter to exit...")
        except EOFError:
            pass


def main(upload_token: Optional[str] = None) -> int:
    """Upload CSV results. upload_token: if None, prompt; if provided, use as-is."""
    try:
        csv_path = _resolve_csv_path()
    except FileNotFoundError as e:
        print("error: {}".format(e), file=sys.stderr)
        print(
            "Usage: python send_results.py [csv_file]",
            file=sys.stderr,
        )
        pause_if_windows()
        return 2

    if not csv_path.is_file():
        print("error: file not found: {}".format(csv_path), file=sys.stderr)
        pause_if_windows()
        return 2

    if upload_token is None:
        upload_token = prompt_upload_token_for_send()
        if upload_token is None:
            print("No token entered; upload cancelled. CSV kept at: {}".format(csv_path))
            print(
                "Helpdesk fallback: send the unencrypted CSV via support "
                "(not the zip)."
            )
            return 0
        if upload_token == "":
            pause_if_windows()
            return 2
    else:
        upload_token = normalize_pasted_token(upload_token)
        ok, reason = verify_upload_token(upload_token)
        if not ok:
            print("error: bad token format ({})".format(reason), file=sys.stderr)
            print(TOKEN_SOURCE_TEXT, file=sys.stderr)
            pause_if_windows()
            return 2

    print("Sending results from: {}".format(csv_path))

    with open(csv_path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))

    payload = _build_payload(rows, csv_path)
    zip_filename = Path(csv_path).stem + ".zip"

    # Direct API expects sent_via_proxy in the JSON (empty string = not via proxy).
    direct_payload = dict(payload)
    direct_payload["sent_via_proxy"] = ""
    direct_zip = _payload_zip_bytes(direct_payload, upload_token)

    receiver_zip = _payload_zip_bytes(payload, upload_token)
    zip_path = _write_inspection_zip(receiver_zip, csv_path)

    print(
        "ZIP:    {} ({:,} bytes on disk, hop payload)".format(
            zip_path, len(receiver_zip)
        )
    )

    if not SEND_METHODS_ORDER:
        print("error: SEND_METHODS_ORDER is empty", file=sys.stderr)
        _delete_zip_quietly(zip_path)
        pause_if_windows()
        return 2

    last_err = ""
    success = False

    try:
        for raw_method in SEND_METHODS_ORDER:
            method = str(raw_method).strip().lower()
            if method == "direct":
                print("POST (direct) -> {}".format(SEND_RESULT_ENDPOINT))
                ok, msg = _try_direct_upload(
                    SEND_RESULT_ENDPOINT,
                    direct_zip,
                    zip_filename,
                    upload_token,
                )
                if ok:
                    print(msg)
                    success = True
                    break
                last_err = msg
                print("Direct upload failed: {}".format(msg))
            elif method in ("receiver", "hop"):
                ok, msg = _try_receiver_hops(zip_filename, receiver_zip, upload_token)
                if ok:
                    print(msg)
                    success = True
                    break
                last_err = msg
            else:
                print(
                    "warning: unknown SEND_METHODS_ORDER entry {!r}, skipping".format(
                        raw_method
                    ),
                    file=sys.stderr,
                )
    finally:
        # Always remove local zip (success or failure); keep CSV for Helpdesk / re-send.
        _delete_zip_quietly(zip_path)

    if success:
        print("Upload succeeded. Local zip removed. CSV kept at: {}".format(csv_path))
        return 0

    print("All send methods failed. Last: {}".format(last_err), file=sys.stderr)
    print("CSV kept at: {}".format(csv_path))
    print(
        "You can re-send later: python3 app/send_results.py {}".format(csv_path)
    )
    print("(you will be asked for the one-time token again)")
    print(
        "Helpdesk fallback: send the unencrypted CSV via support (not the zip)."
    )
    pause_if_windows()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
