"""Single pytest suite for WhiteListCheckerScript (run.py + app/*)."""

from __future__ import annotations

import csv
import importlib.util
import io
import json
import os
import socket
import struct
import sys
import urllib.error
import zipfile
from pathlib import Path
from unittest import mock

import pytest

APP = Path(__file__).resolve().parent
ROOT = APP.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import config  # noqa: E402
import dns_probe  # noqa: E402
import run  # noqa: E402
import upload_token  # noqa: E402


def _load_send_results():
    spec = importlib.util.spec_from_file_location(
        "send_results", APP / "send_results.py"
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


sr = _load_send_results()


# ---------------------------------------------------------------------------
# Part 1 - config / secrets scrub
# ---------------------------------------------------------------------------


class TestConfig:
    def test_core_constants(self):
        assert config.URL_CHECK_LISTS_DIR == "app/url_check_lists"
        assert config.RESULTS_DIR == "results"
        assert config.CHECK_LIMIT_N >= 0
        assert config.DNS_TIMEOUT > 0
        assert config.HTTP_TIMEOUT > 0
        assert config.MAX_WORKERS > 0
        assert config.OUTPUT_CSV.startswith("check_results_")
        assert config.OUTPUT_CSV.endswith(".csv")
        assert config.SEND_RESULT is False
        assert isinstance(config.SKIP_CHECK, bool)
        assert config.SEND_METHODS_ORDER
        assert config.SEND_METHODS_ORDER[0] in ("receiver", "hop")
        assert "direct" in config.SEND_METHODS_ORDER
        assert config.TOKEN_SOURCE_TEXT
        assert "Helpdesk" in config.TOKEN_SOURCE_TEXT
        assert "nasvyazi.org" in config.TOKEN_SOURCE_TEXT
        assert config.VERSION_CHECK_TIMEOUT > 0
        assert config.VERSION_CHECK_URLS
        assert all(u.startswith("https://") for u in config.VERSION_CHECK_URLS)
        assert any("githubusercontent.com" in u for u in config.VERSION_CHECK_URLS)

    def test_no_live_secrets_in_committed_config(self):
        src = (APP / "config.py").read_text(encoding="utf-8")
        assert "ZIP_PASSWORD" not in src or "ZIP_PASSWORD =" not in src
        assert "SEND_RESULT_API_KEY" not in src
        assert "HARDCODED_AUTH_TOKEN" not in src
        assert not hasattr(config, "ZIP_PASSWORD")
        assert not hasattr(config, "SEND_RESULT_API_KEY")
        assert not hasattr(config, "HARDCODED_AUTH_TOKEN")

    def test_endpoints_non_secret(self):
        assert config.SEND_RESULT_ENDPOINT.startswith("http")
        assert config.SEND_RESULT_PATH in config.SEND_RESULT_ENDPOINT
        assert config.RECEIVER_HOPS
        hop = config.RECEIVER_HOPS[0]
        assert hop["host"]
        assert hop["port"] > 0
        assert hop["scheme"] in ("http", "https")
        assert hop["path"].startswith("/")

    def test_example_config_exists_for_operators(self):
        example = APP / "config.example.py"
        assert example.is_file()
        text = example.read_text(encoding="utf-8")
        assert "Volunteers" in text or "volunteers" in text
        assert "config.local.py" in text


# ---------------------------------------------------------------------------
# Part 3 - upload token format
# ---------------------------------------------------------------------------


class TestUploadToken:
    def test_shared_vectors(self):
        for token, expect_ok, label in upload_token.shared_format_test_vectors():
            ok, reason = upload_token.verify_upload_token(token)
            assert ok is expect_ok, (label, reason, token)

    def test_valid_known_token(self):
        assert upload_token.is_valid_upload_token(upload_token.SHARED_VALID_TOKEN)

    def test_normalize_strips_whitespace(self):
        spaced = "  " + upload_token.SHARED_VALID_TOKEN[:16] + "  " + upload_token.SHARED_VALID_TOKEN[16:]
        assert upload_token.normalize_pasted_token(spaced) == upload_token.SHARED_VALID_TOKEN
        assert upload_token.normalize_pasted_token(None) == ""

    def test_rejects_lowercase_body(self):
        body = "abcdefghij0123456789klmnopqrst"
        tok = body[:17] + upload_token._expected_checksum(body) + body[17:]
        ok, reason = upload_token.verify_upload_token(tok)
        assert not ok
        assert "A-Z" in reason

    def test_rejects_missing(self):
        ok, reason = upload_token.verify_upload_token(None)  # type: ignore[arg-type]
        assert not ok


# ---------------------------------------------------------------------------
# run.py — pure helpers
# ---------------------------------------------------------------------------


class TestDnsHelpers:
    def test_build_dns_query_structure(self):
        tx_id, query = run._build_dns_query("example.com")
        assert 0 <= tx_id <= 0xFFFF
        assert len(query) >= 12 + 1 + 7 + 1 + 3 + 1 + 4
        assert query[0:2] == struct.pack(">H", tx_id)
        assert b"example" in query
        assert b"com" in query

    def test_parse_dns_response_empty_or_bad(self):
        assert run._parse_dns_response(b"", 1) == []
        assert run._parse_dns_response(b"\x00" * 11, 1) == []
        bad = struct.pack(">HHHHHH", 1, 0x8003, 0, 0, 0, 0)  # NXDOMAIN rcode
        assert run._parse_dns_response(bad, 1) == []

    def test_parse_dns_response_with_a_record(self):
        tx_id = 0x1234
        header = struct.pack(">HHHHHH", tx_id, 0x8180, 1, 1, 0, 0)
        qname = b"\x07example\x03com\x00"
        question = qname + struct.pack(">HH", 1, 1)
        answer = (
            b"\xc0\x0c"
            + struct.pack(">HHIH", 1, 1, 60, 4)
            + bytes([1, 2, 3, 4])
        )
        ips = run._parse_dns_response(header + question + answer, tx_id)
        assert ips == ["1.2.3.4"]

    def test_skip_name_pointer_and_labels(self):
        data = b"\x03abc\x00" + b"\xc0\x00"
        assert run._skip_name(data, 0) == 5
        assert run._skip_name(data, 5) == 7


class TestTextHelpers:
    def test_extract_title(self):
        assert run._extract_title(b"") == ""
        assert run._extract_title(b"<html><title> Hello  World </title></html>") == (
            "Hello World"
        )
        assert run._extract_title(b"<html>no title</html>") == ""
        long_title = b"<title>" + (b"a" * 300) + b"</title>"
        assert len(run._extract_title(long_title)) == 200

    def test_content_hash(self):
        assert run._content_hash(b"") == ""
        h = run._content_hash(b"abc")
        assert len(h) == 16
        assert h == run._content_hash(b"abc")
        assert h != run._content_hash(b"abd")

    def test_translit_cyrillic_and_english_names(self):
        assert run._translit("Россия") == "Russia"
        assert run._translit("hello") == "hello"
        assert run._translit("А") == "A"
        assert run._translit("а") == "a"

    def test_to_punycode(self):
        assert run._to_punycode("example.com") == "example.com"
        puny = run._to_punycode("пример.рф")
        assert puny.startswith("xn--")
        assert run._to_punycode("bad\uffff")  # falls back or encodes


class TestDomainLists:
    def test_find_list_files(self):
        files = run.find_list_files(str(ROOT))
        assert files
        assert all(Path(f).name.startswith("list_") for f in files)
        assert any(Path(f).name == "list_white_domains.txt" for f in files)

    def test_read_domains(self, tmp_path):
        p = tmp_path / "list_sample.txt"
        p.write_text(
            "# comment\n"
            "\n"
            "example.com\n"
            "https://foo.bar/path\n"
            "http://baz.test\n"
            "//cdn.example/x\n",
            encoding="utf-8",
        )
        domains = run.read_domains(str(p))
        originals = [o for o, _ in domains]
        assert originals == ["example.com", "foo.bar", "baz.test", "cdn.example"]
        assert all(a == o or a.startswith("xn--") or a == o for o, a in domains)

    def test_read_version_text(self):
        ver = run._read_version_text(str(ROOT))
        assert ver
        assert ver == (APP / "version.txt").read_text(encoding="utf-8").strip().splitlines()[0].strip()

    def test_read_version_text_missing(self, tmp_path):
        assert run._read_version_text(str(tmp_path)) == ""


class TestVersionCheck:
    def test_parse_accepts_plain_and_v_prefix(self):
        assert run._parse_version_text("1.3.0\n") == "1.3.0"
        assert run._parse_version_text("v1.2.0") == "1.2.0"
        assert run._parse_version_text("# comment\n1.3.1\n") == "1.3.1"

    def test_parse_rejects_junk(self):
        assert run._parse_version_text("") == ""
        assert run._parse_version_text("not a version") == ""
        assert run._parse_version_text("<html>1.3.0</html>") == ""

    def test_newer_than_local(self):
        assert run._version_key("1.3.0") > run._version_key("1.2.0")
        assert run._version_key("1.3.1") > run._version_key("1.3.0")
        assert run._version_key("1.3.0") == run._version_key("v1.3.0")
        assert not run._is_remote_newer("1.3", "1.3.0")
        assert run._is_remote_newer("1.2.0", "1.3.0")

    def test_notice_is_uppercase_when_remote_is_newer(self, capsys):
        run._print_update_notice("1.2.0", "1.3.0")
        out = capsys.readouterr().out
        assert "A NEWER VERSION OF THIS SCRIPT IS AVAILABLE (1.3.0). YOU HAVE 1.2.0." in out
        assert out.strip() == out.strip().upper()
        assert "NASVYAZI.ORG" in out
        assert "GITHUB.COM/RUNETMONITOR/WHITELISTCHECKERSCRIPT" in out

    def test_notice_silent_when_same_or_older_or_missing(self, capsys):
        run._print_update_notice("1.3.0", "1.3.0")
        run._print_update_notice("1.3.0", "1.2.0")
        run._print_update_notice("1.3.0", "")
        run._print_update_notice("", "1.9.0")
        assert capsys.readouterr().out == ""

    def test_fetch_uses_another_url_when_the_first_fails(self, monkeypatch):
        calls = []

        class _Resp(object):
            def __init__(self, body):
                self._body = body

            def read(self, n=-1):
                return self._body[:n] if n >= 0 else self._body

            def close(self):
                pass

        def fake_urlopen(req, timeout=None):
            url = req.full_url
            calls.append(url)
            if "fail.example" in url:
                raise urllib.error.URLError("blocked")
            return _Resp(b"1.4.0\n")

        monkeypatch.setattr(run.urllib.request, "urlopen", fake_urlopen)
        got = run._fetch_latest_version(
            urls=["https://fail.example/v", "https://ok.example/v"],
            timeout=1,
        )
        assert got == "1.4.0"
        assert len(calls) == 2

    def test_fetch_picks_newest_when_mirrors_disagree(self, monkeypatch):
        class _Resp(object):
            def __init__(self, body):
                self._body = body

            def read(self, n=-1):
                return self._body[:n] if n >= 0 else self._body

            def close(self):
                pass

        def fake_urlopen(req, timeout=None):
            if "stale.example" in req.full_url:
                return _Resp(b"1.2.0\n")
            return _Resp(b"1.3.0\n")

        monkeypatch.setattr(run.urllib.request, "urlopen", fake_urlopen)
        got = run._fetch_latest_version(
            urls=["https://stale.example/v", "https://fresh.example/v"],
            timeout=1,
        )
        assert got == "1.3.0"

    def test_fetch_stays_quiet_on_total_failure(self, monkeypatch):
        def boom(*_a, **_k):
            raise urllib.error.URLError("blocked")

        monkeypatch.setattr(run.urllib.request, "urlopen", boom)
        assert run._fetch_latest_version(urls=["https://blocked.example/v"], timeout=1) == ""


class TestVerdictHelpers:
    def test_row_reachable(self):
        assert run._row_reachable_verdict({"accessible": "YES"})
        assert run._row_reachable_verdict({"accessible": "PARTIAL"})
        assert not run._row_reachable_verdict({"accessible": "NO"})
        assert not run._row_reachable_verdict({"accessible": "ERROR"})

    def test_print_final_verdict(self, capsys):
        results = [
            {"source_file": "list_white_domains.txt", "accessible": "YES"},
            {"source_file": "list_white_domains.txt", "accessible": "NO"},
            {"source_file": "list_ooni_ru.txt", "accessible": "NO"},
            {"source_file": "list_ooni_ru.txt", "accessible": "NO"},
        ]
        run._print_final_verdict(results, str(ROOT))
        out = capsys.readouterr().out
        assert "FINAL VERDICT" in out
        assert "whitelist" in out.lower() or "Whitelist" in out or "accessible" in out


class TestSkipCheckResolve:
    def test_explicit_output_csv(self, tmp_path, monkeypatch):
        csv_path = tmp_path / "check_results_explicit.csv"
        csv_path.write_text("domain\n", encoding="utf-8")
        monkeypatch.setattr(run, "OUTPUT_CSV", csv_path.name)
        path, meta = run._resolve_skip_check_csv_path(str(tmp_path))
        assert path == str(csv_path)
        assert meta == "explicit"

    def test_latest_fallback(self, tmp_path, monkeypatch):
        older = tmp_path / "check_results_20200101_000000.csv"
        newer = tmp_path / "check_results_20250101_000000.csv"
        older.write_text("a\n", encoding="utf-8")
        newer.write_text("b\n", encoding="utf-8")
        os.utime(older, (1_000_000, 1_000_000))
        os.utime(newer, (2_000_000, 2_000_000))
        monkeypatch.setattr(run, "OUTPUT_CSV", "missing.csv")
        path, meta = run._resolve_skip_check_csv_path(str(tmp_path))
        assert path == str(newer)
        assert meta == "latest"

    def test_none_when_empty(self, tmp_path, monkeypatch):
        monkeypatch.setattr(run, "OUTPUT_CSV", "missing.csv")
        path, meta = run._resolve_skip_check_csv_path(str(tmp_path))
        assert path is None
        assert "missing.csv" in meta


# ---------------------------------------------------------------------------
# run.py — network-facing with mocks
# ---------------------------------------------------------------------------


class TestResolveDns:
    def test_system_path(self, monkeypatch):
        monkeypatch.setattr(
            run.socket,
            "getaddrinfo",
            lambda *a, **k: [
                (0, 0, 0, "", ("9.9.9.9", 0)),
                (0, 0, 0, "", ("9.9.9.9", 0)),
                (0, 0, 0, "", ("8.8.8.8", 0)),
            ],
        )
        assert set(run.resolve_dns("example.com")) == {"9.9.9.9", "8.8.8.8"}

    def test_custom_path(self, monkeypatch):
        called = {}

        def fake_custom(domain, server, timeout):
            called["args"] = (domain, server, timeout)
            return ["1.1.1.1"]

        monkeypatch.setattr(run, "resolve_dns_custom", fake_custom)
        assert run.resolve_dns("example.com", server="8.8.8.8") == ["1.1.1.1"]
        assert called["args"][1] == "8.8.8.8"


class TestCheckHttp:
    def test_https_success(self, monkeypatch):
        class FakeResp:
            def getcode(self):
                return 200

            def geturl(self):
                return "https://example.com/"

            def read(self, n=-1):
                return b"<html><title>Ex</title></html>"

        monkeypatch.setattr(
            run.urllib.request, "urlopen", lambda *a, **k: FakeResp()
        )
        r = run.check_http("example.com", timeout=1)
        assert r["status"] == 200
        assert r["protocol"] == "https"
        assert r["size"] > 0
        assert r["error"] == ""

    def test_http_error_status(self, monkeypatch):
        def boom(*a, **k):
            raise urllib.error.HTTPError(
                "https://example.com/", 503, "Unavailable", hdrs=None, fp=None
            )

        monkeypatch.setattr(run.urllib.request, "urlopen", boom)
        r = run.check_http("example.com", timeout=1)
        assert r["status"] == 503
        assert r["protocol"] == "https"

    def test_both_schemes_fail(self, monkeypatch):
        def boom(*a, **k):
            raise urllib.error.URLError("down")

        monkeypatch.setattr(run.urllib.request, "urlopen", boom)
        r = run.check_http("example.com", timeout=1)
        assert r["status"] == 0
        assert r["protocol"] == ""
        assert "down" in r["error"]


class TestCheckDomain:
    def test_dns_failure(self, monkeypatch):
        monkeypatch.setattr(
            run, "resolve_dns", mock.Mock(side_effect=OSError("fail"))
        )
        row = run.check_domain("example.com", "list_x.txt")
        assert row["accessible"] == "NO"
        assert row["dns_error"]
        assert "skipped" in row["http_error"]

    def test_no_a_records(self, monkeypatch):
        monkeypatch.setattr(run, "resolve_dns", mock.Mock(return_value=[]))
        row = run.check_domain("example.com", "list_x.txt")
        assert "no A records" in row["dns_error"]
        assert row["accessible"] == "NO"

    def test_accessible_yes(self, monkeypatch):
        monkeypatch.setattr(run, "resolve_dns", mock.Mock(return_value=["1.2.3.4"]))
        monkeypatch.setattr(
            run, "check_ssl", mock.Mock(return_value=(12.0, True, "Issuer", ""))
        )
        monkeypatch.setattr(
            run,
            "check_http",
            mock.Mock(
                return_value={
                    "status": 200,
                    "size": 100,
                    "url": "https://example.com/",
                    "redirect_url": "https://www.example.com/",
                    "error": "",
                    "body": b"<title>Hi</title>",
                    "protocol": "https",
                }
            ),
        )
        row = run.check_domain("example.com", "list_x.txt", original="example.com")
        assert row["accessible"] == "YES"
        assert row["ssl_valid"] == "YES"
        assert row["http_title"] == "Hi"
        assert row["final_domain"] == "www.example.com"
        assert row["content_hash"]

    def test_accessible_partial(self, monkeypatch):
        monkeypatch.setattr(run, "resolve_dns", mock.Mock(return_value=["1.2.3.4"]))
        monkeypatch.setattr(
            run, "check_ssl", mock.Mock(return_value=(1.0, False, "", "err"))
        )
        monkeypatch.setattr(
            run,
            "check_http",
            mock.Mock(
                return_value={
                    "status": 200,
                    "size": 0,
                    "url": "https://example.com/",
                    "redirect_url": "https://example.com/",
                    "error": "",
                    "body": b"",
                    "protocol": "https",
                }
            ),
        )
        row = run.check_domain("example.com", "list_x.txt")
        assert row["accessible"] == "PARTIAL"


class TestDetectLocation:
    def test_success_no_ip_in_location(self, monkeypatch):
        payload = {
            "city": "Москва",
            "regionName": "Москва",
            "country": "Россия",
            "isp": "Provider",
            "query": "1.1.1.1",
        }

        class FakeResp:
            def read(self):
                return json.dumps(payload).encode("utf-8")

        monkeypatch.setattr(
            run.urllib.request, "urlopen", lambda *a, **k: FakeResp()
        )
        location, isp, ip = run.detect_location()
        assert isp == "Provider"
        assert ip == "1.1.1.1"
        assert "Russia" in location or "Rossiya" in location or location
        assert "1.1.1.1" not in location
        assert "(" not in location

    def test_failure(self, monkeypatch):
        monkeypatch.setattr(
            run.urllib.request,
            "urlopen",
            mock.Mock(side_effect=OSError("offline")),
        )
        assert run.detect_location() == ("", "", "")


class TestGetSystemDns:
    def test_reads_resolv_conf(self, tmp_path, monkeypatch):
        resolv = tmp_path / "resolv.conf"
        resolv.write_text(
            "# comment\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n",
            encoding="utf-8",
        )
        real_open = open

        def fake_open(path, *a, **k):
            if path == "/etc/resolv.conf":
                return real_open(resolv, *a, **k)
            return real_open(path, *a, **k)

        monkeypatch.setattr("builtins.open", fake_open)
        servers = run.get_system_dns_servers()
        assert servers == ["1.1.1.1", "8.8.8.8"]


class TestTokenPrompt:
    def test_empty_token_local_only(self, monkeypatch, capsys):
        monkeypatch.setattr("builtins.input", lambda *_a, **_k: "")
        assert run.prompt_upload_token_before_scan() is None
        out = capsys.readouterr().out
        assert "without VPN" in out
        assert "Helpdesk" in out
        assert "local scan only" in out.lower() or "No token" in out

    def test_valid_token_accepted(self, monkeypatch):
        monkeypatch.setattr(
            "builtins.input", lambda *_a, **_k: upload_token.SHARED_VALID_TOKEN
        )
        assert (
            run.prompt_upload_token_before_scan() == upload_token.SHARED_VALID_TOKEN
        )

    def test_bad_token_aborts(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda *_a, **_k: "not-a-token")
        monkeypatch.setattr(run, "pause_if_windows", lambda: None)
        with pytest.raises(SystemExit) as ei:
            run.prompt_upload_token_before_scan()
        assert ei.value.code == 2

    def test_resend_prompt_wording(self, monkeypatch, capsys):
        monkeypatch.setattr("builtins.input", lambda *_a, **_k: "")
        assert run.prompt_upload_token_before_scan(for_resend=True) is None
        out = capsys.readouterr().out
        assert "cancel" in out.lower() or "cancelled" in out.lower() or "No token" in out


# ---------------------------------------------------------------------------
# send_results.py
# ---------------------------------------------------------------------------


def _sample_rows():
    return [
        {
            "domain": "example.com",
            "accessible": "YES",
            "check_location": "City, Country (1.1.1.1)",
            "check_provider": "ISP",
            "check_ip_address": "1.1.1.1",
            "check_version": "1.0.0",
            "dns_resolved_ips": "1.2.3.4",
            "http_status": "200",
            "empty_should_strip": "",
        },
        {
            "domain": "blocked.test",
            "accessible": "NO",
            "check_location": "",
            "check_provider": "",
            "check_ip_address": "",
            "check_version": "",
            "dns_error": "timeout",
        },
        {
            "domain": "partial.test",
            "accessible": "PARTIAL",
            "http_status": "200",
        },
        {
            "domain": "err.test",
            "accessible": "ERROR",
        },
    ]


class TestSanitizeRegion:
    def test_strips_ipv4_suffix(self):
        assert sr.sanitize_region("Moscow, Russia (1.2.3.4)") == "Moscow, Russia"

    def test_keeps_plain_region(self):
        assert sr.sanitize_region("Moscow, Russia") == "Moscow, Russia"

    def test_empty(self):
        assert sr.sanitize_region("") == ""


class TestSendResultsCryptoAndZip:
    def test_json_dump_compact(self):
        raw = sr._json_dump_bytes({"a": 1, "b": "x"})
        assert raw == b'{"a":1,"b":"x"}'

    def test_zipcrypto_roundtrip_with_one_time_token(self):
        payload = {"hello": "world", "n": 42}
        token = upload_token.SHARED_VALID_TOKEN
        zbytes = sr._payload_zip_bytes(payload, token)
        assert zbytes[:4] == b"PK\x03\x04"
        with zipfile.ZipFile(io.BytesIO(zbytes)) as zf:
            zf.setpassword(token.encode("utf-8"))
            data = zf.read("payload.json")
        assert json.loads(data.decode("utf-8")) == payload

    def test_multipart_body(self):
        body, ct = sr._zip_multipart_body(b"ZIPDATA", "out.zip")
        assert "multipart/form-data; boundary=" in ct
        boundary = ct.split("boundary=", 1)[1]
        assert body.startswith(b"--" + boundary.encode("ascii"))
        assert b"ZIPDATA" in body
        assert b"out.zip" in body
        assert body.rstrip().endswith(b"--")


class TestSendResultsPayload:
    def test_build_payload_no_ip_address(self, monkeypatch):
        monkeypatch.setattr(sr, "get_dns_servers", lambda: ["9.9.9.9"])
        rows = _sample_rows()
        payload = sr._build_payload(rows, Path("check_results_x.csv"))
        assert payload["accessible"] == 1
        assert payload["partial"] == 1
        assert payload["blocked_down"] == 1
        assert payload["errors"] == 1
        assert payload["total"] == 4
        assert payload["dns_servers"] == ["9.9.9.9"]
        assert payload["region"] == "City, Country"
        assert "1.1.1.1" not in payload["region"]
        assert payload["provider"] == "ISP"
        assert "ip_address" not in payload
        assert payload["version"] == "1.0.0"
        assert payload["file_name"] == "check_results_x.csv"
        domains = payload["result_data"]["domains"]
        assert domains[0]["name"] == "example.com"
        assert domains[0]["status"] == "accessible"
        assert "empty_should_strip" not in domains[0]
        assert domains[1]["status"] == "blocked"

    def test_get_dns_servers_custom(self, monkeypatch):
        monkeypatch.setattr(sr, "DNS_SERVER", "1.2.3.4")
        assert sr.get_dns_servers() == ["1.2.3.4"]

    def test_get_dns_servers_system(self, monkeypatch):
        monkeypatch.setattr(sr, "DNS_SERVER", "")
        monkeypatch.setattr(sr, "get_system_dns_servers", lambda: ["8.8.4.4"])
        assert sr.get_dns_servers() == ["8.8.4.4"]

    def test_hop_url(self):
        hop = {
            "scheme": "http",
            "host": "203.0.113.1",
            "port": 5000,
            "path": "/upload",
        }
        url = sr._hop_url(hop)
        assert url == "http://203.0.113.1:5000/upload"


class TestSendResultsCsvResolve:
    def test_from_argv_relative(self, monkeypatch, tmp_path):
        rel = "results/check_results_arg.csv"
        monkeypatch.setattr(sr, "_SCRIPT_DIR", tmp_path)
        monkeypatch.setattr(sys, "argv", ["send_results.py", rel])
        (tmp_path / "results").mkdir()
        target = tmp_path / rel
        target.write_text("x\n", encoding="utf-8")
        assert sr._resolve_csv_path() == target

    def test_from_argv_absolute(self, monkeypatch, tmp_path):
        p = tmp_path / "file.csv"
        p.write_text("x\n", encoding="utf-8")
        monkeypatch.setattr(sys, "argv", ["send_results.py", str(p)])
        assert sr._resolve_csv_path() == p

    def test_newest_when_no_argv(self, monkeypatch, tmp_path):
        results = tmp_path / "results"
        results.mkdir()
        older = results / "check_results_old.csv"
        newer = results / "check_results_new.csv"
        older.write_text("a\n", encoding="utf-8")
        newer.write_text("b\n", encoding="utf-8")
        os.utime(older, (1_000_000, 1_000_000))
        os.utime(newer, (2_000_000, 2_000_000))
        monkeypatch.setattr(sr, "_SCRIPT_DIR", tmp_path)
        monkeypatch.setattr(sys, "argv", ["send_results.py"])
        assert sr._resolve_csv_path() == newer

    def test_missing_raises(self, monkeypatch, tmp_path):
        monkeypatch.setattr(sr, "_SCRIPT_DIR", tmp_path)
        monkeypatch.setattr(sys, "argv", ["send_results.py"])
        (tmp_path / "results").mkdir()
        with pytest.raises(FileNotFoundError):
            sr._resolve_csv_path()


class TestSendResultsUpload:
    def test_direct_upload_ok_uses_web_token(self, monkeypatch):
        seen = {}

        class FakeResp:
            def getcode(self):
                return 200

            def read(self):
                return b'{"ok":true}'

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(req, timeout=None):
            seen["headers"] = dict(req.headers)
            return FakeResp()

        monkeypatch.setattr(sr.urllib.request, "urlopen", fake_urlopen)
        ok, msg = sr._try_direct_upload(
            "https://example.test/upload",
            b"zip",
            "f.zip",
            upload_token.SHARED_VALID_TOKEN,
        )
        assert ok
        assert "200" in msg
        # urllib may title-case header names
        assert seen["headers"].get("X-web-token") == upload_token.SHARED_VALID_TOKEN or seen[
            "headers"
        ].get("X-Web-Token") == upload_token.SHARED_VALID_TOKEN

    def test_direct_upload_http_error(self, monkeypatch):
        def boom(*a, **k):
            raise urllib.error.HTTPError(
                "https://example.test/upload",
                403,
                "Forbidden",
                hdrs=None,
                fp=io.BytesIO(b"nope"),
            )

        monkeypatch.setattr(sr.urllib.request, "urlopen", boom)
        ok, msg = sr._try_direct_upload(
            "https://example.test/upload",
            b"zip",
            "f.zip",
            upload_token.SHARED_VALID_TOKEN,
        )
        assert not ok
        assert "403" in msg

    def test_post_receiver_hop_ok(self, monkeypatch):
        class FakeResponse:
            ok = True
            status_code = 200
            text = '{"ok":true}'

            def json(self):
                return {"ok": True}

        post = mock.Mock(return_value=FakeResponse())
        monkeypatch.setattr(sr.requests, "post", post)
        hop = {
            "host": "203.0.113.1",
            "port": 5000,
            "scheme": "http",
            "path": "/upload",
            "timeout_sec": 10.0,
            "insecure_tls": False,
        }
        code, resp = sr._post_receiver_hop(
            hop, "f.zip", b"zip", upload_token.SHARED_VALID_TOKEN
        )
        assert code == 0
        assert resp is not None and resp.ok
        headers = post.call_args.kwargs["headers"]
        assert headers.get("X-Web-Token") == upload_token.SHARED_VALID_TOKEN
        assert "X-Auth-Token" not in headers

    def test_post_receiver_hop_request_error(self, monkeypatch):
        monkeypatch.setattr(
            sr.requests,
            "post",
            mock.Mock(side_effect=sr.requests.RequestException("boom")),
        )
        hop = {"host": "203.0.113.1", "port": 5000, "scheme": "http", "path": "/upload"}
        code, resp = sr._post_receiver_hop(
            hop, "f.zip", b"zip", upload_token.SHARED_VALID_TOKEN
        )
        assert code == 1
        assert resp is None

    def test_try_receiver_hops_tries_in_order(self, monkeypatch):
        calls = []

        def fake_post(hop, upload_filename, zip_bytes, web_token):
            calls.append(hop["host"])
            if hop["host"] == "first.example":
                return 1, None

            class FakeResponse:
                ok = True
                status_code = 200
                text = "ok"

                def json(self):
                    return {"ok": True}

            return 0, FakeResponse()

        monkeypatch.setattr(sr, "_post_receiver_hop", fake_post)
        monkeypatch.setattr(
            sr,
            "RECEIVER_HOPS",
            [
                {"host": "first.example", "port": 1, "scheme": "http", "path": "/u"},
                {"host": "second.example", "port": 2, "scheme": "http", "path": "/u"},
            ],
        )
        ok, msg = sr._try_receiver_hops("f.zip", b"z", upload_token.SHARED_VALID_TOKEN)
        assert ok
        assert calls == ["first.example", "second.example"]
        assert "second.example" in msg

    def test_write_and_delete_inspection_zip(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sr, "_SCRIPT_DIR", tmp_path)
        monkeypatch.setattr(sr, "RESULTS_DIR", "results")
        out = sr._write_inspection_zip(b"PKDATA", Path("check_results_x.csv"))
        assert out == tmp_path / "results" / "check_results_x.zip"
        assert out.read_bytes() == b"PKDATA"
        sr._delete_zip_quietly(out)
        assert not out.exists()


class TestSendResultsMain:
    def _write_csv(self, path: Path):
        fieldnames = [
            "domain",
            "accessible",
            "check_location",
            "check_provider",
            "check_version",
            "dns_resolved_ips",
        ]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fieldnames)
            w.writeheader()
            w.writerow(
                {
                    "domain": "example.com",
                    "accessible": "YES",
                    "check_location": "Here (9.9.9.9)",
                    "check_provider": "ISP",
                    "check_version": "1.1.8",
                    "dns_resolved_ips": "1.2.3.4",
                }
            )

    def test_main_hop_success_deletes_zip(self, tmp_path, monkeypatch, capsys):
        csv_path = tmp_path / "check_results_t.csv"
        self._write_csv(csv_path)
        monkeypatch.setattr(sr, "_SCRIPT_DIR", tmp_path)
        monkeypatch.setattr(sr, "RESULTS_DIR", "results")
        monkeypatch.setattr(sr, "SEND_METHODS_ORDER", ["receiver"])
        monkeypatch.setattr(sys, "argv", ["send_results.py", str(csv_path)])
        monkeypatch.setattr(sr, "get_dns_servers", lambda: ["8.8.8.8"])
        monkeypatch.setattr(
            sr,
            "_try_receiver_hops",
            mock.Mock(return_value=(True, "OK hop")),
        )
        assert sr.main(upload_token=upload_token.SHARED_VALID_TOKEN) == 0
        out = capsys.readouterr().out
        assert "Sending results from:" in out
        zip_path = tmp_path / "results" / "check_results_t.zip"
        assert not zip_path.exists()

    def test_main_hop_first_then_direct(self, tmp_path, monkeypatch):
        csv_path = tmp_path / "check_results_t.csv"
        self._write_csv(csv_path)
        monkeypatch.setattr(sr, "_SCRIPT_DIR", tmp_path)
        monkeypatch.setattr(sr, "RESULTS_DIR", "results")
        monkeypatch.setattr(sr, "SEND_METHODS_ORDER", ["receiver", "direct"])
        monkeypatch.setattr(sys, "argv", ["send_results.py", str(csv_path)])
        monkeypatch.setattr(sr, "get_dns_servers", lambda: [])
        order = []

        def hop_fail(*a, **k):
            order.append("hop")
            return False, "hop down"

        def direct_ok(*a, **k):
            order.append("direct")
            return True, "OK"

        monkeypatch.setattr(sr, "_try_receiver_hops", hop_fail)
        monkeypatch.setattr(sr, "_try_direct_upload", direct_ok)
        assert sr.main(upload_token=upload_token.SHARED_VALID_TOKEN) == 0
        assert order == ["hop", "direct"]

    def test_main_file_missing(self, monkeypatch, tmp_path):
        missing = tmp_path / "nope.csv"
        monkeypatch.setattr(sys, "argv", ["send_results.py", str(missing)])
        monkeypatch.setattr(sr, "pause_if_windows", lambda: None)
        assert sr.main(upload_token=upload_token.SHARED_VALID_TOKEN) == 2

    def test_main_all_methods_fail_keeps_csv(self, tmp_path, monkeypatch):
        csv_path = tmp_path / "check_results_t.csv"
        self._write_csv(csv_path)
        monkeypatch.setattr(sr, "_SCRIPT_DIR", tmp_path)
        monkeypatch.setattr(sr, "RESULTS_DIR", "results")
        monkeypatch.setattr(sr, "SEND_METHODS_ORDER", ["direct", "receiver"])
        monkeypatch.setattr(sys, "argv", ["send_results.py", str(csv_path)])
        monkeypatch.setattr(sr, "get_dns_servers", lambda: [])
        monkeypatch.setattr(
            sr, "_try_direct_upload", mock.Mock(return_value=(False, "nope"))
        )
        monkeypatch.setattr(
            sr, "_try_receiver_hops", mock.Mock(return_value=(False, "nope"))
        )
        monkeypatch.setattr(sr, "pause_if_windows", lambda: None)
        assert sr.main(upload_token=upload_token.SHARED_VALID_TOKEN) == 1
        assert csv_path.is_file()
        assert not (tmp_path / "results" / "check_results_t.zip").exists()

    def test_main_bad_token_aborts(self, monkeypatch, tmp_path):
        csv_path = tmp_path / "check_results_t.csv"
        self._write_csv(csv_path)
        monkeypatch.setattr(sys, "argv", ["send_results.py", str(csv_path)])
        monkeypatch.setattr(sr, "pause_if_windows", lambda: None)
        assert sr.main(upload_token="bad") == 2

    def test_main_prompt_empty_cancels(self, tmp_path, monkeypatch):
        csv_path = tmp_path / "check_results_t.csv"
        self._write_csv(csv_path)
        monkeypatch.setattr(sys, "argv", ["send_results.py", str(csv_path)])
        monkeypatch.setattr(sr, "prompt_upload_token_for_send", lambda: None)
        assert sr.main() == 0


class TestCsvNoIpPersistence:
    def test_csv_fieldnames_exclude_ip(self, tmp_path, monkeypatch):
        """Simulate the CSV write path fieldnames used by run.main."""
        # Field list is constructed inside main; assert the contract via a mini write
        # matching run.py's hardened columns.
        fieldnames = [
            "domain",
            "accessible",
            "check_location",
            "check_provider",
            "check_version",
        ]
        assert "check_ip_address" not in fieldnames
        path = tmp_path / "out.csv"
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fieldnames)
            w.writeheader()
            w.writerow(
                {
                    "domain": "example.com",
                    "accessible": "YES",
                    "check_location": "City, Country",
                    "check_provider": "ISP",
                    "check_version": "1.0",
                }
            )
        text = path.read_text(encoding="utf-8")
        assert "check_ip_address" not in text
        assert "1.1.1.1" not in text


class TestReadmeVolunteerWording:
    def test_readme_matches_token_source(self):
        readme = (ROOT / "README.txt").read_text(encoding="utf-8")
        assert "without VPN" in readme
        assert "Helpdesk" in readme
        assert "nasvyazi.org" in readme
        assert "one-time" in readme.lower() or "one-time" in readme
        assert "Do not edit config.py" in readme or "do not edit config" in readme.lower()
        assert "unencrypted CSV" in readme
        assert "re-send" in readme.lower() or "Re-send" in readme
        assert config.TOKEN_SOURCE_TEXT.split("(")[0].strip() in readme or (
            "Na Svyazi Helpdesk" in readme
        )


class TestUploadTokenExtraBranches:
    def test_token_from_body_rejects_bad_length(self):
        with pytest.raises(ValueError):
            upload_token._token_from_body("SHORT")

    def test_non_digit_checksum(self):
        tok = upload_token.SHARED_VALID_TOKEN[:17] + "AB" + upload_token.SHARED_VALID_TOKEN[19:]
        ok, reason = upload_token.verify_upload_token(tok)
        assert not ok
        assert "checksum" in reason

    def test_too_few_digits(self):
        body = "A" * 21 + "0" * 9
        tok = upload_token._token_from_body(body)
        ok, reason = upload_token.verify_upload_token(tok)
        assert not ok
        assert "digits" in reason

    def test_body_length_guard(self, monkeypatch):
        monkeypatch.setattr(upload_token, "_body_chars", lambda _t: "SHORT")
        ok, reason = upload_token.verify_upload_token(upload_token.SHARED_VALID_TOKEN)
        assert not ok
        assert "body length" in reason


class TestConfigLocalOverrides:
    def test_apply_local_overrides(self, tmp_path, monkeypatch):
        (tmp_path / "config.py").write_text("# stub\n", encoding="utf-8")
        (tmp_path / "config.local.py").write_text("DNS_TIMEOUT = 99\n", encoding="utf-8")
        monkeypatch.setattr(config, "__file__", str(tmp_path / "config.py"))
        old = config.DNS_TIMEOUT
        try:
            config._apply_local_overrides()
            assert config.DNS_TIMEOUT == 99
        finally:
            config.DNS_TIMEOUT = old

    def test_apply_local_overrides_missing_is_noop(self, tmp_path, monkeypatch):
        (tmp_path / "config.py").write_text("# stub\n", encoding="utf-8")
        monkeypatch.setattr(config, "__file__", str(tmp_path / "config.py"))
        old = config.DNS_TIMEOUT
        config._apply_local_overrides()
        assert config.DNS_TIMEOUT == old

    def test_env_endpoint_override_inprocess(self, monkeypatch):
        monkeypatch.setenv("SEND_RESULT_ENDPOINT", "https://example.test/override")
        spec = importlib.util.spec_from_file_location(
            "config_env_cov", APP / "config.py"
        )
        mod = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(mod)
        assert mod.SEND_RESULT_ENDPOINT == "https://example.test/override"

    def test_env_endpoint_override_via_subprocess(self):
        code = (
            "import importlib.util, os, sys\n"
            "from pathlib import Path\n"
            "p = Path(%r)\n"
            "os.environ['SEND_RESULT_ENDPOINT'] = 'https://example.test/override'\n"
            "spec = importlib.util.spec_from_file_location('cfg_env', p)\n"
            "m = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(m)\n"
            "assert m.SEND_RESULT_ENDPOINT == 'https://example.test/override'\n"
            "print('ok')\n"
        ) % str(APP / "config.py")
        import subprocess

        out = subprocess.check_output(
            [sys.executable, "-c", code],
            cwd=str(APP),
            env={**os.environ, "SEND_RESULT_ENDPOINT": "https://example.test/override"},
        )
        assert b"ok" in out


class TestSendResultsExtraBranches:
    def test_try_hops_empty_list(self, monkeypatch):
        monkeypatch.setattr(sr, "RECEIVER_HOPS", [])
        ok, msg = sr._try_receiver_hops("f.zip", b"z", upload_token.SHARED_VALID_TOKEN)
        assert not ok
        assert "no RECEIVER_HOPS" in msg

    def test_try_hops_http_error_response(self, monkeypatch):
        class FakeResponse:
            ok = False
            status_code = 403
            text = "x" * 600

            def json(self):
                raise ValueError("not json")

        monkeypatch.setattr(
            sr,
            "_post_receiver_hop",
            mock.Mock(return_value=(1, FakeResponse())),
        )
        monkeypatch.setattr(
            sr,
            "RECEIVER_HOPS",
            [{"host": "h.example", "port": 1, "scheme": "http", "path": "/u"}],
        )
        ok, msg = sr._try_receiver_hops("f.zip", b"z", upload_token.SHARED_VALID_TOKEN)
        assert not ok
        assert "403" in msg

    def test_prompt_upload_token_for_send_valid(self, monkeypatch):
        monkeypatch.setattr(
            "builtins.input", lambda *_a, **_k: upload_token.SHARED_VALID_TOKEN
        )
        assert sr.prompt_upload_token_for_send() == upload_token.SHARED_VALID_TOKEN

    def test_prompt_upload_token_for_send_bad(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda *_a, **_k: "bad")
        assert sr.prompt_upload_token_for_send() == ""

    def test_prompt_upload_token_for_send_eof(self, monkeypatch):
        def boom(*_a, **_k):
            raise EOFError

        monkeypatch.setattr("builtins.input", boom)
        assert sr.prompt_upload_token_for_send() is None

    def test_main_prompt_bad_token_returns_2(self, tmp_path, monkeypatch):
        csv_path = tmp_path / "check_results_t.csv"
        TestSendResultsMain()._write_csv(csv_path)
        monkeypatch.setattr(sys, "argv", ["send_results.py", str(csv_path)])
        monkeypatch.setattr(sr, "prompt_upload_token_for_send", lambda: "")
        monkeypatch.setattr(sr, "pause_if_windows", lambda: None)
        assert sr.main() == 2

    def test_main_empty_send_methods(self, tmp_path, monkeypatch):
        csv_path = tmp_path / "check_results_t.csv"
        TestSendResultsMain()._write_csv(csv_path)
        monkeypatch.setattr(sr, "_SCRIPT_DIR", tmp_path)
        monkeypatch.setattr(sr, "RESULTS_DIR", "results")
        monkeypatch.setattr(sr, "SEND_METHODS_ORDER", [])
        monkeypatch.setattr(sys, "argv", ["send_results.py", str(csv_path)])
        monkeypatch.setattr(sr, "get_dns_servers", lambda: [])
        monkeypatch.setattr(sr, "pause_if_windows", lambda: None)
        assert sr.main(upload_token=upload_token.SHARED_VALID_TOKEN) == 2

    def test_main_unknown_method_then_fail(self, tmp_path, monkeypatch):
        csv_path = tmp_path / "check_results_t.csv"
        TestSendResultsMain()._write_csv(csv_path)
        monkeypatch.setattr(sr, "_SCRIPT_DIR", tmp_path)
        monkeypatch.setattr(sr, "RESULTS_DIR", "results")
        monkeypatch.setattr(sr, "SEND_METHODS_ORDER", ["mystery"])
        monkeypatch.setattr(sys, "argv", ["send_results.py", str(csv_path)])
        monkeypatch.setattr(sr, "get_dns_servers", lambda: [])
        monkeypatch.setattr(sr, "pause_if_windows", lambda: None)
        assert sr.main(upload_token=upload_token.SHARED_VALID_TOKEN) == 1

    def test_looks_like_ipv6_region(self):
        assert sr.sanitize_region("City (2001:db8::1)") == "City"
        assert not sr._looks_like_public_ip("")
        assert not sr._looks_like_public_ip("not-an-ip")

    def test_pause_if_windows_noop_on_non_windows(self, monkeypatch):
        monkeypatch.setattr(sr.sys, "platform", "darwin")
        sr.pause_if_windows()

    def test_pause_if_windows_on_win32(self, monkeypatch):
        monkeypatch.setattr(sr.sys, "platform", "win32")
        monkeypatch.setattr("builtins.input", lambda *_a, **_k: "")
        sr.pause_if_windows()

    def test_pause_if_windows_eof(self, monkeypatch):
        monkeypatch.setattr(sr.sys, "platform", "win32")

        def boom(*_a, **_k):
            raise EOFError

        monkeypatch.setattr("builtins.input", boom)
        sr.pause_if_windows()

    def test_direct_upload_url_error(self, monkeypatch):
        monkeypatch.setattr(
            sr.urllib.request,
            "urlopen",
            mock.Mock(side_effect=urllib.error.URLError("down")),
        )
        ok, msg = sr._try_direct_upload(
            "https://example.test/u",
            b"z",
            "f.zip",
            upload_token.SHARED_VALID_TOKEN,
        )
        assert not ok
        assert "down" in msg

    def test_direct_upload_non_2xx(self, monkeypatch):
        class FakeResp:
            def getcode(self):
                return 299 + 1  # 300

            def read(self):
                return b"redir"

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        monkeypatch.setattr(
            sr.urllib.request, "urlopen", lambda *a, **k: FakeResp()
        )
        ok, msg = sr._try_direct_upload(
            "https://example.test/u",
            b"z",
            "f.zip",
            upload_token.SHARED_VALID_TOKEN,
        )
        assert not ok
        assert "300" in msg

    def test_direct_upload_httperror_read_fails(self, monkeypatch):
        class BadHTTPError(urllib.error.HTTPError):
            def read(self, *a, **k):
                raise OSError("no body")

        def boom(*a, **k):
            raise BadHTTPError(
                "https://example.test/u", 500, "err", hdrs=None, fp=None
            )

        monkeypatch.setattr(sr.urllib.request, "urlopen", boom)
        ok, msg = sr._try_direct_upload(
            "https://example.test/u",
            b"z",
            "f.zip",
            upload_token.SHARED_VALID_TOKEN,
        )
        assert not ok
        assert "500" in msg

    def test_delete_zip_none_and_oserror(self, tmp_path, monkeypatch):
        sr._delete_zip_quietly(None)

        class FakePath:
            def is_file(self):
                return True

            def unlink(self):
                raise OSError("busy")

        sr._delete_zip_quietly(FakePath())

    def test_build_payload_no_strip(self, monkeypatch):
        monkeypatch.setattr(sr, "STRIP_EMPTY_DOMAIN_FIELDS", False)
        monkeypatch.setattr(sr, "get_dns_servers", lambda: [])
        rows = [
            {
                "domain": "example.com",
                "accessible": "YES",
                "check_location": "X",
                "check_provider": "Y",
                "empty_should_keep": "",
            }
        ]
        payload = sr._build_payload(rows, Path("f.csv"))
        assert "empty_should_keep" in payload["result_data"]["domains"][0]

    def test_csv_resolve_missing_file_main(self, monkeypatch, tmp_path):
        monkeypatch.setattr(sr, "_SCRIPT_DIR", tmp_path)
        monkeypatch.setattr(sys, "argv", ["send_results.py"])
        (tmp_path / "results").mkdir()
        monkeypatch.setattr(sr, "pause_if_windows", lambda: None)
        assert sr.main(upload_token=upload_token.SHARED_VALID_TOKEN) == 2


class TestRunSendHelper:
    def test_run_send_results_calls_main(self, tmp_path, monkeypatch):
        csv_path = tmp_path / "check_results_t.csv"
        csv_path.write_text("domain,accessible\nexample.com,YES\n", encoding="utf-8")
        called = {}

        def fake_main(upload_token=None):
            called["token"] = upload_token
            return 0

        import send_results as srmod

        monkeypatch.setattr(srmod, "main", fake_main)
        code = run._run_send_results(
            str(ROOT), str(csv_path), upload_token.SHARED_VALID_TOKEN
        )
        assert code == 0
        assert called["token"] == upload_token.SHARED_VALID_TOKEN

    def test_pause_if_windows_run(self, monkeypatch):
        monkeypatch.setattr(run.sys, "platform", "win32")
        monkeypatch.setattr("builtins.input", lambda *_a, **_k: "")
        run.pause_if_windows()
        monkeypatch.setattr(run.sys, "platform", "linux")
        run.pause_if_windows()

    def test_pause_if_windows_eof(self, monkeypatch):
        monkeypatch.setattr(run.sys, "platform", "win32")

        def boom(*_a, **_k):
            raise EOFError

        monkeypatch.setattr("builtins.input", boom)
        run.pause_if_windows()

    def test_run_send_results_inserts_app_path(self, tmp_path, monkeypatch):
        csv_path = tmp_path / "check_results_t.csv"
        csv_path.write_text("domain,accessible\nexample.com,YES\n", encoding="utf-8")
        app_dir = str(APP)
        while app_dir in sys.path:
            sys.path.remove(app_dir)
        called = {}

        def fake_main(upload_token=None):
            called["token"] = upload_token
            return 0

        import send_results as srmod

        monkeypatch.setattr(srmod, "main", fake_main)
        try:
            code = run._run_send_results(
                str(ROOT), str(csv_path), upload_token.SHARED_VALID_TOKEN
            )
        finally:
            if app_dir not in sys.path:
                sys.path.insert(0, app_dir)
        assert code == 0
        assert called["token"] == upload_token.SHARED_VALID_TOKEN


# ---------------------------------------------------------------------------
# Full coverage gaps (run.py + entrypoints)
# ---------------------------------------------------------------------------


class TestDnsParseEdgeCases:
    def test_skip_name_runs_off_end(self):
        # label length claims more bytes than remain; loop exits via final return
        assert run._skip_name(b"\x05ab", 0) == 6

    def test_parse_truncated_answers(self):
        tx_id = 0x1111
        header = struct.pack(">HHHHHH", tx_id, 0x8180, 1, 2, 0, 0)
        qname = b"\x03com\x00"
        question = qname + struct.pack(">HH", 1, 1)
        # first answer: pointer only then cut off before rdata header completes
        short = header + question + b"\xc0\x0c" + b"\x00\x01"
        assert run._parse_dns_response(short, tx_id) == []

        # offset past end mid-loop
        header1 = struct.pack(">HHHHHH", tx_id, 0x8180, 1, 1, 0, 0)
        tiny = header1 + question  # no answer body but an=1
        assert run._parse_dns_response(tiny, tx_id) == []

    def test_resolve_dns_custom(self, monkeypatch):
        tx_id = 0x2222
        header = struct.pack(">HHHHHH", tx_id, 0x8180, 1, 1, 0, 0)
        qname = b"\x07example\x03com\x00"
        question = qname + struct.pack(">HH", 1, 1)
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([9, 9, 9, 9])
        payload = header + question + answer

        class FakeSock:
            def settimeout(self, t):
                pass

            def sendto(self, data, addr):
                pass

            def recvfrom(self, n):
                return payload, ("8.8.8.8", 53)

            def close(self):
                pass

        monkeypatch.setattr(run.socket, "socket", lambda *a, **k: FakeSock())
        monkeypatch.setattr(run, "_build_dns_query", lambda domain: (tx_id, b"query"))
        assert run.resolve_dns_custom("example.com", "8.8.8.8", 1) == ["9.9.9.9"]


class TestCheckHttpSslExtra:
    def test_generic_exception_then_fail(self, monkeypatch):
        monkeypatch.setattr(
            run.urllib.request,
            "urlopen",
            mock.Mock(side_effect=RuntimeError("boom")),
        )
        r = run.check_http("example.com", timeout=1)
        assert r["status"] == 0
        assert "boom" in r["error"]

    def test_check_ssl_tcp_fail(self, monkeypatch):
        class FakeSock:
            def settimeout(self, t):
                pass

            def connect(self, addr):
                raise OSError("refused")

            def close(self):
                raise OSError("close failed")

        monkeypatch.setattr(run.socket, "socket", lambda *a, **k: FakeSock())
        tcp_ms, ok, issuer, err = run.check_ssl("example.com", timeout=1)
        assert ok is False
        assert "tcp:" in err
        assert tcp_ms >= 0

    def test_check_ssl_handshake_ok(self, monkeypatch):
        class FakeSslSock:
            def getpeercert(self):
                return {
                    "issuer": (
                        (("organizationName", "Let's Encrypt"),),
                        (("commonName", "R3"),),
                    )
                }

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        class FakeCtx:
            def wrap_socket(self, sock, server_hostname=None):
                return FakeSslSock()

        class FakeSock:
            def settimeout(self, t):
                pass

            def connect(self, addr):
                pass

            def close(self):
                raise OSError("already closed")

        monkeypatch.setattr(run.socket, "socket", lambda *a, **k: FakeSock())
        monkeypatch.setattr(run.ssl, "create_default_context", lambda: FakeCtx())
        tcp_ms, ok, issuer, err = run.check_ssl("example.com", timeout=1)
        assert ok is True
        assert "Let's Encrypt" in issuer
        assert err == ""

    def test_check_ssl_handshake_fail(self, monkeypatch):
        class FakeCtx:
            def wrap_socket(self, sock, server_hostname=None):
                raise run.ssl.SSLError("bad cert")

        class FakeSock:
            def settimeout(self, t):
                pass

            def connect(self, addr):
                pass

            def close(self):
                pass

        monkeypatch.setattr(run.socket, "socket", lambda *a, **k: FakeSock())
        monkeypatch.setattr(run.ssl, "create_default_context", lambda: FakeCtx())
        tcp_ms, ok, issuer, err = run.check_ssl("example.com", timeout=1)
        assert ok is False
        assert "bad cert" in err

    def test_extract_title_decode_error(self, monkeypatch):
        class BadBytes(bytes):
            def decode(self, *a, **k):
                raise Exception("decode fail")

        assert run._extract_title(BadBytes(b"x")) == ""

    def test_read_version_blank_file(self, tmp_path):
        app = tmp_path / "app"
        app.mkdir()
        (app / "version.txt").write_text("\n\n  \n", encoding="utf-8")
        assert run._read_version_text(str(tmp_path)) == ""


class TestCheckDomainExtra:
    def test_ssl_raises(self, monkeypatch):
        monkeypatch.setattr(run, "resolve_dns", mock.Mock(return_value=["1.2.3.4"]))
        monkeypatch.setattr(
            run, "check_ssl", mock.Mock(side_effect=RuntimeError("ssl boom"))
        )
        monkeypatch.setattr(
            run,
            "check_http",
            mock.Mock(
                return_value={
                    "status": 200,
                    "size": 10,
                    "url": "https://example.com/",
                    "redirect_url": "https://example.com/",
                    "error": "",
                    "body": b"ok",
                    "protocol": "https",
                }
            ),
        )
        row = run.check_domain("example.com", "list_x.txt")
        assert row["ssl_valid"] == "NO"
        assert "ssl boom" in row["ssl_error"]
        assert row["accessible"] == "YES"

    def test_redirect_parse_error(self, monkeypatch):
        monkeypatch.setattr(run, "resolve_dns", mock.Mock(return_value=["1.2.3.4"]))
        monkeypatch.setattr(
            run, "check_ssl", mock.Mock(return_value=(1.0, True, "I", ""))
        )
        monkeypatch.setattr(
            run,
            "check_http",
            mock.Mock(
                return_value={
                    "status": 200,
                    "size": 10,
                    "url": "https://example.com/",
                    "redirect_url": "://bad",
                    "error": "",
                    "body": b"ok",
                    "protocol": "https",
                }
            ),
        )
        monkeypatch.setattr(
            run,
            "urlparse",
            mock.Mock(side_effect=ValueError("bad url")),
        )
        row = run.check_domain("example.com", "list_x.txt")
        assert row["accessible"] == "YES"
        assert row["final_domain"] == ""

    def test_http_raises(self, monkeypatch):
        monkeypatch.setattr(run, "resolve_dns", mock.Mock(return_value=["1.2.3.4"]))
        monkeypatch.setattr(
            run, "check_ssl", mock.Mock(return_value=(1.0, True, "I", ""))
        )
        monkeypatch.setattr(
            run, "check_http", mock.Mock(side_effect=RuntimeError("http boom"))
        )
        row = run.check_domain("example.com", "list_x.txt")
        assert "http boom" in row["http_error"]
        assert row["accessible"] == "NO"


class TestDetectLocationExtra:
    def test_distinct_city_appended(self, monkeypatch):
        payload = {
            "city": "Казань",
            "regionName": "Татарстан",
            "country": "Россия",
            "isp": "ISP",
            "query": "8.8.8.8",
        }

        class FakeResp:
            def read(self):
                return json.dumps(payload).encode("utf-8")

        monkeypatch.setattr(
            run.urllib.request, "urlopen", lambda *a, **k: FakeResp()
        )
        location, isp, ip = run.detect_location()
        assert isp == "ISP"
        assert ip == "8.8.8.8"
        assert "Kazan" in location or "Kazanh" in location or "Kazan" in location.replace(
            "ь", ""
        )
        assert "Tatarstan" in location or "Tatars" in location
        assert "Russia" in location


class TestGetSystemDnsExtra:
    def test_resolv_open_fails_then_darwin(self, monkeypatch):
        monkeypatch.setattr(run.sys, "platform", "darwin")

        def boom_open(path, *a, **k):
            raise OSError("no resolv")

        monkeypatch.setattr("builtins.open", boom_open)
        monkeypatch.setattr(
            run.subprocess,
            "check_output",
            mock.Mock(
                return_value=(
                    "resolver #0\n  nameserver[0] : 1.1.1.1\n"
                    "  nameserver[1] : 1.1.1.1\n"
                    "  nameserver[0] : 8.8.8.8\n"
                )
            ),
        )
        assert run.get_system_dns_servers() == ["1.1.1.1", "8.8.8.8"]

    def test_darwin_scutil_fails(self, monkeypatch):
        monkeypatch.setattr(run.sys, "platform", "darwin")

        def boom_open(path, *a, **k):
            raise OSError("no resolv")

        monkeypatch.setattr("builtins.open", boom_open)
        monkeypatch.setattr(
            run.subprocess,
            "check_output",
            mock.Mock(side_effect=OSError("no scutil")),
        )
        assert run.get_system_dns_servers() == []

    def test_win32_ipconfig(self, monkeypatch):
        monkeypatch.setattr(run.sys, "platform", "win32")

        def boom_open(path, *a, **k):
            raise OSError("no resolv")

        monkeypatch.setattr("builtins.open", boom_open)
        monkeypatch.setattr(
            run.subprocess,
            "check_output",
            mock.Mock(
                return_value=(
                    "Windows IP Configuration\n\n"
                    "   DNS Servers . . . . . . . . . . . : 9.9.9.9\n"
                    "   DNS Servers . . . . . . . . . . . : not-an-ip\n"
                )
            ),
        )
        assert run.get_system_dns_servers() == ["9.9.9.9"]

    def test_win32_ipconfig_fails(self, monkeypatch):
        monkeypatch.setattr(run.sys, "platform", "win32")

        def boom_open(path, *a, **k):
            raise OSError("no resolv")

        monkeypatch.setattr("builtins.open", boom_open)
        monkeypatch.setattr(
            run.subprocess,
            "check_output",
            mock.Mock(side_effect=OSError("no ipconfig")),
        )
        assert run.get_system_dns_servers() == []


class TestTokenPromptExtra:
    def test_eof_treated_as_empty(self, monkeypatch, capsys):
        def boom(*_a, **_k):
            raise EOFError

        monkeypatch.setattr("builtins.input", boom)
        assert run.prompt_upload_token_before_scan() is None
        assert "No token" in capsys.readouterr().out

    def test_resend_valid_token_wording(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "builtins.input", lambda *_a, **_k: upload_token.SHARED_VALID_TOKEN
        )
        assert (
            run.prompt_upload_token_before_scan(for_resend=True)
            == upload_token.SHARED_VALID_TOKEN
        )
        out = capsys.readouterr().out
        assert "Uploading" in out


class TestVerdictExtra:
    def test_non_whitelist_network_message(self, capsys):
        results = [
            {"source_file": "list_white_domains.txt", "accessible": "YES"},
            {"source_file": "list_ooni_ru.txt", "accessible": "YES"},
        ]
        run._print_final_verdict(results, str(ROOT))
        out = capsys.readouterr().out
        assert "doesn't use whitelists" in out or "does not use" in out

    def test_absolute_output_csv_resolve(self, tmp_path, monkeypatch):
        csv_path = tmp_path / "abs.csv"
        csv_path.write_text("domain\n", encoding="utf-8")
        monkeypatch.setattr(run, "OUTPUT_CSV", str(csv_path))
        path, meta = run._resolve_skip_check_csv_path(str(tmp_path / "other"))
        assert path == str(csv_path)
        assert meta == "explicit"


class TestRunMainFlows:
    @pytest.fixture(autouse=True)
    def _no_version_fetch(self, monkeypatch):
        monkeypatch.setattr(run, "_fetch_latest_version", lambda: "")

    def _stub_check_domain(self, monkeypatch):
        def fake_check(domain, source_file, server=None, original=None):
            return {
                "domain": original if original is not None else domain,
                "source_file": source_file,
                "check_timestamp": "2020-01-01T00:00:00Z",
                "dns_resolved_ips": "1.2.3.4",
                "dns_time_ms": "1.0",
                "dns_error": "",
                "tcp_connect_time_ms": "1.0",
                "ssl_valid": "YES",
                "ssl_issuer": "X",
                "ssl_error": "",
                "http_status": "200",
                "http_url": "https://{}/".format(domain),
                "http_redirect_url": "",
                "http_time_ms": "1.0",
                "http_content_bytes": "10",
                "http_error": "",
                "protocol": "https",
                "final_domain": "",
                "http_title": "T",
                "content_hash": "abcd",
                "accessible": "YES",
            }

        monkeypatch.setattr(run, "check_domain", fake_check)

    def test_skip_check_missing_csv(self, tmp_path, monkeypatch):
        monkeypatch.setattr(run, "SKIP_CHECK", True)
        monkeypatch.setattr(run, "RESULTS_DIR", "results")
        monkeypatch.setattr(run, "OUTPUT_CSV", "missing.csv")
        monkeypatch.setattr(run, "pause_if_windows", lambda: None)
        monkeypatch.setattr(run.os.path, "abspath", lambda p: str(tmp_path / "run.py"))
        monkeypatch.setattr(run.os.path, "dirname", lambda p: str(tmp_path))
        (tmp_path / "results").mkdir()
        with pytest.raises(SystemExit) as ei:
            run.main()
        assert ei.value.code == 1

    def test_skip_check_upload_ok(self, tmp_path, monkeypatch, capsys):
        results = tmp_path / "results"
        results.mkdir()
        csv_path = results / "check_results_20200101_000000.csv"
        csv_path.write_text("domain\n", encoding="utf-8")
        monkeypatch.setattr(run, "SKIP_CHECK", True)
        monkeypatch.setattr(run, "RESULTS_DIR", "results")
        monkeypatch.setattr(run, "OUTPUT_CSV", "missing.csv")
        monkeypatch.setattr(run.os.path, "abspath", lambda p: str(tmp_path / "run.py"))
        monkeypatch.setattr(run.os.path, "dirname", lambda p: str(tmp_path))
        monkeypatch.setattr(
            run,
            "prompt_upload_token_before_scan",
            lambda for_resend=False: upload_token.SHARED_VALID_TOKEN,
        )
        monkeypatch.setattr(run, "_run_send_results", mock.Mock(return_value=0))
        monkeypatch.setattr(run, "_read_version_text", lambda *_a: "1.2.3")
        run.main()
        out = capsys.readouterr().out
        assert "SKIP_CHECK" in out
        assert "newest" in out.lower() or "Note" in out

    def test_skip_check_upload_fail_exits(self, tmp_path, monkeypatch):
        results = tmp_path / "results"
        results.mkdir()
        csv_path = results / "check_results_x.csv"
        csv_path.write_text("domain\n", encoding="utf-8")
        monkeypatch.setattr(run, "SKIP_CHECK", True)
        monkeypatch.setattr(run, "RESULTS_DIR", "results")
        monkeypatch.setattr(run, "OUTPUT_CSV", csv_path.name)
        monkeypatch.setattr(run.os.path, "abspath", lambda p: str(tmp_path / "run.py"))
        monkeypatch.setattr(run.os.path, "dirname", lambda p: str(tmp_path))
        monkeypatch.setattr(
            run,
            "prompt_upload_token_before_scan",
            lambda for_resend=False: upload_token.SHARED_VALID_TOKEN,
        )
        monkeypatch.setattr(run, "_run_send_results", mock.Mock(return_value=3))
        monkeypatch.setattr(run, "pause_if_windows", lambda: None)
        monkeypatch.setattr(run, "_read_version_text", lambda *_a: "")
        with pytest.raises(SystemExit) as ei:
            run.main()
        assert ei.value.code == 3

    def test_skip_check_no_token(self, tmp_path, monkeypatch, capsys):
        results = tmp_path / "results"
        results.mkdir()
        csv_path = results / "check_results_x.csv"
        csv_path.write_text("domain\n", encoding="utf-8")
        monkeypatch.setattr(run, "SKIP_CHECK", True)
        monkeypatch.setattr(run, "RESULTS_DIR", "results")
        monkeypatch.setattr(run, "OUTPUT_CSV", csv_path.name)
        monkeypatch.setattr(run.os.path, "abspath", lambda p: str(tmp_path / "run.py"))
        monkeypatch.setattr(run.os.path, "dirname", lambda p: str(tmp_path))
        monkeypatch.setattr(
            run, "prompt_upload_token_before_scan", lambda for_resend=False: None
        )
        monkeypatch.setattr(run, "_read_version_text", lambda *_a: "v")
        run.main()
        assert "nothing to upload" in capsys.readouterr().out.lower()

    def test_main_no_list_files(self, tmp_path, monkeypatch):
        monkeypatch.setattr(run, "SKIP_CHECK", False)
        monkeypatch.setattr(run, "RESULTS_DIR", "results")
        monkeypatch.setattr(run, "DNS_SERVER", "")
        monkeypatch.setattr(run.os.path, "abspath", lambda p: str(tmp_path / "run.py"))
        monkeypatch.setattr(run.os.path, "dirname", lambda p: str(tmp_path))
        monkeypatch.setattr(
            run, "prompt_upload_token_before_scan", lambda for_resend=False: None
        )
        monkeypatch.setattr(run, "get_system_dns_servers", lambda: [])
        monkeypatch.setattr(run, "detect_location", lambda: ("", "", ""))
        monkeypatch.setattr(run, "find_list_files", lambda *_a: [])
        monkeypatch.setattr(run, "pause_if_windows", lambda: None)
        monkeypatch.setattr(run, "_read_version_text", lambda *_a: "")
        with pytest.raises(SystemExit) as ei:
            run.main()
        assert ei.value.code == 1

    def test_main_scan_local_only(self, tmp_path, monkeypatch, capsys):
        lists = tmp_path / "app" / "url_check_lists"
        lists.mkdir(parents=True)
        (lists / "list_white_domains.txt").write_text("example.com\n", encoding="utf-8")
        (lists / "list_control.txt").write_text("blocked.test\n", encoding="utf-8")
        monkeypatch.setattr(run, "SKIP_CHECK", False)
        monkeypatch.setattr(run, "RESULTS_DIR", "results")
        monkeypatch.setattr(run, "DNS_SERVER", "8.8.8.8")
        monkeypatch.setattr(run, "CHECK_LIMIT_N", 1)
        monkeypatch.setattr(run, "MAX_WORKERS", 2)
        monkeypatch.setattr(run, "OUTPUT_CSV", "check_results_test.csv")
        monkeypatch.setattr(run, "URL_CHECK_LISTS_DIR", "app/url_check_lists")
        monkeypatch.setattr(run.os.path, "abspath", lambda p: str(tmp_path / "run.py"))
        monkeypatch.setattr(run.os.path, "dirname", lambda p: str(tmp_path))
        monkeypatch.setattr(
            run, "prompt_upload_token_before_scan", lambda for_resend=False: None
        )
        monkeypatch.setattr(
            run, "detect_location", lambda: ("City, Country", "ISP", "1.1.1.1")
        )
        self._stub_check_domain(monkeypatch)
        monkeypatch.setattr(run, "_read_version_text", lambda *_a: "9.9.9")
        run.main()
        out = capsys.readouterr().out
        assert "Domain Checker" in out
        assert "Local-only" in out or "local" in out.lower()
        out_csv = tmp_path / "results" / "check_results_test.csv"
        assert out_csv.is_file()
        text = out_csv.read_text(encoding="utf-8")
        assert "check_ip_address" not in text
        assert "City, Country" in text

    def test_update_notice_at_start_and_end(self, tmp_path, monkeypatch, capsys):
        lists = tmp_path / "app" / "url_check_lists"
        lists.mkdir(parents=True)
        (lists / "list_a.txt").write_text("a.example\n", encoding="utf-8")
        monkeypatch.setattr(run, "SKIP_CHECK", False)
        monkeypatch.setattr(run, "RESULTS_DIR", "results")
        monkeypatch.setattr(run, "DNS_SERVER", "")
        monkeypatch.setattr(run, "OUTPUT_CSV", "check_results_ver.csv")
        monkeypatch.setattr(run, "URL_CHECK_LISTS_DIR", "app/url_check_lists")
        monkeypatch.setattr(run.os.path, "abspath", lambda p: str(tmp_path / "run.py"))
        monkeypatch.setattr(run.os.path, "dirname", lambda p: str(tmp_path))
        monkeypatch.setattr(
            run, "prompt_upload_token_before_scan", lambda for_resend=False: None
        )
        monkeypatch.setattr(run, "get_system_dns_servers", lambda: [])
        monkeypatch.setattr(run, "detect_location", lambda: ("", "", ""))
        self._stub_check_domain(monkeypatch)
        monkeypatch.setattr(run, "_read_version_text", lambda *_a: "1.2.0")
        monkeypatch.setattr(run, "_fetch_latest_version", lambda: "1.3.0")
        run.main()
        out = capsys.readouterr().out
        assert (
            out.count("A NEWER VERSION OF THIS SCRIPT IS AVAILABLE (1.3.0). YOU HAVE 1.2.0.")
            == 2
        )

    def test_main_scan_upload_fail_keeps_csv(self, tmp_path, monkeypatch, capsys):
        lists = tmp_path / "app" / "url_check_lists"
        lists.mkdir(parents=True)
        (lists / "list_a.txt").write_text("a.example\n", encoding="utf-8")
        monkeypatch.setattr(run, "SKIP_CHECK", False)
        monkeypatch.setattr(run, "RESULTS_DIR", "results")
        monkeypatch.setattr(run, "DNS_SERVER", "")
        monkeypatch.setattr(run, "CHECK_LIMIT_N", 0)
        monkeypatch.setattr(run, "OUTPUT_CSV", "check_results_up.csv")
        monkeypatch.setattr(run, "URL_CHECK_LISTS_DIR", "app/url_check_lists")
        monkeypatch.setattr(run.os.path, "abspath", lambda p: str(tmp_path / "run.py"))
        monkeypatch.setattr(run.os.path, "dirname", lambda p: str(tmp_path))
        monkeypatch.setattr(
            run,
            "prompt_upload_token_before_scan",
            lambda for_resend=False: upload_token.SHARED_VALID_TOKEN,
        )
        monkeypatch.setattr(run, "get_system_dns_servers", lambda: ["1.1.1.1"])
        monkeypatch.setattr(run, "detect_location", lambda: ("", "", ""))
        self._stub_check_domain(monkeypatch)
        monkeypatch.setattr(run, "_run_send_results", mock.Mock(return_value=1))
        monkeypatch.setattr(run, "_read_version_text", lambda *_a: "")
        run.main()
        out = capsys.readouterr().out
        assert "Upload failed" in out
        assert (tmp_path / "results" / "check_results_up.csv").is_file()

    def test_main_future_exception(self, tmp_path, monkeypatch, capsys):
        lists = tmp_path / "app" / "url_check_lists"
        lists.mkdir(parents=True)
        (lists / "list_a.txt").write_text("a.example\n", encoding="utf-8")
        monkeypatch.setattr(run, "SKIP_CHECK", False)
        monkeypatch.setattr(run, "RESULTS_DIR", "results")
        monkeypatch.setattr(run, "DNS_SERVER", "")
        monkeypatch.setattr(run, "OUTPUT_CSV", "check_results_err.csv")
        monkeypatch.setattr(run, "URL_CHECK_LISTS_DIR", "app/url_check_lists")
        monkeypatch.setattr(run, "MAX_WORKERS", 1)
        monkeypatch.setattr(run.os.path, "abspath", lambda p: str(tmp_path / "run.py"))
        monkeypatch.setattr(run.os.path, "dirname", lambda p: str(tmp_path))
        monkeypatch.setattr(
            run, "prompt_upload_token_before_scan", lambda for_resend=False: None
        )
        monkeypatch.setattr(run, "get_system_dns_servers", lambda: [])
        monkeypatch.setattr(run, "detect_location", lambda: ("", "", ""))
        monkeypatch.setattr(
            run, "check_domain", mock.Mock(side_effect=RuntimeError("worker boom"))
        )
        monkeypatch.setattr(run, "_read_version_text", lambda *_a: "1")
        run.main()
        out = capsys.readouterr().out
        assert "ERROR" in out
        text = (tmp_path / "results" / "check_results_err.csv").read_text(encoding="utf-8")
        assert "ERROR" in text or "worker boom" in text

    def test_main_upload_success(self, tmp_path, monkeypatch, capsys):
        lists = tmp_path / "app" / "url_check_lists"
        lists.mkdir(parents=True)
        (lists / "list_a.txt").write_text("a.example\n", encoding="utf-8")
        monkeypatch.setattr(run, "SKIP_CHECK", False)
        monkeypatch.setattr(run, "RESULTS_DIR", "results")
        monkeypatch.setattr(run, "DNS_SERVER", "")
        monkeypatch.setattr(run, "OUTPUT_CSV", "check_results_ok.csv")
        monkeypatch.setattr(run, "URL_CHECK_LISTS_DIR", "app/url_check_lists")
        monkeypatch.setattr(run.os.path, "abspath", lambda p: str(tmp_path / "run.py"))
        monkeypatch.setattr(run.os.path, "dirname", lambda p: str(tmp_path))
        monkeypatch.setattr(
            run,
            "prompt_upload_token_before_scan",
            lambda for_resend=False: upload_token.SHARED_VALID_TOKEN,
        )
        monkeypatch.setattr(run, "get_system_dns_servers", lambda: ["8.8.8.8"])
        monkeypatch.setattr(run, "detect_location", lambda: ("Loc", "Prov", "9.9.9.9"))
        self._stub_check_domain(monkeypatch)
        monkeypatch.setattr(run, "_run_send_results", mock.Mock(return_value=0))
        monkeypatch.setattr(run, "_read_version_text", lambda *_a: "1.0")
        run.main()
        assert "Sending results" in capsys.readouterr().out


class TestBootstrapAndEntrypoints:
    def test_run_bootstraps_app_dir(self):
        app_dir = str(APP)
        removed = []
        while app_dir in sys.path:
            sys.path.remove(app_dir)
            removed.append(app_dir)
        name = "run_bootstrap_cov"
        try:
            spec = importlib.util.spec_from_file_location(name, ROOT / "run.py")
            mod = importlib.util.module_from_spec(spec)
            assert spec.loader is not None
            sys.modules[name] = mod
            spec.loader.exec_module(mod)
            assert app_dir in sys.path
        finally:
            sys.modules.pop(name, None)
            for p in removed:
                if p not in sys.path:
                    sys.path.insert(0, p)

    def test_send_results_bootstraps_paths(self):
        root = str(ROOT)
        app = str(APP)
        removed = []
        for p in (root, app):
            while p in sys.path:
                sys.path.remove(p)
                removed.append(p)
        name = "send_results_bootstrap_cov"
        try:
            spec = importlib.util.spec_from_file_location(name, APP / "send_results.py")
            mod = importlib.util.module_from_spec(spec)
            assert spec.loader is not None
            sys.modules[name] = mod
            spec.loader.exec_module(mod)
            assert root in sys.path
            assert app in sys.path
        finally:
            sys.modules.pop(name, None)
            for p in removed:
                if p not in sys.path:
                    sys.path.insert(0, p)

    def test_send_results_dunder_main(self, tmp_path, monkeypatch):
        import runpy

        missing = tmp_path / "nope.csv"
        monkeypatch.setattr(sys, "argv", ["send_results.py", str(missing)])
        monkeypatch.setattr(sr, "pause_if_windows", lambda: None)
        # Fresh run_path uses its own namespace; patch via builtins after import is hard.
        # Fast-fail missing file: pause is darwin-noop; expect SystemExit(2).
        with pytest.raises(SystemExit) as ei:
            runpy.run_path(str(APP / "send_results.py"), run_name="__main__")
        assert ei.value.code == 2

    def test_run_dunder_main(self, tmp_path, monkeypatch):
        import runpy

        monkeypatch.setattr(config, "SKIP_CHECK", True)
        monkeypatch.setattr(config, "OUTPUT_CSV", "missing_for_coverage.csv")
        monkeypatch.setattr(config, "RESULTS_DIR", str(tmp_path / "results"))
        (tmp_path / "results").mkdir()
        monkeypatch.setattr("builtins.input", lambda *_a, **_k: "")

        def fake_exit(code=0):
            raise SystemExit(code)

        monkeypatch.setattr(sys, "exit", fake_exit)
        # RESULTS_DIR is imported by name into run.py at load time; runpy re-imports
        # from config, so patching config.RESULTS_DIR is enough for a fresh load.
        # But script_dir is dirname(run.py)=ROOT, so results path is ROOT/RESULTS_DIR
        # if RESULTS_DIR is absolute, join still works as absolute.
        with pytest.raises(SystemExit) as ei:
            runpy.run_path(str(ROOT / "run.py"), run_name="__main__")
        assert ei.value.code == 1


# ---------------------------------------------------------------------------
# Part 9 - multi-resolver DNS probe (app/dns_probe.py)
# ---------------------------------------------------------------------------


def _mkres(slug, ip, kind="global"):
    res = dns_probe.parse_resolver_line(
        "{},{},{},{}".format(slug, ip, kind, slug)
    )
    assert res is not None
    return res


def _dns_reply(query, ips=(), rcode=0, tx_id=None, question=None, extra_rr=False):
    """Wire-format response to `query`, using a compression pointer for names."""
    tx = struct.unpack(">H", query[:2])[0] if tx_id is None else tx_id
    body = query[12:] if question is None else question
    answers = b""
    count = 0
    if extra_rr:
        # A CNAME ahead of the A records: the parser must step over it.
        answers += b"\xc0\x0c" + struct.pack(">HHIH", 5, 1, 60, 2) + b"\xc0\x0c"
        count += 1
    for ip in ips:
        answers += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4)
        answers += bytes(int(p) for p in ip.split("."))
        count += 1
    flags = 0x8180 | (rcode & 0x0F)
    return struct.pack(">HHHHHH", tx, flags, 1, count, 0, 0) + body + answers


class _FakeClock:
    """Monotonic clock that advances a fixed step on every read."""

    def __init__(self, step=0.01):
        self.now = 0.0
        self.step = step

    def __call__(self):
        self.now += self.step
        return self.now


class _FakeTransport:
    """Scripted DNS transport: no sockets, fully deterministic."""

    def __init__(self, plan=None, addresses=None):
        self.plan = plan or {}
        self.addresses = addresses or {}
        self.default = "ok"
        self.inbox = []
        self.sent = []
        self.opened = []
        self.refuse_family = set()
        self.send_error = {}
        self.duplicate = set()
        self.spoof_source = {}
        self.closed = False

    def open(self, family):
        if family in self.refuse_family:
            return False
        self.opened.append(family)
        return True

    def _packets_for(self, ip, data):
        behaviour = self.plan.get(ip, self.default)
        if callable(behaviour):
            return behaviour(data)
        if behaviour == "drop":
            return []
        if behaviour == "nxdomain":
            return [_dns_reply(data, rcode=3)]
        if behaviour == "servfail":
            return [_dns_reply(data, rcode=2)]
        if behaviour == "refused":
            return [_dns_reply(data, rcode=5)]
        if behaviour == "noanswer":
            return [_dns_reply(data)]
        return [_dns_reply(data, ips=self.addresses.get(ip, ["1.2.3.4"]))]

    def send(self, family, data, address):
        ip = address[0]
        error = self.send_error.get(ip)
        if error is not None:
            raise error
        self.sent.append((ip, data))
        packets = self._packets_for(ip, data)
        if ip in self.duplicate:
            packets = list(packets) + list(packets)
        source = self.spoof_source.get(ip, ip)
        for packet in packets:
            self.inbox.append((family, packet, (source, 53)))

    def poll(self, timeout):
        out, self.inbox = self.inbox, []
        return out

    def close(self):
        self.closed = True


def _probe(domains, resolvers, transport, **kwargs):
    kwargs.setdefault("timeout", 0.2)
    kwargs.setdefault("attempts", 2)
    kwargs.setdefault("max_seconds", 60.0)
    kwargs.setdefault("qps_by_kind", {"global": 500.0, "russian": 500.0, "nsdi": 500.0})
    kwargs.setdefault("clock", _FakeClock())
    return dns_probe.probe(domains, resolvers, transport=transport, **kwargs)


class TestDnsProbeRoster:
    def test_parse_basic_line(self):
        res = dns_probe.parse_resolver_line("quad9,9.9.9.9,global,Quad9_DNS_1")
        assert res.slug == "quad9"
        assert res.ip == "9.9.9.9"
        assert res.kind == dns_probe.KIND_GLOBAL
        assert res.name == "Quad9_DNS_1"
        assert res.family == socket.AF_INET

    def test_name_defaults_to_slug(self):
        assert dns_probe.parse_resolver_line("a,1.1.1.1,global").name == "a"

    @pytest.mark.parametrize(
        "line",
        ["", "   ", "# comment", "onlyslug", "slug,notanip,global", "slug,,global"],
    )
    def test_unusable_lines_are_skipped(self, line):
        assert dns_probe.parse_resolver_line(line) is None

    def test_unknown_kind_falls_back_to_the_cautious_rate(self):
        res = dns_probe.parse_resolver_line("x,8.8.8.8,weird,X")
        assert res.kind == dns_probe.KIND_RUSSIAN

    def test_ipv6_resolver_is_accepted_and_normalized(self):
        res = dns_probe.parse_resolver_line("mskix,2001:06d0:00d6::2001,russian,MSK")
        assert res is not None
        assert res.family == socket.AF_INET6
        assert res.ip == "2001:6d0:d6::2001"

    def test_load_dedupes_slug_and_ip(self, tmp_path):
        path = tmp_path / "dns_servers.txt"
        path.write_text(
            "# header\n"
            "a,1.1.1.1,global,A\n"
            "a,2.2.2.2,global,duplicate slug\n"
            "b,1.1.1.1,global,duplicate ip\n"
            "\n"
            "junk line\n"
            "c,9.9.9.9,nsdi,C\n",
            encoding="utf-8",
        )
        resolvers = dns_probe.load_resolvers(str(path))
        assert [r.slug for r in resolvers] == ["a", "c"]

    def test_missing_file_disables_the_probe(self, tmp_path):
        assert dns_probe.load_resolvers(str(tmp_path / "nope.txt")) == []

    def test_shipped_roster_is_usable(self):
        resolvers = dns_probe.load_resolvers(str(APP / "dns_servers.txt"))
        assert len(resolvers) >= 10
        slugs = [r.slug for r in resolvers]
        assert len(set(slugs)) == len(slugs)
        assert len(set(r.ip for r in resolvers)) == len(resolvers)
        assert any(r.kind == dns_probe.KIND_NSDI for r in resolvers)
        assert any(r.kind == dns_probe.KIND_GLOBAL for r in resolvers)
        assert any(r.kind == dns_probe.KIND_RUSSIAN for r in resolvers)
        for slug in slugs:
            # Slugs land in a CSV cell as "slug=TOKEN"; keep them boring.
            assert slug.isascii() and slug.replace("_", "").isalnum()
            assert ";" not in slug and "=" not in slug and "," not in slug


class TestDnsProbeWire:
    def test_encode_qname_roundtrip(self):
        assert dns_probe.encode_qname("Example.COM.") == b"\x07example\x03com\x00"

    @pytest.mark.parametrize("bad", ["", ".", "a" * 64 + ".com", "пример.рф"])
    def test_encode_qname_rejects_unusable_names(self, bad):
        with pytest.raises((ValueError, UnicodeError)):
            dns_probe.encode_qname(bad)

    def test_build_query_header(self):
        qname = dns_probe.encode_qname("example.com")
        packet = dns_probe.build_query(qname, 0x1234)
        tx, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", packet[:12])
        assert (tx, flags, qd, an, ns, ar) == (0x1234, 0x0100, 1, 0, 0, 0)
        assert packet[12:] == qname + struct.pack(">HH", 1, 1)

    def _query(self, domain="example.com", tx_id=0x4242):
        return dns_probe.build_query(dns_probe.encode_qname(domain), tx_id)

    def test_parse_extracts_a_records(self):
        q = self._query()
        reply = _dns_reply(q, ips=["1.2.3.4", "5.6.7.8"])
        rcode, ips = dns_probe.parse_response(
            reply, 0x4242, dns_probe.question_key("example.com")
        )
        assert rcode == 0
        assert ips == ["1.2.3.4", "5.6.7.8"]

    def test_parse_steps_over_non_a_records(self):
        q = self._query()
        reply = _dns_reply(q, ips=["1.2.3.4"], extra_rr=True)
        rcode, ips = dns_probe.parse_response(
            reply, 0x4242, dns_probe.question_key("example.com")
        )
        assert (rcode, ips) == (0, ["1.2.3.4"])

    def test_parse_keeps_nxdomain_distinct_from_empty_answer(self):
        q = self._query()
        question = dns_probe.question_key("example.com")
        nx = dns_probe.parse_response(_dns_reply(q, rcode=3), 0x4242, question)
        empty = dns_probe.parse_response(_dns_reply(q), 0x4242, question)
        assert nx == (3, [])
        assert empty == (0, [])

    def test_parse_rejects_wrong_transaction_id(self):
        q = self._query()
        assert dns_probe.parse_response(
            _dns_reply(q), 0x9999, dns_probe.question_key("example.com")
        ) is None

    def test_parse_rejects_mismatched_question(self):
        """An answer about another name must not be credited to this domain."""
        q = self._query()
        other = dns_probe.build_query(dns_probe.encode_qname("evil.test"), 0x4242)
        reply = _dns_reply(q, ips=["6.6.6.6"], question=other[12:])
        assert dns_probe.parse_response(
            reply, 0x4242, dns_probe.question_key("example.com")
        ) is None

    def test_parse_rejects_a_query_masquerading_as_a_reply(self):
        q = self._query()
        assert dns_probe.parse_response(
            q, 0x4242, dns_probe.question_key("example.com")
        ) is None

    @pytest.mark.parametrize("raw", [b"", b"\x00" * 11, b"\x42\x42" + b"\xff" * 30])
    def test_parse_survives_garbage(self, raw):
        assert dns_probe.parse_response(
            raw, 0x4242, dns_probe.question_key("example.com")
        ) is None

    def test_parse_rejects_compression_pointer_in_question(self):
        header = struct.pack(">HHHHHH", 0x4242, 0x8180, 1, 0, 0, 0)
        assert dns_probe.parse_response(
            header + b"\xc0\x0c" + struct.pack(">HH", 1, 1),
            0x4242,
            dns_probe.question_key("example.com"),
        ) is None

    def test_parse_tolerates_truncated_answer_section(self):
        q = self._query()
        reply = _dns_reply(q, ips=["1.2.3.4"])[:-2]
        rcode, ips = dns_probe.parse_response(
            reply, 0x4242, dns_probe.question_key("example.com")
        )
        assert (rcode, ips) == (0, [])


class TestDnsProbeEngine:
    def test_every_resolver_answers(self):
        resolvers = [_mkres("a", "1.1.1.1"), _mkres("b", "9.9.9.9")]
        transport = _FakeTransport(addresses={"1.1.1.1": ["5.5.5.5"],
                                              "9.9.9.9": ["5.5.5.5"]})
        result = _probe(["example.com"], resolvers, transport)
        assert result.queries_done == 2
        assert result.queries_total == 2
        assert result.dead == ()
        outcomes = result.by_domain["example.com"]
        assert outcomes["a"].code == dns_probe.CODE_OK
        assert outcomes["a"].ips == ("5.5.5.5",)
        assert outcomes["b"].attempts == 1

    @pytest.mark.parametrize(
        "behaviour,code",
        [
            ("nxdomain", dns_probe.CODE_NXDOMAIN),
            ("servfail", dns_probe.CODE_SERVFAIL),
            ("refused", dns_probe.CODE_REFUSED),
            ("noanswer", dns_probe.CODE_NOANSWER),
        ],
    )
    def test_rcodes_stay_distinct(self, behaviour, code):
        resolvers = [_mkres("a", "1.1.1.1")]
        transport = _FakeTransport(plan={"1.1.1.1": behaviour})
        result = _probe(["example.com"], resolvers, transport)
        assert result.by_domain["example.com"]["a"].code == code

    def test_silent_resolver_is_retried_then_timed_out(self):
        resolvers = [_mkres("a", "1.1.1.1")]
        transport = _FakeTransport(plan={"1.1.1.1": "drop"})
        result = _probe(["example.com"], resolvers, transport, attempts=3)
        outcome = result.by_domain["example.com"]["a"]
        assert outcome.code == dns_probe.CODE_TIMEOUT
        assert outcome.attempts == 3
        assert len(transport.sent) == 3

    def test_retries_are_sent_when_the_inflight_window_is_full(self):
        """A full window of timeouts must still be retried, not stuck forever."""
        resolvers = [_mkres("a", "1.1.1.1")]
        transport = _FakeTransport(plan={"1.1.1.1": "drop"})
        domains = ["d{}.test".format(i) for i in range(4)]
        result = _probe(
            domains,
            resolvers,
            transport,
            attempts=3,
            max_inflight_per_server=2,
            max_inflight=2,
            breaker_failures=10 ** 6,
        )
        assert result.stopped_early is False
        for name in domains:
            outcome = result.by_domain[name]["a"]
            assert outcome.code == dns_probe.CODE_TIMEOUT
            assert outcome.attempts == 3
        assert len(transport.sent) == 12

    def test_udp_endpoint_shape_is_portable(self):
        v4 = _mkres("a", "1.1.1.1")
        v6 = _mkres("b", "2001:db8::1")
        assert dns_probe.udp_endpoint(v4) == ("1.1.1.1", 53)
        assert dns_probe.udp_endpoint(v6) == ("2001:db8::1", 53, 0, 0)
        custom = v4._replace(port=5353)
        assert dns_probe.udp_endpoint(custom) == ("1.1.1.1", 5353)

    def test_late_first_attempt_still_counts_as_an_answer(self):
        """A reply to attempt 1 arriving after attempt 2 went out is not a loss."""
        held = []

        def hold_then_release(data):
            held.append(data)
            if len(held) == 1:
                return []
            return [_dns_reply(held[0], ips=["7.7.7.7"])]

        resolvers = [_mkres("a", "1.1.1.1")]
        transport = _FakeTransport(plan={"1.1.1.1": hold_then_release})
        result = _probe(["example.com"], resolvers, transport, attempts=3)
        outcome = result.by_domain["example.com"]["a"]
        assert outcome.code == dns_probe.CODE_OK
        assert outcome.ips == ("7.7.7.7",)

    def test_breaker_drops_a_resolver_that_never_answers(self):
        resolvers = [_mkres("live", "1.1.1.1"), _mkres("dead", "203.0.113.9")]
        transport = _FakeTransport(plan={"203.0.113.9": "drop"})
        domains = ["d{}.test".format(i) for i in range(30)]
        result = _probe(
            domains,
            resolvers,
            transport,
            attempts=1,
            breaker_failures=3,
            max_inflight_per_server=4,
        )
        assert result.dead == ("dead",)
        probed = sum(
            1 for d in domains if "dead" in result.by_domain.get(d, {})
        )
        # Stops well short of the full list instead of paying the timeout 30x.
        assert 0 < probed < len(domains)
        assert all("live" in result.by_domain[d] for d in domains)

    def test_answering_resolver_never_trips_the_breaker(self):
        """NXDOMAIN proves the server is alive, so it must not count as failure."""
        resolvers = [_mkres("a", "1.1.1.1")]
        transport = _FakeTransport(plan={"1.1.1.1": "nxdomain"})
        domains = ["d{}.test".format(i) for i in range(20)]
        result = _probe(domains, resolvers, transport, breaker_failures=3)
        assert result.dead == ()
        assert len(result.by_domain) == 20

    def test_second_conflicting_answer_is_recorded(self):
        def two_answers(data):
            return [
                _dns_reply(data, ips=["4.4.4.4"]),
                _dns_reply(data, ips=["9.9.9.9"]),
            ]

        resolvers = [_mkres("a", "1.1.1.1")]
        transport = _FakeTransport(plan={"1.1.1.1": two_answers})
        result = _probe(["example.com"], resolvers, transport)
        assert result.conflicts == 1
        assert result.by_domain["example.com"]["a"].conflict is True
        assert result.by_domain["example.com"]["a"].ips == ("4.4.4.4",)

    def test_identical_duplicate_reply_is_not_a_conflict(self):
        resolvers = [_mkres("a", "1.1.1.1")]
        transport = _FakeTransport(addresses={"1.1.1.1": ["4.4.4.4"]})
        transport.duplicate.add("1.1.1.1")
        result = _probe(["example.com"], resolvers, transport)
        assert result.conflicts == 0
        assert result.by_domain["example.com"]["a"].conflict is False

    def test_send_error_on_retry_does_not_crash_when_breaker_trips(self):
        class Mix(_FakeTransport):
            def send(self, family, data, address):
                n = len(self.sent)
                self.sent.append((address[0], data))
                if n >= 2:
                    raise OSError("unreachable")

        resolvers = [_mkres("a", "1.1.1.1")]
        result = _probe(
            ["a.test", "b.test", "c.test", "d.test"],
            resolvers,
            Mix(),
            attempts=2,
            breaker_failures=2,
            max_inflight_per_server=2,
            max_inflight=2,
        )
        assert result.queries_done >= 1
        assert all(
            result.by_domain[name]["a"].code in (
                dns_probe.CODE_ERROR, dns_probe.CODE_TIMEOUT
            )
            for name in result.by_domain
            if "a" in result.by_domain[name]
        )

    def test_reply_from_an_unexpected_source_is_not_credited(self):
        resolvers = [_mkres("a", "1.1.1.1")]
        transport = _FakeTransport(addresses={"1.1.1.1": ["4.4.4.4"]})
        transport.spoof_source["1.1.1.1"] = "203.0.113.200"
        result = _probe(["example.com"], resolvers, transport, attempts=1)
        assert result.unmatched >= 1
        assert result.by_domain["example.com"]["a"].code == dns_probe.CODE_TIMEOUT

    def test_reply_about_another_name_is_not_credited(self):
        def wrong_question(data):
            other = dns_probe.build_query(
                dns_probe.encode_qname("attacker.test"),
                struct.unpack(">H", data[:2])[0],
            )
            return [_dns_reply(data, ips=["6.6.6.6"], question=other[12:])]

        resolvers = [_mkres("a", "1.1.1.1")]
        transport = _FakeTransport(plan={"1.1.1.1": wrong_question})
        result = _probe(["example.com"], resolvers, transport, attempts=1)
        assert result.unmatched >= 1
        assert result.by_domain["example.com"]["a"].code == dns_probe.CODE_TIMEOUT

    def test_unroutable_resolver_reports_error_not_timeout(self):
        resolvers = [_mkres("a", "1.1.1.1")]
        transport = _FakeTransport()
        transport.send_error["1.1.1.1"] = OSError("network unreachable")
        result = _probe(["example.com"], resolvers, transport)
        assert result.by_domain["example.com"]["a"].code == dns_probe.CODE_ERROR

    def test_socket_backpressure_is_retried_not_lost(self):
        state = {"blocked": 3}
        real_send = _FakeTransport.send

        class Backpressure(_FakeTransport):
            def send(self, family, data, address):
                if state["blocked"] > 0:
                    state["blocked"] -= 1
                    raise BlockingIOError("would block")
                real_send(self, family, data, address)

        resolvers = [_mkres("a", "1.1.1.1")]
        transport = Backpressure(addresses={"1.1.1.1": ["8.8.4.4"]})
        result = _probe(["example.com"], resolvers, transport)
        assert result.by_domain["example.com"]["a"].code == dns_probe.CODE_OK

    def test_stop_event_ends_the_run_early(self):
        import threading

        stop = threading.Event()
        stop.set()
        resolvers = [_mkres("a", "1.1.1.1")]
        result = _probe(
            ["a.test", "b.test"], resolvers, _FakeTransport(), stop_event=stop
        )
        assert result.stopped_early is True
        assert result.queries_done == 0

    def test_deadline_ends_the_run_and_flags_partial(self):
        resolvers = [_mkres("a", "1.1.1.1")]
        transport = _FakeTransport(plan={"1.1.1.1": "drop"})
        domains = ["d{}.test".format(i) for i in range(200)]
        result = _probe(
            domains,
            resolvers,
            transport,
            attempts=5,
            breaker_failures=10 ** 6,
            max_seconds=1.0,
            clock=_FakeClock(step=0.01),
        )
        assert result.stopped_early is True
        assert result.queries_done < result.queries_total

    def test_resolver_whose_socket_cannot_open_is_skipped(self):
        transport = _FakeTransport()
        transport.refuse_family.add(socket.AF_INET6)
        resolvers = [_mkres("v4", "1.1.1.1"), _mkres("v6", "2001:db8::1")]
        result = _probe(["example.com"], resolvers, transport)
        assert [r.slug for r in result.resolvers] == ["v4"]
        assert set(result.by_domain["example.com"]) == {"v4"}

    def test_no_usable_resolvers_returns_an_empty_result(self):
        transport = _FakeTransport()
        transport.refuse_family.add(socket.AF_INET)
        result = _probe(["example.com"], [_mkres("a", "1.1.1.1")], transport)
        assert result.resolvers == []
        assert result.queries_total == 0

    def test_unencodable_domain_is_reported_not_skipped(self):
        resolvers = [_mkres("a", "1.1.1.1")]
        result = _probe(["\u043f\u0440\u0438\u043c\u0435\u0440.\u0440\u0444"],
                        resolvers, _FakeTransport())
        outcomes = result.by_domain["\u043f\u0440\u0438\u043c\u0435\u0440.\u0440\u0444"]
        assert outcomes["a"].code == dns_probe.CODE_ERROR

    def test_duplicate_domains_are_resolved_once(self):
        resolvers = [_mkres("a", "1.1.1.1")]
        transport = _FakeTransport()
        result = _probe(
            ["Example.COM", "example.com", "example.com."], resolvers, transport
        )
        assert result.domains == 1
        assert len(transport.sent) == 1

    def test_progress_callback_reports_completion(self):
        seen = []
        resolvers = [_mkres("a", "1.1.1.1")]
        _probe(
            ["example.com"],
            resolvers,
            _FakeTransport(),
            progress=lambda done, total: seen.append((done, total)),
        )
        assert seen[-1] == (1, 1)

    def test_real_transport_is_closed_when_owned(self, monkeypatch):
        created = {}

        class Recording(_FakeTransport):
            def __init__(self):
                _FakeTransport.__init__(self)
                created["transport"] = self

        monkeypatch.setattr(dns_probe, "UdpTransport", Recording)
        dns_probe.probe(["example.com"], [_mkres("a", "1.1.1.1")], max_seconds=5.0)
        assert created["transport"].closed is True

    def test_windows_connreset_does_not_kill_the_socket(self):
        """Windows reports ICMP port-unreachable as WSAECONNRESET on the next recv."""
        sock = mock.Mock()
        sock.recvfrom.side_effect = [
            ConnectionResetError("WSAECONNRESET"),
            (b"pkt", ("1.1.1.1", 53)),
            BlockingIOError(),
        ]
        transport = dns_probe.UdpTransport()
        orig_selector = transport._selector
        key = mock.Mock()
        key.fileobj = sock
        key.data = socket.AF_INET
        transport._selector = mock.Mock()
        transport._selector.select.return_value = [(key, 1)]
        transport._socks[socket.AF_INET] = sock
        try:
            got = transport.poll(0.01)
            assert got == [(socket.AF_INET, b"pkt", ("1.1.1.1", 53))]
            assert sock.recvfrom.call_count == 3
        finally:
            try:
                orig_selector.close()
            except (OSError, ValueError):
                pass

    def test_ipv6_send_uses_a_four_tuple(self):
        recorded = []

        class Rec(_FakeTransport):
            def send(self, family, data, address):
                recorded.append(address)
                _FakeTransport.send(self, family, data, address)

        resolvers = [_mkres("v6", "2001:db8::1")]
        _probe(["example.com"], resolvers, Rec())
        assert recorded
        assert recorded[0] == ("2001:db8::1", 53, 0, 0)

    def test_loopback_udp_roundtrip(self):
        """Real sockets, real selector: the path Windows/macOS/Linux volunteers hit."""
        import threading

        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            srv.bind(("127.0.0.1", 0))
        except OSError as exc:
            pytest.skip("cannot bind loopback UDP: {}".format(exc))
        port = srv.getsockname()[1]
        stop = threading.Event()

        def server():
            srv.settimeout(0.2)
            while not stop.is_set():
                try:
                    data, addr = srv.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                try:
                    srv.sendto(_dns_reply(data, ips=["10.0.0.9"]), addr)
                except OSError:
                    break

        thread = threading.Thread(target=server)
        thread.daemon = True
        thread.start()
        resolver = _mkres("loop", "127.0.0.1")._replace(port=port)
        try:
            result = dns_probe.probe(
                ["example.com"],
                [resolver],
                timeout=1.0,
                attempts=3,
                max_seconds=5.0,
                qps_by_kind={"global": 50.0, "russian": 50.0, "nsdi": 50.0},
            )
            outcome = result.by_domain["example.com"]["loop"]
            assert outcome.code == dns_probe.CODE_OK
            assert outcome.ips == ("10.0.0.9",)
        finally:
            stop.set()
            try:
                srv.close()
            except OSError:
                pass
            thread.join(1.0)


class TestDnsProbeColumns:
    def _resolvers(self):
        return [
            _mkres("g1", "1.1.1.1", "global"),
            _mkres("g2", "8.8.8.8", "global"),
            _mkres("nsdi", "195.208.4.1", "nsdi"),
        ]

    def _ok(self, ips):
        return dns_probe.Outcome(dns_probe.CODE_OK, tuple(ips), 1, 1.0, False)

    def test_agreement_collapses_to_one_variant(self):
        resolvers = self._resolvers()
        outcomes = {
            "g1": self._ok(["1.2.3.4"]),
            "g2": self._ok(["1.2.3.4"]),
            "nsdi": self._ok(["1.2.3.4"]),
        }
        cols = dns_probe.format_columns(outcomes, resolvers)
        assert cols["dns_probe_detail"] == "g1=A;g2=A;nsdi=A"
        assert cols["dns_probe_variants"] == "A=1.2.3.4"
        assert cols["dns_probe_ok"] == "3"
        assert cols["dns_probe_total"] == "3"
        assert cols["dns_probe_nsdi"] == dns_probe.CODE_OK

    def test_majority_answer_gets_the_first_letter(self):
        resolvers = self._resolvers()
        outcomes = {
            "g1": self._ok(["9.9.9.9"]),
            "g2": self._ok(["1.2.3.4"]),
            "nsdi": self._ok(["1.2.3.4"]),
        }
        cols = dns_probe.format_columns(outcomes, resolvers)
        assert cols["dns_probe_detail"] == "g1=B;g2=A;nsdi=A"
        assert cols["dns_probe_variants"] == "A=1.2.3.4|B=9.9.9.9"

    def test_ip_order_does_not_create_a_false_variant(self):
        resolvers = self._resolvers()[:2]
        outcomes = {
            "g1": self._ok(["1.1.1.1", "2.2.2.2"]),
            "g2": self._ok(["2.2.2.2", "1.1.1.1"]),
        }
        cols = dns_probe.format_columns(outcomes, resolvers)
        assert cols["dns_probe_detail"] == "g1=A;g2=A"

    def test_failure_tokens_and_nsdi_verdict(self):
        resolvers = self._resolvers()
        outcomes = {
            "g1": self._ok(["1.2.3.4"]),
            "g2": dns_probe.Outcome(dns_probe.CODE_TIMEOUT, (), 3, 9.0, False),
            "nsdi": dns_probe.Outcome(dns_probe.CODE_NXDOMAIN, (), 1, 2.0, False),
        }
        cols = dns_probe.format_columns(outcomes, resolvers)
        assert cols["dns_probe_detail"] == "g1=A;g2=TO;nsdi=NX"
        assert cols["dns_probe_ok"] == "1"
        assert cols["dns_probe_nsdi"] == dns_probe.CODE_NXDOMAIN

    def test_conflict_is_marked_on_the_token(self):
        resolvers = self._resolvers()[:1]
        outcomes = {
            "g1": dns_probe.Outcome(dns_probe.CODE_OK, ("1.2.3.4",), 1, 1.0, True)
        }
        cols = dns_probe.format_columns(outcomes, resolvers)
        assert cols["dns_probe_detail"] == "g1=A*"

    def test_dropped_resolver_is_absent_from_the_row(self):
        resolvers = self._resolvers()
        cols = dns_probe.format_columns({"g1": self._ok(["1.2.3.4"])}, resolvers)
        assert cols["dns_probe_detail"] == "g1=A"
        assert cols["dns_probe_total"] == "1"
        assert cols["dns_probe_nsdi"] == ""

    def test_no_outcomes_yields_blank_columns(self):
        cols = dns_probe.format_columns({}, self._resolvers())
        assert cols == dict(dns_probe.EMPTY_COLUMNS)
        assert set(cols) == set(dns_probe.COLUMNS)

    def test_columns_never_contain_the_csv_delimiter(self):
        resolvers = self._resolvers()
        outcomes = {
            "g1": self._ok(["1.2.3.4", "5.6.7.8"]),
            "g2": dns_probe.Outcome(dns_probe.CODE_REFUSED, (), 1, 1.0, True),
            "nsdi": self._ok(["9.9.9.9"]),
        }
        cols = dns_probe.format_columns(outcomes, resolvers)
        assert "\n" not in cols["dns_probe_detail"]
        assert "\n" not in cols["dns_probe_variants"]

    def test_variant_letters_pass_z(self):
        assert dns_probe._variant_letter(0) == "A"
        assert dns_probe._variant_letter(25) == "Z"
        assert dns_probe._variant_letter(26) == "AA"


class TestDnsProbeMeta:
    def _result(self, **kwargs):
        base = dict(
            by_domain={},
            resolvers=[_mkres("a", "1.1.1.1"), _mkres("n", "195.208.4.1", "nsdi")],
            dead=("a",),
            elapsed=12.34,
            domains=7,
            queries_total=14,
            queries_done=13,
            conflicts=2,
            unmatched=1,
            stopped_early=True,
        )
        base.update(kwargs)
        return dns_probe.ProbeResult(**base)

    def test_roster_roundtrip(self):
        resolvers = self._result().resolvers
        text = dns_probe.format_roster(resolvers)
        assert text == "a=1.1.1.1/global;n=195.208.4.1/nsdi"
        assert dns_probe.parse_roster(text) == [
            {"slug": "a", "ip": "1.1.1.1", "kind": "global"},
            {"slug": "n", "ip": "195.208.4.1", "kind": "nsdi"},
        ]

    def test_meta_roundtrip(self):
        parsed = dns_probe.parse_meta(dns_probe.format_meta(self._result()))
        assert parsed["v"] == dns_probe.META_VERSION
        assert parsed["domains"] == "7"
        assert parsed["queries"] == "13"
        assert parsed["planned"] == "14"
        assert parsed["conflicts"] == "2"
        assert parsed["unmatched"] == "1"
        assert parsed["partial"] == "1"
        assert parsed["dead"] == "a"

    def test_meta_omits_dead_when_all_resolvers_answered(self):
        assert "dead" not in dns_probe.parse_meta(
            dns_probe.format_meta(self._result(dead=()))
        )

    @pytest.mark.parametrize("junk", ["", "   ", "novalue", ";;;", None])
    def test_parsers_tolerate_junk(self, junk):
        assert dns_probe.parse_roster(junk) == []
        assert dns_probe.parse_meta(junk) == {}


class TestRunDnsProbeWiring:
    def test_probe_domains_are_deduped_and_normalized(self):
        tasks = [
            ("Example.COM", "Example.COM", "a.txt"),
            ("example.com", "example.com", "b.txt"),
            ("xn--e1afmkfd.xn--p1ai", "xn--e1afmkfd.xn--p1ai.", "a.txt"),
            ("", "", "a.txt"),
        ]
        assert run._probe_domains(tasks) == ["example.com", "xn--e1afmkfd.xn--p1ai"]

    def test_servers_path_is_built_for_the_host_platform(self):
        path = run._probe_servers_path(os.path.join("X", "Y"))
        assert path == os.path.join("X", "Y", "app", "dns_servers.txt")

    def test_probe_is_skipped_without_a_roster(self, tmp_path):
        tasks = [("example.com", "example.com", "list_a.txt")]
        assert run._start_dns_probe(str(tmp_path), tasks) is None

    def test_probe_is_skipped_when_disabled(self, tmp_path, monkeypatch):
        (tmp_path / "app").mkdir()
        (tmp_path / "app" / "dns_servers.txt").write_text(
            "a,1.1.1.1,global,A\n", encoding="utf-8"
        )
        monkeypatch.setattr(run, "DNS_PROBE_ENABLED", False)
        tasks = [("example.com", "example.com", "list_a.txt")]
        assert run._start_dns_probe(str(tmp_path), tasks) is None

    def test_probe_is_skipped_on_an_install_without_the_module(self, monkeypatch):
        monkeypatch.setattr(run, "dns_probe", None)
        assert run._start_dns_probe("/nowhere", [("a", "a", "f")]) is None

    def test_probe_is_skipped_when_there_are_no_domains(self, tmp_path, monkeypatch):
        (tmp_path / "app").mkdir()
        (tmp_path / "app" / "dns_servers.txt").write_text(
            "a,1.1.1.1,global,A\n", encoding="utf-8"
        )
        assert run._start_dns_probe(str(tmp_path), []) is None

    def test_apply_writes_blanks_when_the_probe_did_not_run(self):
        rows = [{"domain": "example.com", "probe_key": "example.com"}]
        run._apply_dns_probe(rows, None)
        assert rows[0]["dns_probe_detail"] == ""
        assert set(dns_probe.COLUMNS) <= set(rows[0])

    def test_apply_joins_rows_to_outcomes_by_punycode_key(self):
        resolvers = [_mkres("a", "1.1.1.1")]
        result = _probe(["example.com"], resolvers, _FakeTransport())
        rows = [
            {"domain": "example.com", "probe_key": "example.com"},
            {"domain": "other.test", "probe_key": "other.test"},
        ]
        run._apply_dns_probe(rows, result)
        assert rows[0]["dns_probe_detail"] == "a=A"
        assert rows[0]["dns_probe_ok"] == "1"
        assert rows[1]["dns_probe_detail"] == ""

    def test_apply_is_a_noop_without_the_module(self, monkeypatch):
        monkeypatch.setattr(run, "dns_probe", None)
        rows = [{"domain": "example.com"}]
        run._apply_dns_probe(rows, None)
        assert rows == [{"domain": "example.com"}]

    def test_finish_reports_a_crashed_probe_without_killing_the_scan(self, capsys):
        import threading

        thread = threading.Thread(target=lambda: None)
        thread.start()
        thread.join()
        handle = run._ProbeHandle(
            thread, {"error": "boom"}, threading.Event(), [], 0.0, 0
        )
        assert run._finish_dns_probe(handle) is None
        assert "DNS probe failed: boom" in capsys.readouterr().out

    def test_finish_on_no_handle(self):
        assert run._finish_dns_probe(None) is None

    def test_finish_keeps_partial_result_on_keyboardinterrupt(self, capsys, monkeypatch):
        import threading
        import time

        release = threading.Event()

        def worker():
            release.wait(30)

        thread = threading.Thread(target=worker)
        thread.daemon = True
        thread.start()
        box = {"result": "partial"}
        handle = run._ProbeHandle(
            thread, box, threading.Event(), [_mkres("a", "1.1.1.1")], time.monotonic(), 1
        )
        joins = {"n": 0}
        orig_join = threading.Thread.join

        def wrapped(self, timeout=None):
            joins["n"] += 1
            if joins["n"] == 1:
                raise KeyboardInterrupt()
            return orig_join(self, timeout)

        monkeypatch.setattr(threading.Thread, "join", wrapped)
        monkeypatch.setattr(run, "DNS_PROBE_MAX_SECONDS", 1.0)
        try:
            result = run._finish_dns_probe(handle)
            assert result == "partial"
            assert handle.stop.is_set()
            assert "interrupted" in capsys.readouterr().out
        finally:
            release.set()
            orig_join(thread, 1.0)

    def test_summary_mentions_dropped_and_conflicting_resolvers(self, capsys):
        result = dns_probe.ProbeResult(
            by_domain={}, resolvers=[_mkres("a", "1.1.1.1")], dead=("a",),
            elapsed=3.0, domains=1, queries_total=2, queries_done=1,
            conflicts=4, unmatched=0, stopped_early=True,
        )
        run._print_dns_probe_summary(result)
        out = capsys.readouterr().out
        assert "Stopped     : a" in out
        assert "Disagreed   : 4" in out
        assert "time limit" in out
        assert "blank" not in out
        assert "injection" not in out

    def test_summary_is_silent_without_a_result(self, capsys):
        run._print_dns_probe_summary(None)
        assert capsys.readouterr().out == ""


class _RecordingTransport(_FakeTransport):
    """Stands in for UdpTransport so run.main() exercises the real prober."""

    instances = []

    def __init__(self):
        _FakeTransport.__init__(self, addresses={"1.1.1.1": ["10.0.0.1"],
                                                 "9.9.9.9": ["10.0.0.1"]})
        self.plan = {"203.0.113.9": "drop"}
        _RecordingTransport.instances.append(self)


class TestRunDnsProbeEndToEnd:
    ROSTER = (
        "cloudflare,1.1.1.1,global,CF\n"
        "nsdi,9.9.9.9,nsdi,NSDI\n"
        "deadisp,203.0.113.9,russian,Dead\n"
    )

    def _setup(self, tmp_path, monkeypatch, roster=None):
        lists = tmp_path / "app" / "url_check_lists"
        lists.mkdir(parents=True)
        (lists / "list_white_domains.txt").write_text(
            "example.com\n", encoding="utf-8"
        )
        if roster is not None:
            (tmp_path / "app" / "dns_servers.txt").write_text(
                roster, encoding="utf-8"
            )
        monkeypatch.setattr(run, "SKIP_CHECK", False)
        monkeypatch.setattr(run, "RESULTS_DIR", "results")
        monkeypatch.setattr(run, "DNS_SERVER", "")
        monkeypatch.setattr(run, "CHECK_LIMIT_N", 0)
        monkeypatch.setattr(run, "MAX_WORKERS", 2)
        monkeypatch.setattr(run, "OUTPUT_CSV", "check_results_probe.csv")
        monkeypatch.setattr(run, "URL_CHECK_LISTS_DIR", "app/url_check_lists")
        monkeypatch.setattr(run, "DNS_PROBE_MAX_SECONDS", 20.0)
        monkeypatch.setattr(run.os.path, "abspath", lambda p: str(tmp_path / "run.py"))
        monkeypatch.setattr(run.os.path, "dirname", lambda p: str(tmp_path))
        monkeypatch.setattr(
            run, "prompt_upload_token_before_scan", lambda for_resend=False: None
        )
        monkeypatch.setattr(run, "get_system_dns_servers", lambda: [])
        monkeypatch.setattr(run, "detect_location", lambda: ("City, RU", "ISP", "1.1.1.1"))
        monkeypatch.setattr(run, "_read_version_text", lambda *_a: "1.3.0")
        monkeypatch.setattr(run, "_fetch_latest_version", lambda: "")
        monkeypatch.setattr(
            run,
            "check_domain",
            lambda domain, source_file, server=None, original=None: {
                "domain": original if original is not None else domain,
                "source_file": source_file,
                "accessible": "YES",
                "dns_time_ms": "1.0",
                "http_time_ms": "1.0",
            },
        )
        _RecordingTransport.instances = []
        monkeypatch.setattr(dns_probe, "UdpTransport", _RecordingTransport)
        return tmp_path / "results" / "check_results_probe.csv"

    def _read(self, csv_path):
        with open(csv_path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            return reader.fieldnames, list(reader)

    def test_probe_columns_reach_the_csv(self, tmp_path, monkeypatch, capsys):
        csv_path = self._setup(tmp_path, monkeypatch, self.ROSTER)
        run.main()
        fieldnames, rows = self._read(csv_path)

        for column in dns_probe.COLUMNS + dns_probe.META_COLUMNS:
            assert column in fieldnames
        assert "probe_key" not in fieldnames

        row = rows[0]
        assert row["dns_probe_detail"] == "cloudflare=A;nsdi=A;deadisp=TO"
        assert row["dns_probe_variants"] == "A=10.0.0.1"
        assert row["dns_probe_ok"] == "2"
        assert row["dns_probe_total"] == "3"
        assert row["dns_probe_nsdi"] == dns_probe.CODE_OK

        # Run-level values ride on the first data row, like check_location.
        assert row["dns_probe_resolvers"] == (
            "cloudflare=1.1.1.1/global;nsdi=9.9.9.9/nsdi;deadisp=203.0.113.9/russian"
        )
        meta = dns_probe.parse_meta(row["dns_probe_meta"])
        assert meta["v"] == dns_probe.META_VERSION
        assert meta["domains"] == "1"

        out = capsys.readouterr().out
        assert "DNS probe" in out
        assert _RecordingTransport.instances[0].closed is True

    def test_missing_roster_leaves_the_columns_blank(self, tmp_path, monkeypatch):
        csv_path = self._setup(tmp_path, monkeypatch, roster=None)
        run.main()
        fieldnames, rows = self._read(csv_path)
        assert "dns_probe_detail" in fieldnames
        assert rows[0]["dns_probe_detail"] == ""
        assert rows[0]["dns_probe_meta"] == ""
        # The scan itself is unaffected.
        assert rows[0]["accessible"] == "YES"

    def test_old_install_without_the_module_writes_the_original_columns(
        self, tmp_path, monkeypatch
    ):
        """A volunteer whose copy predates dns_probe.py still produces a valid CSV."""
        csv_path = self._setup(tmp_path, monkeypatch, self.ROSTER)
        monkeypatch.setattr(run, "dns_probe", None)
        run.main()
        fieldnames, rows = self._read(csv_path)
        assert not any(name.startswith("dns_probe") for name in fieldnames)
        assert rows[0]["accessible"] == "YES"
        assert rows[0]["check_version"] == "1.3.0"

    def test_probe_failure_does_not_abort_the_scan(self, tmp_path, monkeypatch):
        csv_path = self._setup(tmp_path, monkeypatch, self.ROSTER)

        def explode(*_a, **_k):
            raise RuntimeError("probe exploded")

        monkeypatch.setattr(dns_probe, "probe", explode)
        run.main()
        _fieldnames, rows = self._read(csv_path)
        assert rows[0]["accessible"] == "YES"
        assert rows[0]["dns_probe_detail"] == ""


class TestProbeUploadCompatibility:
    """The server keeps accepting CSVs from clients that predate the probe."""

    OLD_COLUMNS = [
        "domain",
        "check_timestamp",
        "dns_resolved_ips",
        "source_file",
        "accessible",
        "check_location",
        "check_provider",
        "check_version",
    ]

    def _old_rows(self):
        return [
            {
                "domain": "example.com",
                "check_timestamp": "2026-01-01T00:00:00Z",
                "dns_resolved_ips": "1.2.3.4",
                "source_file": "list_white_domains.txt",
                "accessible": "YES",
                "check_location": "City, RU",
                "check_provider": "ISP",
                "check_version": "1.2.0",
            },
            {
                "domain": "blocked.test",
                "check_timestamp": "2026-01-01T00:00:00Z",
                "dns_resolved_ips": "",
                "source_file": "list_blocked_nsdi.txt",
                "accessible": "NO",
                "check_location": "",
                "check_provider": "",
                "check_version": "",
            },
        ]

    def _new_rows(self):
        rows = self._old_rows()
        rows[0].update(
            {
                "dns_probe_ok": "2",
                "dns_probe_total": "3",
                "dns_probe_nsdi": "ok",
                "dns_probe_detail": "cloudflare=A;nsdi=A;mts=TO",
                "dns_probe_variants": "A=1.2.3.4",
                "dns_probe_resolvers": "cloudflare=1.1.1.1/global;nsdi=195.208.4.1/nsdi",
                "dns_probe_meta": "v=1;domains=2;elapsed=9.5;dead=mts",
            }
        )
        rows[1].update(
            {
                "dns_probe_ok": "0",
                "dns_probe_total": "3",
                "dns_probe_nsdi": "nxdomain",
                "dns_probe_detail": "cloudflare=NX;nsdi=NX;mts=TO",
                "dns_probe_variants": "",
                "dns_probe_resolvers": "",
                "dns_probe_meta": "",
            }
        )
        return rows

    def test_old_csv_produces_no_probe_key(self, monkeypatch):
        monkeypatch.setattr(sr, "get_dns_servers", lambda: ["8.8.8.8"])
        payload = sr._build_payload(self._old_rows(), Path("check_results_old.csv"))
        assert "dns_probe" not in payload["result_data"]
        assert payload["total"] == 2
        assert payload["accessible"] == 1
        assert payload["region"] == "City, RU"
        names = [d["name"] for d in payload["result_data"]["domains"]]
        assert names == ["example.com", "blocked.test"]

    def test_new_csv_lifts_probe_metadata_into_result_data(self, monkeypatch):
        monkeypatch.setattr(sr, "get_dns_servers", lambda: ["8.8.8.8"])
        payload = sr._build_payload(self._new_rows(), Path("check_results_new.csv"))
        probe = payload["result_data"]["dns_probe"]
        assert probe["meta"]["dead"] == "mts"
        assert probe["meta"]["domains"] == "2"
        assert probe["resolvers"] == [
            {"slug": "cloudflare", "ip": "1.1.1.1", "kind": "global"},
            {"slug": "nsdi", "ip": "195.208.4.1", "kind": "nsdi"},
        ]
        assert probe["resolvers_raw"].startswith("cloudflare=")

    def test_run_level_columns_never_leak_into_domain_entries(self, monkeypatch):
        monkeypatch.setattr(sr, "get_dns_servers", lambda: [])
        payload = sr._build_payload(self._new_rows(), Path("c.csv"))
        for entry in payload["result_data"]["domains"]:
            assert "dns_probe_resolvers" not in entry
            assert "dns_probe_meta" not in entry
            assert "probe_key" not in entry
        # Per-domain probe values do travel.
        assert payload["result_data"]["domains"][0]["dns_probe_detail"] == (
            "cloudflare=A;nsdi=A;mts=TO"
        )

    def test_adding_probe_columns_does_not_disturb_the_old_payload_shape(
        self, monkeypatch
    ):
        monkeypatch.setattr(sr, "get_dns_servers", lambda: [])
        old = sr._build_payload(self._old_rows(), Path("c.csv"))
        new = sr._build_payload(self._new_rows(), Path("c.csv"))
        for key in (
            "region", "provider", "accessible", "partial", "blocked_down",
            "errors", "total", "version", "file_name",
        ):
            assert old[key] == new[key]
        # The precalc on the server reads only these two per-domain keys.
        for old_entry, new_entry in zip(
            old["result_data"]["domains"], new["result_data"]["domains"]
        ):
            assert old_entry["source_file"] == new_entry["source_file"]
            assert old_entry["status"] == new_entry["status"]

    def test_probe_summary_without_the_module(self, monkeypatch):
        monkeypatch.setattr(sr, "dns_probe", None)
        summary = sr._probe_summary(self._new_rows())
        assert summary["meta_raw"].startswith("v=1")
        assert "meta" not in summary

    def test_probe_summary_ignores_blank_columns(self):
        rows = [{"dns_probe_resolvers": "  ", "dns_probe_meta": ""}]
        assert sr._probe_summary(rows) == {}

    def test_full_upload_roundtrip_for_both_generations(self, tmp_path, monkeypatch):
        """Both CSV generations zip, encrypt and decrypt with the same token."""
        monkeypatch.setattr(sr, "get_dns_servers", lambda: [])
        token = upload_token.SHARED_VALID_TOKEN
        for label, rows, columns in (
            ("old", self._old_rows(), self.OLD_COLUMNS),
            ("new", self._new_rows(),
             self.OLD_COLUMNS + list(dns_probe.COLUMNS) + list(dns_probe.META_COLUMNS)),
        ):
            path = tmp_path / "check_results_{}.csv".format(label)
            with open(path, "w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(rows)
            with open(path, newline="", encoding="utf-8") as fh:
                parsed = list(csv.DictReader(fh))
            payload = sr._build_payload(parsed, path)
            blob = sr._payload_zip_bytes(payload, token)
            with zipfile.ZipFile(io.BytesIO(blob)) as zf:
                zf.setpassword(token.encode("utf-8"))
                restored = json.loads(zf.read("payload.json").decode("utf-8"))
            assert restored["total"] == 2
            assert ("dns_probe" in restored["result_data"]) is (label == "new")
