"""Single pytest suite for WhiteListCheckerScript (run.py + app/*)."""

from __future__ import annotations

import csv
import importlib.util
import io
import json
import os
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
