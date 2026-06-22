"""
Tests for the local CDR variant: the pure ``cdr_dispatch`` decision core and the FastAPI
service (``app.py``) layered on top.

Per pitfall #30, an independently-importable module (``app.py``) ships with its own test
file. This sets the same env-var defaults conftest.py does *before* importing the modules,
so the module-level boto3 clients construct offline — independent of test_cdr.py's
collection order.

Two things are proven here:
  1. cdr_dispatch makes the documented decision for every routing branch and performs NO
     S3/SNS/CloudWatch I/O.
  2. The FastAPI /sanitise endpoint returns clean bytes on success and the correct status
     codes for rejected / unsupported / error inputs — using the SAME decision core as the
     Lambda, so there is no second implementation to drift.
"""

import io
import json
import os
import zipfile

os.environ.setdefault("SANITISED_BUCKET", "local-cdr-test")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")
os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")

import pytest
from fastapi.testclient import TestClient

import lambda_function as cdr
import app as local_app
from test_cdr import (
    _make_docx_with_macro,
    _make_pdf_with_js,
    _make_image_with_exif,
    _make_xlsb,
)
from PIL import Image


client = TestClient(local_app.app)


# ── cdr_dispatch: pure decision core ────────────────────────────────────────────

class TestCdrDispatchRouting:
    def test_office_macro_sanitised(self):
        res = cdr.cdr_dispatch(_make_docx_with_macro(), "docx")
        assert res["status"] == "sanitised"
        assert res["data"] is not None
        # vbaProject.bin must be gone from the rebuilt archive
        names = zipfile.ZipFile(io.BytesIO(res["data"])).namelist()
        assert "word/vbaProject.bin" not in names
        assert res["delete_source"] is True

    def test_macro_enabled_ext_remapped(self):
        res = cdr.cdr_dispatch(_make_docx_with_macro(), "docm")
        assert res["status"] == "sanitised"
        assert res["original_ext"] == "docm"
        assert res["sanitised_ext"] == "docx"

    def test_pdf_sanitised(self):
        res = cdr.cdr_dispatch(_make_pdf_with_js(), "pdf")
        assert res["status"] == "sanitised"
        assert b"/OpenAction" not in res["data"]

    def test_image_sanitised(self):
        res = cdr.cdr_dispatch(_make_image_with_exif("JPEG"), "jpg")
        assert res["status"] == "sanitised"
        assert b"Camera" not in res["data"]  # EXIF Make tag stripped

    def test_legacy_ole_unsupported(self):
        res = cdr.cdr_dispatch(b"\xd0\xcf\x11\xe0junk", "doc")
        assert res["status"] == "unsupported-format"
        assert res["data"] is None
        assert res["delete_source"] is True

    def test_rtf_fail_closed(self):
        res = cdr.cdr_dispatch(b"{\\rtf1 anything}", "rtf")
        assert res["status"] == "unsupported-format"
        assert "rejected by design" in res["reason"]
        assert res["metric"] == "passthrough"

    def test_unknown_extension_fail_closed(self):
        res = cdr.cdr_dispatch(b"<svg onload=alert(1)>", "svg")
        assert res["status"] == "unsupported-format"
        assert "unsupported extension" in res["reason"]
        assert res["metric"] == "passthrough"

    def test_non_ooxml_zip_rejected(self):
        # A valid ZIP that is not an OOXML package (no [Content_Types].xml) is hard-rejected.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("arbitrary.txt", b"not office")
        res = cdr.cdr_dispatch(buf.getvalue(), "docx")
        assert res["status"] == "rejected"
        assert res["metric"] == "zip-anomaly"
        assert res["delete_source"] is True

    def test_oversize_rejected(self):
        res = cdr.cdr_dispatch(b"x" * 2048, "pdf", max_file_bytes=1024)
        assert res["status"] == "rejected"
        assert res["reason"] == "file too large"

    def test_dispatch_does_no_io(self, monkeypatch):
        # Any S3/SNS/CloudWatch call from the pure core is a bug. Trip a flag if touched.
        for c in ("s3", "sns", "cw"):
            obj = getattr(cdr, c)
            monkeypatch.setattr(
                obj, "_make_api_call",
                lambda *a, **k: (_ for _ in ()).throw(AssertionError("cdr_dispatch did I/O")),
                raising=False,
            )
        cdr.cdr_dispatch(_make_docx_with_macro(), "docx")
        cdr.cdr_dispatch(b"{\\rtf1}", "rtf")


# ── FastAPI service ──────────────────────────────────────────────────────────────

class TestSanitiseEndpoint:
    def test_healthz(self):
        r = client.get("/healthz")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert "docx" in body["office_exts"]
        assert "rtf" in body["rejected_by_design"]

    def test_sanitise_office_returns_clean_bytes(self):
        r = client.post(
            "/sanitise",
            files={"file": ("dirty.docm", _make_docx_with_macro(),
                            "application/vnd.ms-word.document.macroEnabled.12")},
        )
        assert r.status_code == 200
        assert r.headers["x-cdr-status"] == "sanitised"
        assert r.headers["x-cdr-original-ext"] == "docm"
        assert r.headers["x-cdr-sanitised-ext"] == "docx"
        assert 'filename="dirty.docx"' in r.headers["content-disposition"]
        names = zipfile.ZipFile(io.BytesIO(r.content)).namelist()
        assert "word/vbaProject.bin" not in names

    def test_sanitise_pdf(self):
        r = client.post("/sanitise",
                        files={"file": ("x.pdf", _make_pdf_with_js(), "application/pdf")})
        assert r.status_code == 200
        assert b"/OpenAction" not in r.content

    def test_report_header_is_valid_json(self):
        r = client.post("/sanitise",
                        files={"file": ("x.docx", _make_docx_with_macro(), "application/zip")})
        assert r.status_code == 200
        report = json.loads(r.headers["x-cdr-report"])
        assert "removed" in report

    def test_rtf_rejected_422(self):
        r = client.post("/sanitise",
                        files={"file": ("x.rtf", b"{\\rtf1 evil}", "application/rtf")})
        assert r.status_code == 422
        assert r.json()["status"] == "unsupported-format"

    def test_unknown_ext_rejected_422(self):
        r = client.post("/sanitise",
                        files={"file": ("x.svg", b"<svg/>", "image/svg+xml")})
        assert r.status_code == 422
        assert "unsupported extension" in r.json()["reason"]

    def test_corrupt_pdf_returns_500(self):
        r = client.post("/sanitise",
                        files={"file": ("x.pdf", b"%PDF-1.4 not really a pdf", "application/pdf")})
        assert r.status_code == 500
        assert r.json()["status"] == "error"

    def test_non_ooxml_zip_rejected_422(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("a.txt", b"x")
        r = client.post("/sanitise",
                        files={"file": ("x.docx", buf.getvalue(), "application/zip")})
        assert r.status_code == 422
        assert r.json()["status"] == "rejected"

    def test_healthz_full_contract(self):
        body = client.get("/healthz").json()
        assert body["pdf"] is True
        assert "jpg" in body["image_exts"]
        assert body["max_file_bytes"] == cdr._MAX_FILE_BYTES
        # rejected_by_design is the LEGACY | FAIL_CLOSED union — pin both halves.
        assert {"doc", "xls", "ppt", "rtf"} <= set(body["rejected_by_design"])

    def test_clean_image_removals_zero(self):
        # A freshly-generated image with no metadata: sanitised, nothing removed.
        buf = io.BytesIO()
        Image.new("RGB", (8, 8), (1, 2, 3)).save(buf, format="PNG")
        r = client.post("/sanitise",
                        files={"file": ("clean.png", buf.getvalue(), "image/png")})
        assert r.status_code == 200
        assert r.headers["x-cdr-removals"] == "0"
        assert r.headers["x-cdr-sanitised-ext"] == "png"

    def test_jpeg_returns_clean_bytes(self):
        r = client.post("/sanitise",
                        files={"file": ("p.jpg", _make_image_with_exif("JPEG"), "image/jpeg")})
        assert r.status_code == 200
        assert r.headers["x-cdr-sanitised-ext"] == "jpg"
        assert b"Camera" not in r.content  # EXIF Make tag stripped

    def test_xlsb_remapped_to_xlsx(self):
        r = client.post("/sanitise",
                        files={"file": ("book.xlsb", _make_xlsb(), "application/octet-stream")})
        assert r.status_code == 200
        assert r.headers["x-cdr-sanitised-ext"] == "xlsx"
        assert "filename*=UTF-8''book.xlsx" in r.headers["content-disposition"]
        # output is a valid openpyxl-openable xlsx
        import openpyxl
        openpyxl.load_workbook(io.BytesIO(r.content))

    def test_zero_byte_docx_rejected(self):
        r = client.post("/sanitise",
                        files={"file": ("x.docx", b"", "application/zip")})
        assert r.status_code == 422
        assert r.json()["status"] == "rejected"

    def test_empty_filename_rejected(self):
        # An empty filename is treated by FastAPI as a missing file part -> its own 422
        # validation error (not the app's unsupported-format path). Either way it is NOT
        # accepted as sanitised — that is the security-relevant invariant.
        r = client.post("/sanitise",
                        files={"file": ("", _make_docx_with_macro(), "application/zip")})
        assert r.status_code == 422
        assert "x-cdr-status" not in {k.lower() for k in r.headers}

    def test_no_extension_filename_unsupported(self):
        r = client.post("/sanitise",
                        files={"file": ("document", _make_docx_with_macro(), "application/zip")})
        assert r.status_code == 422
        assert r.json()["status"] == "unsupported-format"

    def test_no_file_field_422(self):
        # FastAPI's own validation: the required `file` part is missing.
        r = client.post("/sanitise")
        assert r.status_code == 422
        # distinguish FastAPI validation shape from the app's own 422 reason shape
        assert any("file" in str(e.get("loc", "")) for e in r.json()["detail"])


# ── HTTP layer: hardening (findings A–F from the audit) ──────────────────────────

class TestSizeLimit:
    def test_oversize_via_http_413(self, monkeypatch):
        # Authoritative counted read: a body over the limit is 413, regardless of any
        # declared Content-Length (TestClient sets a correct one here anyway).
        monkeypatch.setattr(cdr, "_MAX_FILE_BYTES", 1024)
        r = client.post("/sanitise",
                        files={"file": ("big.pdf", b"x" * 4096, "application/pdf")})
        assert r.status_code == 413
        assert r.json()["status"] == "rejected"
        assert r.json()["reason"] == "file too large"

    def test_under_limit_not_rejected_for_size(self, monkeypatch):
        # A file comfortably under the limit passes the size gate (then fails on content,
        # proving the guard let it through rather than 413-ing it). The limit is generous
        # enough to absorb multipart framing overhead in the request Content-Length.
        monkeypatch.setattr(cdr, "_MAX_FILE_BYTES", 100_000)
        r = client.post("/sanitise",
                        files={"file": ("x.docx", b"x" * 64, "application/zip")})
        assert r.status_code != 413  # size gate passed; ZIP validation then rejects (422)
        assert r.status_code == 422

    def test_read_bounded_counts_actual_bytes(self):
        # Content-Length is advisory; _read_bounded is the authoritative guard. It returns
        # None (-> caller 413s) once the counted bytes exceed the limit, regardless of any
        # declared size. Drive the helper directly with a fake UploadFile.
        import asyncio

        class _FakeUpload:
            def __init__(self, payload, chunk):
                self._buf = io.BytesIO(payload)
                self._chunk = chunk
            async def read(self, n=-1):
                return self._buf.read(n if n and n > 0 else None)

        # over the limit -> None
        over = _FakeUpload(b"z" * 5000, local_app._READ_CHUNK)
        assert asyncio.run(local_app._read_bounded(over, 1024)) is None
        # at/under the limit -> full bytes
        under = _FakeUpload(b"z" * 1024, local_app._READ_CHUNK)
        assert asyncio.run(local_app._read_bounded(under, 1024)) == b"z" * 1024

    def test_oversize_rejected_before_handler_runs(self, monkeypatch):
        # The Codex finding: the limit must be enforced BEFORE the multipart parser / route
        # function. Prove the route function never runs on an oversize upload by tripping a
        # sentinel inside cdr_dispatch — it must stay False, and the response must be 413.
        monkeypatch.setattr(cdr, "_MAX_FILE_BYTES", 1024)
        reached = {"handler": False}

        def _spy(*a, **k):
            reached["handler"] = True
            raise AssertionError("cdr_dispatch must not run on an oversize upload")
        monkeypatch.setattr(cdr, "cdr_dispatch", _spy)

        r = client.post("/sanitise",
                        files={"file": ("big.pdf", b"x" * 8192, "application/pdf")})
        assert r.status_code == 413
        assert reached["handler"] is False  # middleware short-circuited before the route

    def test_middleware_rejects_honest_content_length_without_reading_body(self):
        # An honest oversize Content-Length is rejected by the middleware without ever
        # pulling the body off the wire (no receive() call). Drive the ASGI app directly.
        import asyncio
        old = cdr._MAX_FILE_BYTES
        cdr._MAX_FILE_BYTES = 1024
        try:
            received = {"status": None, "receive_called": False}

            async def receive():
                received["receive_called"] = True
                return {"type": "http.request", "body": b"y" * 8192, "more_body": False}

            async def send(msg):
                if msg["type"] == "http.response.start":
                    received["status"] = msg["status"]

            scope = {
                "type": "http", "http_version": "1.1", "method": "POST",
                "path": "/sanitise", "raw_path": b"/sanitise", "query_string": b"",
                "scheme": "http",
                "headers": [
                    (b"host", b"testserver"),
                    (b"content-type", b"multipart/form-data; boundary=B"),
                    (b"content-length", b"8192"),  # honest, oversize
                ],
                "client": ("127.0.0.1", 1), "server": ("testserver", 80),
            }
            asyncio.run(local_app.app(scope, receive, send))
            assert received["status"] == 413
            assert received["receive_called"] is False  # body never read off the wire
        finally:
            cdr._MAX_FILE_BYTES = old

    def test_middleware_catches_understated_content_length(self):
        # A lying (understated) Content-Length must NOT bypass the guard: the byte counter
        # over the streamed body is authoritative and trips 413.
        import asyncio
        old = cdr._MAX_FILE_BYTES
        cdr._MAX_FILE_BYTES = 1024
        try:
            result = {"status": None}
            boundary = "B"
            part = (f"--{boundary}\r\n"
                    'Content-Disposition: form-data; name="file"; filename="x.pdf"\r\n'
                    "Content-Type: application/pdf\r\n\r\n").encode() + b"y" * 8192 + \
                   f"\r\n--{boundary}--\r\n".encode()

            async def receive():
                return {"type": "http.request", "body": part, "more_body": False}

            async def send(msg):
                if msg["type"] == "http.response.start":
                    result["status"] = msg["status"]

            scope = {
                "type": "http", "http_version": "1.1", "method": "POST",
                "path": "/sanitise", "raw_path": b"/sanitise", "query_string": b"",
                "scheme": "http",
                "headers": [
                    (b"host", b"testserver"),
                    (b"content-type", f"multipart/form-data; boundary={boundary}".encode()),
                    (b"content-length", b"10"),  # lies low
                ],
                "client": ("127.0.0.1", 1), "server": ("testserver", 80),
            }
            asyncio.run(local_app.app(scope, receive, send))
            assert result["status"] == 413  # counter caught it despite CL=10
        finally:
            cdr._MAX_FILE_BYTES = old

    def test_middleware_stops_feeding_body_after_limit(self):
        # ultrareview finding: merely flagging "tripped" while still returning every chunk
        # lets the multipart parser drain the WHOLE oversize body into its buffer. The
        # middleware must STOP forwarding the body once the limit trips. Feed the body in
        # small ASGI chunks and assert only a bounded prefix is ever pulled off the wire.
        import asyncio
        old = cdr._MAX_FILE_BYTES
        cdr._MAX_FILE_BYTES = 1024
        try:
            boundary = "B"
            head = (f"--{boundary}\r\n"
                    'Content-Disposition: form-data; name="file"; filename="x.pdf"\r\n'
                    "Content-Type: application/pdf\r\n\r\n").encode()
            payload = head + b"y" * 8192 + f"\r\n--{boundary}--\r\n".encode()
            chunks = [payload[i:i + 256] for i in range(0, len(payload), 256)]
            total = len(chunks)
            pulled = {"n": 0}
            status = {"v": None}

            async def receive():
                pulled["n"] += 1
                body = chunks.pop(0) if chunks else b""
                return {"type": "http.request", "body": body, "more_body": bool(chunks)}

            async def send(msg):
                if msg["type"] == "http.response.start":
                    status["v"] = msg["status"]

            # NO content-length header at all (the chunked-Transfer-Encoding vector the
            # reviewer flagged) — forces the counted path with no honest size to short out.
            scope = {
                "type": "http", "http_version": "1.1", "method": "POST",
                "path": "/sanitise", "raw_path": b"/sanitise", "query_string": b"",
                "scheme": "http",
                "headers": [
                    (b"host", b"testserver"),
                    (b"content-type", f"multipart/form-data; boundary={boundary}".encode()),
                ],
                "client": ("127.0.0.1", 1), "server": ("testserver", 80),
            }
            asyncio.run(local_app.app(scope, receive, send))
            assert status["v"] == 413
            # Only a bounded prefix is read — never the whole body. With a 1024-byte limit
            # over 256-byte chunks the stream is cut within the first handful of chunks.
            assert pulled["n"] <= 8 and pulled["n"] < total // 2
        finally:
            cdr._MAX_FILE_BYTES = old


class TestContentDispositionHardening:
    def test_quote_in_filename_cannot_break_out(self):
        # Finding A: a literal " must not escape the quoted filename. Test the helper
        # directly (the HTTP client percent-encodes the request filename, masking it).
        cd = local_app._content_disposition('evil".docx')
        # the ascii filename has the quote neutralised, and the * form percent-encodes it
        assert 'filename="evil_.docx"' in cd
        assert "%22" in cd  # the real quote, percent-encoded in filename*
        # no raw quote-breakout: exactly the two expected quote pairs, none injected
        assert cd.count('"') == 2

    def test_crlf_and_path_in_filename_neutralised(self):
        # CR/LF are what enable header injection; they must be gone. The residual literal
        # text "X-Injected: 1" left inside the quoted filename is inert (no CR/LF to start
        # a new header line), so we assert on the control chars and path separators only.
        cd = local_app._content_disposition("../a\r\nX-Injected: 1.docx")
        assert "\r" not in cd and "\n" not in cd
        assert "/" not in cd  # basename + replacement removes path separators
        assert cd.startswith("attachment; ")

    def test_non_latin1_filename_header_is_encodable(self):
        # ultrareview finding: a non-Latin-1 filename (CJK) left raw in the legacy
        # filename="…" value makes the ASGI server's latin-1 header encode RAISE — a 500
        # that loses the disarmed file. The ascii fallback must be latin-1-safe; the true
        # name is carried in the RFC 5987 filename* form.
        cd = local_app._content_disposition("文件.docx")
        cd.encode("latin-1")  # must not raise
        assert "filename=\"__.docx\"" in cd
        assert "filename*=UTF-8''%E6%96%87%E4%BB%B6.docx" in cd

    def test_non_latin1_filename_end_to_end_200(self):
        # End-to-end: a CJK-named upload is disarmed and returned (200), not crashed (500).
        r = client.post("/sanitise",
                        files={"file": ("文件.docx", _make_docx_with_macro(), "application/zip")})
        assert r.status_code == 200
        r.headers["content-disposition"].encode("latin-1")  # response header is sane

    def test_basename_strips_directories(self):
        cd = local_app._content_disposition("/etc/passwd")
        assert 'filename="passwd"' in cd


class TestHeaderValueHygiene:
    def test_is_clean_rejects_control_chars(self):
        # Finding C: isascii() passes CR/LF; our gate must reject them.
        assert "a\r\nX: 1".isascii() is True            # documents the wrong check
        assert local_app._is_clean_header_value("a\r\nX: 1") is False
        assert local_app._is_clean_header_value("normal text 123") is True
        assert local_app._is_clean_header_value("café") is False  # non-ascii too

    def test_safe_ext_header_caps_and_filters(self):
        assert local_app._safe_ext_header("docx") == "docx"
        assert local_app._safe_ext_header("A" * 100) == "unknown"   # length cap
        assert local_app._safe_ext_header('x"y') == "unknown"        # charset cap
        assert local_app._safe_ext_header("") == "unknown"


class TestReportHeaderGating:
    def test_large_report_omits_header(self, monkeypatch):
        big = {"status": "sanitised", "data": b"PK\x03\x04out", "original_ext": "docx",
               "sanitised_ext": "docx", "cdr_mode": "full",
               "report": {"removed": [f"word/very/long/part/name/{i}.bin" for i in range(300)]},
               "reason": None, "metric": None, "delete_source": True}
        monkeypatch.setattr(cdr, "cdr_dispatch", lambda *a, **k: big)
        # disable truncation so the JSON is genuinely large
        monkeypatch.setattr(cdr, "_truncate_removed", lambda d: d)
        r = client.post("/sanitise",
                        files={"file": ("x.docx", b"anything", "application/zip")})
        assert r.status_code == 200
        assert "x-cdr-report" not in {k.lower() for k in r.headers}
        assert r.headers["x-cdr-removals"] == "300"  # count still reported

    def test_unicode_report_is_json_escaped_and_kept(self, monkeypatch):
        # json.dumps(ensure_ascii) escapes non-ascii to \uXXXX, which is clean ASCII — so a
        # unicode entry name is safely retained in the header (escaped), not dropped.
        payload = {"status": "sanitised", "data": b"PK\x03\x04out", "original_ext": "docx",
                   "sanitised_ext": "docx", "cdr_mode": "full",
                   "report": {"removed": ["café.bin"]},
                   "reason": None, "metric": None, "delete_source": True}
        monkeypatch.setattr(cdr, "cdr_dispatch", lambda *a, **k: payload)
        r = client.post("/sanitise",
                        files={"file": ("x.docx", b"anything", "application/zip")})
        assert r.status_code == 200
        assert "caf\\u00e9.bin" in r.headers["x-cdr-report"]
        assert r.headers["x-cdr-report"].isascii()

    def test_crlf_in_entry_name_cannot_inject_header(self, monkeypatch):
        # A stripped ZIP entry name carrying raw CR/LF is the header-injection vector. Two
        # layers neutralise it: json.dumps escapes \r\n to \\r\\n (so the serialised report
        # is printable ASCII and injects nothing), and _is_clean_header_value is a backstop
        # for any non-JSON value. Assert the header, if present, contains no raw CR/LF and no
        # injected header appears.
        payload = {"status": "sanitised", "data": b"PK\x03\x04out", "original_ext": "docx",
                   "sanitised_ext": "docx", "cdr_mode": "full",
                   "report": {"removed": ["evil\r\nX-Injected: 1.bin"]},
                   "reason": None, "metric": None, "delete_source": True}
        monkeypatch.setattr(cdr, "cdr_dispatch", lambda *a, **k: payload)
        r = client.post("/sanitise",
                        files={"file": ("x.docx", b"anything", "application/zip")})
        assert r.status_code == 200
        assert "x-injected" not in {k.lower() for k in r.headers}
        rep = r.headers.get("x-cdr-report", "")
        assert "\r" not in rep and "\n" not in rep


class TestErrorPathHardening:
    def test_dispatch_raise_returns_generic_500(self, monkeypatch):
        # Finding E: the real exception must not leak to the client.
        def boom(*a, **k):
            raise RuntimeError("secret internal path /opt/cdr/x")
        monkeypatch.setattr(cdr, "cdr_dispatch", boom)
        r = client.post("/sanitise",
                        files={"file": ("x.pdf", b"data", "application/pdf")})
        assert r.status_code == 500
        assert r.json()["status"] == "error"
        assert r.json()["reason"] == "internal disarm error"
        assert "secret" not in json.dumps(r.json())

    def test_sanitised_with_none_data_is_500(self, monkeypatch):
        # Finding F: a sanitised verdict with no bytes must NOT 200 an empty body.
        payload = {"status": "sanitised", "data": None, "original_ext": "docx",
                   "sanitised_ext": "docx", "cdr_mode": "full",
                   "report": {"removed": []}, "reason": None, "metric": None,
                   "delete_source": True}
        monkeypatch.setattr(cdr, "cdr_dispatch", lambda *a, **k: payload)
        r = client.post("/sanitise",
                        files={"file": ("x.docx", b"anything", "application/zip")})
        assert r.status_code == 500
        assert r.json()["status"] == "error"


class TestRenameOutput:
    def test_no_extension(self):
        assert local_app._rename_output("README", "docx") == "README"

    def test_multiple_dots(self):
        assert local_app._rename_output("my.report.final.docm", "docx") == "my.report.final.docx"

    def test_dotfile_only_extension(self):
        assert local_app._rename_output(".docx", "docx") == ".docx"

    def test_empty_sanitised_ext_returns_stem(self):
        assert local_app._rename_output("file.bin", "") == "file"
