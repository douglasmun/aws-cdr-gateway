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
)


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
