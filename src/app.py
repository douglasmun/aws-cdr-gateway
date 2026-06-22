"""
Local CDR service — a FastAPI wrapper around the *same* CDR decision core the AWS
Lambda uses (``cdr_dispatch`` in ``lambda_function.py``). No S3, no SNS, no AWS account.

Any local application can disarm a file by POSTing it to ``/sanitise`` and reading the
clean bytes back from the response body, with the CDR report in response headers. The
security decisions (fail-closed unknown extensions, RTF/legacy rejection, ZIP structural
validation, format-specific disarm) are identical to the cloud pipeline because both call
``cdr_dispatch`` — there is no second implementation to drift.

Run:
    cd src
    pip install -r requirements.txt -r requirements-local.txt
    uvicorn app:app --host 127.0.0.1 --port 8000

    # or: python app.py

Use:
    curl -sS -o clean.docx -D - \
         -F file=@dirty.docm \
         http://127.0.0.1:8000/sanitise

    # -> 200 with clean bytes; X-CDR-* headers carry status/report
    # -> 413 JSON when the upload exceeds the size limit
    # -> 422 JSON {status, reason} for rejected / unsupported files
    # -> 500 JSON {status: "error"} for an unparseable file

Note this is a single-process disarm service intended for trusted local/internal use
(a sidecar, a desktop integration, a batch tool). It is not hardened as a public,
internet-facing upload endpoint — put it behind your own auth/ratelimit if you expose it.

Hardening applied to the HTTP layer (the disarm core is shared and unchanged):
  * Body size is bounded BEFORE buffering the whole upload — Content-Length is rejected
    early, then the body is read in chunks with a running counter (Content-Length is
    advisory, mirroring _read_zip_entry_safe's distrust of declared sizes).
  * All attacker-controlled header values are sanitised: the Content-Disposition filename
    is RFC 6266 / RFC 5987 encoded (no quote-breakout), the extension headers are charset-
    and length-capped, and the X-CDR-Report header is dropped if it contains any non-
    printable-ASCII byte (defends against control-char header injection regardless of the
    ASGI server's own checks).
  * Internal disarm errors return a generic message to the client; the real exception is
    logged server-side only.
"""

import json
import logging
import os
import re

# lambda_function constructs boto3 clients and requires SANITISED_BUCKET at import time
# (it is the cloud entry point). The local service never touches S3, but the import still
# runs that module-level code — so provide inert defaults BEFORE importing it. These are
# never used by cdr_dispatch (it performs no I/O); they only satisfy the import.
os.environ.setdefault("SANITISED_BUCKET", "local-cdr-unused")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "local")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "local")
os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")

from fastapi import FastAPI, File, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from urllib.parse import quote

import lambda_function as cdr

logger = logging.getLogger("cdr.local")

app = FastAPI(
    title="Local CDR Gateway",
    version="1.1.0",
    description="Content Disarmament & Reconstruction — local variant of the AWS pipeline.",
)

_CONTENT_TYPE_FALLBACK = "application/octet-stream"

# Read the body in 1 MB chunks so we can stop early on an oversize upload instead of
# materialising a multi-GB body before the size check.
_READ_CHUNK = 1024 * 1024

# Header hygiene: an extension that goes into a response header must be a short, plain
# token. Anything else is reported as "unknown" in the header (the routing decision still
# used the real extension inside cdr_dispatch).
_SAFE_EXT_RE = re.compile(r"^[a-z0-9]{1,16}$")


def _ext_from_name(filename: str) -> str:
    """Derive the lowercase extension. Byte-for-byte equivalent to the Lambda handler's
    ``key.rsplit('.', 1)[-1].lower() if '.' in key else ''`` — kept in sync deliberately
    so the local and cloud routing never diverge (CLAUDE.md pitfall #41)."""
    return filename.rsplit(".", 1)[-1].lower() if filename and "." in filename else ""


def _safe_ext_header(ext: str) -> str:
    """Charset/length-capped extension for a response header value."""
    return ext if _SAFE_EXT_RE.match(ext) else "unknown"


def _is_clean_header_value(value: str) -> bool:
    """True iff ``value`` is entirely printable ASCII (0x20–0x7E). Rejects CR, LF, NUL and
    every other control char — unlike ``str.isascii()``, which passes them. Used to gate
    the attacker-influenced X-CDR-Report header so header injection cannot ride a stripped
    ZIP entry name into the response, independent of the ASGI server's own checks."""
    return all("\x20" <= c <= "\x7e" for c in value)


def _content_disposition(filename: str) -> str:
    """Build a safe ``Content-Disposition: attachment`` value.

    The filename is attacker-controlled (multipart part header). A literal ``"`` would
    otherwise break out of the quoted-string form (``filename="foo".docx"``). We emit BOTH
    a sanitised ASCII ``filename=`` (quotes/backslashes/controls/path-separators removed)
    for legacy clients AND an RFC 5987 ``filename*=UTF-8''…`` percent-encoded form for the
    true name — neither can inject header structure."""
    base = os.path.basename(filename or "") or "file"
    ascii_name = re.sub(r'[\\"\x00-\x1f\x7f/]', "_", base)
    star = quote(base, safe="")  # percent-encode everything unsafe, incl. quotes/CR/LF
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{star}"


async def _read_bounded(file: UploadFile, limit: int) -> bytes | None:
    """Read the upload in chunks up to ``limit`` bytes. Returns the bytes, or ``None`` if
    the running total exceeds ``limit`` (caller returns 413). Does not trust any declared
    size — counts actual bytes read."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(_READ_CHUNK)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


@app.get("/healthz")
def healthz() -> dict:
    """Liveness probe. Reports the formats this build will attempt to disarm."""
    return {
        "status": "ok",
        "office_exts": sorted(cdr.OFFICE_EXTS),
        "image_exts": sorted(cdr.IMAGE_EXTS),
        "pdf": True,
        "rejected_by_design": sorted(cdr.FAIL_CLOSED_EXTS | cdr.LEGACY_EXTS),
        "max_file_bytes": cdr._MAX_FILE_BYTES,
    }


@app.post("/sanitise")
async def sanitise(request: Request, file: UploadFile = File(...)) -> Response:
    """Disarm an uploaded file.

    Success (status == "sanitised"): 200, body = clean file bytes, headers:
        X-CDR-Status, X-CDR-Original-Ext, X-CDR-Sanitised-Ext, X-CDR-Mode,
        X-CDR-Removals, X-CDR-Report (JSON; omitted if too large or non-printable).
    Oversize upload: 413 JSON {status: "rejected", reason: "file too large"}.
    Rejected / unsupported: 422 JSON {status, reason, original_ext, sanitised_ext}.
    Internal disarm error (e.g. corrupt file): 500 JSON {status: "error"}.
    """
    limit = cdr._MAX_FILE_BYTES

    # ── Early Content-Length reject (advisory) ────────────────────────────────
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > limit:
                return JSONResponse(status_code=413,
                                    content={"status": "rejected", "reason": "file too large"})
        except ValueError:
            pass  # malformed header — fall through to the authoritative counted read

    # ── Bounded read (authoritative; does not trust Content-Length) ───────────
    data = await _read_bounded(file, limit)
    if data is None:
        return JSONResponse(status_code=413,
                            content={"status": "rejected", "reason": "file too large"})

    ext = _ext_from_name(os.path.basename(file.filename or ""))

    try:
        decision = cdr.cdr_dispatch(data, ext)
    except Exception as exc:  # corrupt/unparseable input — mirrors the Lambda error path
        logger.exception("CDR disarm error: ext=%s error=%s", ext, exc)
        return JSONResponse(
            status_code=500,
            content={"status": "error", "reason": "internal disarm error",
                     "original_ext": _safe_ext_header(ext)},
        )

    if decision["status"] != "sanitised":
        return JSONResponse(
            status_code=422,
            content={
                "status":        decision["status"],
                "reason":        decision["reason"],
                "original_ext":  decision["original_ext"],
                "sanitised_ext": decision["sanitised_ext"],
            },
        )

    # Fail-closed invariant: a "sanitised" verdict MUST carry bytes. Guard against a future
    # core regression returning sanitised+None, which would ship an empty body labelled
    # clean (a fail-open). Never return 200 without disarmed content.
    if decision["data"] is None:
        logger.error("cdr_dispatch returned sanitised with no data: ext=%s", ext)
        return JSONResponse(status_code=500,
                            content={"status": "error", "reason": "internal disarm error"})

    report        = decision["report"] or {}
    sanitised_ext = decision["sanitised_ext"]
    out_ct        = cdr._content_type_for_ext(sanitised_ext, _CONTENT_TYPE_FALLBACK)
    out_name      = _rename_output(os.path.basename(file.filename or "") or "file",
                                   sanitised_ext)

    headers = {
        "X-CDR-Status":        "sanitised",
        "X-CDR-Original-Ext":  _safe_ext_header(decision["original_ext"]),
        "X-CDR-Sanitised-Ext": _safe_ext_header(sanitised_ext),
        "X-CDR-Mode":          decision["cdr_mode"] or "full",
        "X-CDR-Removals":      str(len(report.get("removed", []))),
        "Content-Disposition": _content_disposition(out_name),
        "X-Content-Type-Options": "nosniff",
    }

    # The report carries attacker-influenced strings (stripped ZIP entry names, rel types).
    # Truncate, then attach only if it is bounded AND entirely printable ASCII — never let a
    # control char reach a response header. Clients needing the full report can parse the
    # file plus the X-CDR-Removals count.
    safe_report = cdr._truncate_removed({"report": dict(report)})["report"]
    report_json = json.dumps(safe_report, separators=(",", ":"))
    if len(report_json) <= 6000 and _is_clean_header_value(report_json):
        headers["X-CDR-Report"] = report_json

    return Response(content=decision["data"], media_type=out_ct, headers=headers)


def _rename_output(filename: str, sanitised_ext: str) -> str:
    """Swap the original extension for the (possibly remapped) sanitised one, e.g.
    ``report.docm`` -> ``report.docx``. Files with no extension are returned unchanged."""
    if "." not in filename:
        return filename
    stem = filename.rsplit(".", 1)[0]
    return f"{stem}.{sanitised_ext}" if sanitised_ext else stem


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
