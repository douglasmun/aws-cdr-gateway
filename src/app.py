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

from fastapi import FastAPI, File, UploadFile
from fastapi.responses import JSONResponse, Response
from urllib.parse import quote

import lambda_function as cdr

logger = logging.getLogger("cdr.local")

app = FastAPI(
    title="Local CDR Gateway",
    version="1.2.0",
    description="Content Disarmament & Reconstruction — local variant of the AWS pipeline.",
)


class BodySizeLimitMiddleware:
    """Pure-ASGI middleware that bounds the request body BEFORE any parser sees it.

    FastAPI resolves ``UploadFile = File(...)`` by running Starlette's multipart parser
    over the body *before* the route function executes — so an in-handler size check cannot
    stop an oversize upload from first being consumed/spooled. This middleware sits above
    routing: it rejects an oversize ``Content-Length`` immediately (no body read at all),
    and otherwise wraps the ASGI ``receive`` callable with a running byte counter. The
    moment the counted bytes exceed the limit it stops forwarding the body — it returns an
    EOF (``more_body=False``) message to the parser instead of the overrunning chunk and
    every subsequent chunk — so the parser cannot keep buffering the rest of the upload. A
    413 is then emitted (``guarded_send``) in place of whatever the truncated parse would
    have produced. The parser still sees at most the bytes up to the limit plus the head of
    the tripping chunk, never the full oversize body. The limit is read per-request from
    ``cdr._MAX_FILE_BYTES`` so it tracks the same env-tunable bound as the Lambda and so
    tests can monkeypatch it.
    """

    def __init__(self, app, limit_getter):
        self.app = app
        self._limit_getter = limit_getter

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        limit = self._limit_getter()

        # 1) Fast path: an honest, oversize Content-Length is rejected without reading body.
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    if int(value) > limit:
                        await _send_413(send)
                        return
                except ValueError:
                    pass  # malformed — fall through to the authoritative counted read
                break

        # 2) Authoritative path: count actual streamed bytes; Content-Length is advisory.
        # Once the running total exceeds the limit we STOP feeding the body downstream — we
        # hand the multipart parser a truncated, EOF-terminated stream so it cannot keep
        # buffering the rest of an oversize upload into memory/spool. (Merely flagging a
        # boolean while still returning every chunk would let the parser drain the whole
        # body before the 413 — the bug this guards against.)
        counter = {"total": 0, "tripped": False}

        async def counting_receive():
            if counter["tripped"]:
                # Already over the limit: present EOF so the parser unwinds immediately
                # instead of pulling (and buffering) more body bytes.
                return {"type": "http.request", "body": b"", "more_body": False}
            message = await receive()
            if message["type"] == "http.request":
                counter["total"] += len(message.get("body", b""))
                if counter["total"] > limit:
                    counter["tripped"] = True
                    # Drop the overrunning chunk's body and signal EOF; the 413 is emitted
                    # by guarded_send. Do not pass these excess bytes to the parser.
                    return {"type": "http.request", "body": b"", "more_body": False}
            return message

        sent_413 = {"done": False}

        async def guarded_send(message):
            # If the limit tripped, the downstream app may still try to respond; suppress
            # its output and emit a single 413 instead.
            if counter["tripped"]:
                if not sent_413["done"]:
                    sent_413["done"] = True
                    await _send_413(send)
                return
            await send(message)

        try:
            await self.app(scope, counting_receive, guarded_send)
        finally:
            # If the body overran but the downstream app never produced a response (e.g. it
            # awaited more body and got cut off), make sure the client still gets a 413.
            if counter["tripped"] and not sent_413["done"]:
                sent_413["done"] = True
                await _send_413(send)


async def _send_413(send) -> None:
    body = b'{"status":"rejected","reason":"file too large"}'
    await send({
        "type": "http.response.start",
        "status": 413,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ],
    })
    await send({"type": "http.response.body", "body": body})


app.add_middleware(BodySizeLimitMiddleware, limit_getter=lambda: cdr._MAX_FILE_BYTES)

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

    The filename is attacker-controlled (multipart part header). Two hazards:
      * a literal ``"`` would break out of the quoted-string form (``filename="foo".docx"``);
      * a non-Latin-1 character (e.g. CJK) in the legacy ``filename="…"`` value makes the
        ASGI server's ``.encode('latin-1')`` of the header RAISE — turning a successful
        disarm into a 500 that loses the cleaned file.
    So the legacy ``filename=`` value is reduced to printable ASCII only (everything outside
    0x20–0x7E, plus ``"``/``\\``/``/``, replaced with ``_``); the true Unicode name is carried
    losslessly in the RFC 5987 ``filename*=UTF-8''…`` percent-encoded form, which every
    modern client prefers. Neither form can inject header structure or non-Latin-1 bytes."""
    base = os.path.basename(filename or "") or "file"
    # ASCII-only fallback: replace any non-printable-ASCII byte and the structural chars.
    ascii_name = re.sub(r'[^\x20-\x7e]|["\\/]', "_", base) or "file"
    star = quote(base, safe="")  # percent-encode everything unsafe, incl. quotes/CR/LF/UTF-8
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
async def sanitise(file: UploadFile = File(...)) -> Response:
    """Disarm an uploaded file.

    Success (status == "sanitised"): 200, body = clean file bytes, headers:
        X-CDR-Status, X-CDR-Original-Ext, X-CDR-Sanitised-Ext, X-CDR-Mode,
        X-CDR-Removals, X-CDR-Report (JSON; omitted if too large or non-printable).
    Oversize upload: 413 JSON {status: "rejected", reason: "file too large"} — enforced by
        BodySizeLimitMiddleware BEFORE the multipart parser runs (see that class). The
        bounded read below is a defence-in-depth backstop on the assembled bytes.
    Rejected / unsupported: 422 JSON {status, reason, original_ext, sanitised_ext}.
    Internal disarm error (e.g. corrupt file): 500 JSON {status: "error"}.
    """
    limit = cdr._MAX_FILE_BYTES

    # The middleware has already aborted any oversize body before this point. This bounded
    # read is a redundant safety net (it never trusts a declared size) so the assembled
    # `data` object can never exceed the limit even if the middleware were bypassed.
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
    # Bind host/port from env so the same entrypoint works locally (default loopback —
    # never exposed by accident) and in a container (set CDR_HOST=0.0.0.0). The service has
    # no built-in auth; only bind 0.0.0.0 behind your own network controls / reverse proxy.
    host = os.environ.get("CDR_HOST", "127.0.0.1")
    port = int(os.environ.get("CDR_PORT", "8000"))
    uvicorn.run(app, host=host, port=port)
