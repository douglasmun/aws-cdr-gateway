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
    pip install -r requirements.txt        # includes fastapi + uvicorn
    uvicorn app:app --host 127.0.0.1 --port 8000

    # or: python app.py

Use:
    curl -sS -o clean.docx -D - \
         -F file=@dirty.docm \
         http://127.0.0.1:8000/sanitise

    # -> 200 with clean bytes; X-CDR-* headers carry status/report
    # -> 422 JSON {status, reason} for rejected / unsupported files

Note this is a single-process disarm service intended for trusted local/internal use
(a sidecar, a desktop integration, a batch tool). It is not hardened as a public,
internet-facing upload endpoint — put it behind your own auth/ratelimit if you expose it.
"""

import io
import json
import os

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

import lambda_function as cdr

app = FastAPI(
    title="Local CDR Gateway",
    version="1.0.0",
    description="Content Disarmament & Reconstruction — local variant of the AWS pipeline.",
)

# Maps the disarm content type for the (possibly remapped) output extension; reuses the
# Lambda's own table so a docm->docx output gets the correct clean content type.
_CONTENT_TYPE_FALLBACK = "application/octet-stream"


def _ext_from_name(filename: str) -> str:
    return filename.rsplit(".", 1)[-1].lower() if filename and "." in filename else ""


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
        X-CDR-Removals, X-CDR-Report (JSON, truncated to fit a header).
    Rejected / unsupported: 422, JSON {status, reason, original_ext, sanitised_ext}.
    Internal disarm error (e.g. corrupt PDF): 500, JSON {status: "error", reason}.
    """
    data = await file.read()
    ext  = _ext_from_name(file.filename or "")

    try:
        decision = cdr.cdr_dispatch(data, ext)
    except Exception as exc:  # corrupt/unparseable input — mirrors the Lambda error path
        return JSONResponse(
            status_code=500,
            content={"status": "error", "reason": str(exc), "original_ext": ext},
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

    report        = decision["report"] or {}
    sanitised_ext = decision["sanitised_ext"]
    out_ct        = cdr._content_type_for_ext(sanitised_ext, _CONTENT_TYPE_FALLBACK)
    out_name      = _rename_output(file.filename or "file", sanitised_ext)

    # Report can be large; truncate removals for the header. Full report is still the
    # source of truth server-side — the header is a convenience for thin clients.
    safe_report = cdr._truncate_removed({"report": dict(report)})["report"]
    report_json = json.dumps(safe_report, separators=(",", ":"))

    headers = {
        "X-CDR-Status":        "sanitised",
        "X-CDR-Original-Ext":  decision["original_ext"],
        "X-CDR-Sanitised-Ext": sanitised_ext,
        "X-CDR-Mode":          decision["cdr_mode"] or "full",
        "X-CDR-Removals":      str(len(report.get("removed", []))),
        "Content-Disposition": f'attachment; filename="{out_name}"',
    }
    # Headers must be latin-1 encodable and bounded; only attach the report header when it
    # fits comfortably (HTTP header practical limits ~8 KB). Clients needing the full
    # report can parse the file plus the X-CDR-Removals count.
    if len(report_json) <= 6000 and report_json.isascii():
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
