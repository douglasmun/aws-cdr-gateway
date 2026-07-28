# Architecture

> Extracted from CLAUDE.md. This is the authoritative architecture reference; CLAUDE.md points here.

## CDR Lambda

| File | Purpose |
|---|---|
| `src/lambda_function.py` | CDR Lambda — handles all ZIP/OOXML Office formats, PDF, and images. Exposes `cdr_dispatch(data, ext)`, the **pure I/O-free CDR decision core** (routing + disarm), used by both the cloud `handler` and the local service |
| `src/app.py` | **Local CDR variant** — FastAPI service wrapping `cdr_dispatch`; disarm files over HTTP with no AWS account. Covered by `test_cdr_local.py` |

> This repo ships a **single** CDR engine (`lambda_function.py`), covered by `test_cdr.py`. There is no second Lambda and no cross-Lambda parity requirement.
>
> **Two front-ends, one core.** The `handler` (AWS, S3/SNS-driven) and `app.py` (local, FastAPI) are both thin wrappers over the *same* pure `cdr_dispatch(data, ext)`. `cdr_dispatch` performs **no I/O** — it decides the disposition (`sanitised` / `rejected` / `unsupported-format`), returns the clean bytes + report, and reports which side-effect metric the caller should emit and whether to delete the source. Never duplicate routing/disarm logic into a wrapper: a security decision must exist in exactly one place so the two front-ends cannot drift. See pitfall #41.

## Local CDR service (`src/app.py`)

A FastAPI wrapper exposing the engine over HTTP for any local application — no S3, no SNS, no AWS account. `POST /sanitise` (multipart `file`) returns **200** + clean bytes with `X-CDR-*` headers on success, **413** when the upload exceeds `CDR_MAX_FILE_BYTES`, **422** JSON for rejected/unsupported input, **500** JSON (generic message) for an unparseable file. `GET /healthz` reports liveness and supported formats. Dependencies (`fastapi`, `uvicorn`) live in `src/requirements-local.txt` and are **deliberately excluded** from the Lambda layer (`requirements.txt`), so the deployed package stays lean. The test dependency is `httpx2` (not `httpx`): Starlette's `TestClient` now prefers `httpx2` and emits a `StarletteDeprecationWarning` on the `httpx` fallback — `httpx` is test-only (no `src/*.py` imports it), so the pin moved to `httpx2` (#27). Intended for trusted local/internal use — no built-in auth/rate-limiting.

**Container / sidecar.** The service ships as a Docker image (`Dockerfile` + `docker-compose.yml`): slim `python:3.12`, multi-stage (no compiler in the runtime image), **non-root** (uid 10001), read-only-rootfs-capable (with tmpfs `/tmp`), built-in HEALTHCHECK on `/healthz`. `app.py`'s `__main__` binds `CDR_HOST`/`CDR_PORT` from env (default `127.0.0.1:8000`; the image sets `CDR_HOST=0.0.0.0`). Published multi-arch (amd64+arm64) to `ghcr.io/douglasmun/aws-cdr-gateway` by the `.github/workflows/docker-publish.yml` workflow **on a `v*` tag** (→ `:X.Y.Z`, `:X.Y`, `:X`, `:latest`); the image is public. Full guide: `docs/deploy-container.md`. The CI `docker-build` job builds the image + curls `/healthz` + asserts uid 10001 on every PR.

**HTTP-layer hardening (the disarm core is shared and unchanged).** The front-end was adversarially audited; the fixes are pinned by `test_cdr_local.py`:
- **Body size bounded BEFORE multipart parsing** — `BodySizeLimitMiddleware` (pure ASGI, above routing) rejects an oversize `Content-Length` without reading the body and otherwise wraps `receive` with a running byte counter. The moment the count exceeds the limit it **stops forwarding the body** — it returns an empty `more_body=False` (EOF) message to the parser instead of the overrunning chunk and every subsequent chunk — so the multipart parser cannot keep buffering/spooling the rest of an oversize upload (the chunked-`Transfer-Encoding` / understated-`Content-Length` disk-fill vector; ultrareview bug_001). Merely flagging a boolean while still returning chunks lets the parser drain the whole body first — do not regress to that. An in-handler check alone is too late: FastAPI parses `UploadFile = File(...)` before the route runs (Codex finding). `_read_bounded` in the handler is a defence-in-depth backstop on the assembled bytes. Limit is read per-request from `cdr._MAX_FILE_BYTES` (env-tunable, monkeypatchable). Pinned by `TestSizeLimit` incl. `test_oversize_rejected_before_handler_runs`, `test_middleware_rejects_honest_content_length_without_reading_body`, and `test_middleware_stops_feeding_body_after_limit` (only a bounded prefix of a chunked body is ever read off the wire).
- **No header injection / no Latin-1 crash via filename** — `_content_disposition` basenames the filename and emits both a printable-ASCII `filename=` (regex `[^\x20-\x7e]|["\\/]` → `_`, so the value is **always Latin-1-encodable**) and an RFC 5987 `filename*=UTF-8''…` carrying the true Unicode name. A literal `"` can no longer break out of the quoted-string (confirmed against a raw socket — TestClient masks it by pre-encoding), AND a non-Latin-1 filename (CJK/Cyrillic/emoji) no longer makes Starlette's `header.encode('latin-1')` raise after the route returns — which had turned a *successful* disarm into a 500 that dropped the cleaned bytes (ultrareview bug_002). Stripping only quotes/controls but leaving codepoints >U+007F in the legacy slot is the bug; the ASCII slot must be ASCII-only. Pinned by `test_non_latin1_filename_header_is_encodable` and `test_non_latin1_filename_end_to_end_200`.
- **Header value hygiene** — extension headers are charset/length-capped (`_safe_ext_header`, `^[a-z0-9]{1,16}$`); the `X-CDR-Report` header is gated by `_is_clean_header_value` (printable ASCII only — `str.isascii()` wrongly passes CR/LF) on top of `json.dumps`' own control-char escaping; `X-Content-Type-Options: nosniff` is set.
- **Fail-closed invariant** — a `sanitised` verdict with `data is None` returns 500, never a 200 with an empty body labelled clean.
- **No error leakage** — the 500 path returns a generic reason; the real exception is logged server-side only.

The Lambda is triggered by **Amazon EventBridge** on S3 `ObjectCreated` (PutObject / CompleteMultipartUpload) events. EventBridge can fan out to the CDR Lambda and a Malware Scan Lambda in parallel; a Result Aggregator Lambda combines both results before routing files.

## Data Flow

```
S3 Source Bucket → EventBridge → CDR Lambda + Malware Scan Lambda → Result Aggregator
                                                                           │
                                              ┌────────────────────────────┤
                                              ▼          ▼                 ▼
                                         Clean bucket  Sanitised bucket  Quarantine bucket
```

Sanitised files land at `sanitised/<original-key>` in `SANITISED_BUCKET`. Failed files go to `QUARANTINE_BUCKET` if configured.

## Infrastructure (`src/template.yaml`)

AWS SAM template defines:
- Source, sanitised, and quarantine S3 buckets (AES256 encryption, versioning, public access blocked)
- Quarantine bucket and its IAM policies are gated behind `QuarantineEnabled` condition — the template deploys cleanly without a quarantine bucket name
- CDR Lambda (Python 3.12, 1024 MB, 300 s timeout, `/tmp` ephemeral storage 1024 MB)
- `ReservedConcurrentExecutions: 20` — prevents OOM bursts; tune per throughput SLA
- `CdrDlq` SQS dead-letter queue (14-day retention) — catches events after EventBridge retry exhaustion
- `CdrResultTopic` SNS for CDR result metadata published to downstream consumers
- `CdrAlarmTopic` SNS **separate** from `CdrResultTopic` — all CloudWatch alarms route here so alarm noise doesn't pollute result consumers
- CloudWatch alarms: Lambda errors, p99 duration (threshold 250 s, fires before 300 s timeout), throttles, DLQ depth, passthrough files
- `CDR_MAX_FILE_BYTES`, `CDR_MAX_ENTRY_BYTES`, `CDR_MAX_TOTAL_BYTES`, `CDR_MAX_ZIP_ENTRIES`, `CDR_MAX_IMAGE_PIXELS`, `CDR_MAX_TOTAL_IMAGE_PIXELS` and `CDR_MAX_IMAGE_FRAMES` as SAM Parameters — every resource cap is tunable without code changes
- `ResourcePrefix` (default `cdr`) prefixes the Lambda, SNS topics, DLQ and alarm names. These are account-and-region-scoped, so two stacks in one region collide on them unless it differs; the default reproduces the historical names exactly, so existing stacks are unaffected. `docs/benchmark.py --function` must match (`<prefix>-lambda`) or CloudWatch returns no data.
  - **The default prefix may already be taken.** A `cdr-*` deployment can exist in a target account managed by another tool entirely (Terraform, CDK) and belonging to another repo — actively serving traffic. `sam deploy` then fails at `AWS::EarlyValidation::ResourceExistenceCheck`; pass a distinct `ResourcePrefix` (staging used `cdr-staging`) rather than removing whatever holds the name. **Absence from CloudFormation does not mean unmanaged**, so confirm ownership before touching a `cdr-*` resource: check `aws lambda list-functions` against every IaC state you can reach, and read the function's recent CloudWatch logs for live traffic. If it belongs to another tool, removal is that tool's job (e.g. `terraform destroy` from the owning repo) — deleting via the console or CLI desyncs its state and breaks the service.
- EventBridge pattern restricted to `reason: [PutObject, CompleteMultipartUpload]` — excludes CopyObject events that could form a processing loop

## Defence-in-Depth Layers

1. **Magic byte / ZIP structure validation** — `50 4B 03 04` ZIP header, safe compression methods, no duplicate entries, and `[Content_Types].xml` presence (see "ZIP integrity validation" below); a structural anomaly is a hard reject, not a CDR-proceeds path
2. **CDR** — ZIP-level surgery (no Office library re-serialisation)
3. **Antivirus scan** — parallel Lambda (ClamAV / GuardDuty / external API)

## CDR Approach by Format

**Office (all ZIP/OOXML formats):** `docx`, `docm→docx`, `dotx`, `dotm→dotx`, `xlsx`, `xlsm→xlsx`, `xltx`, `xltm→xltx`, `xlam→xlsx`, `xlsb→xlsx`, `pptx`, `pptm→pptx`, `potx`, `potm→potx`, `ppsx`, `ppsm→ppsx`, `ppam→pptx`. Macro-enabled extensions are renamed to their clean equivalents after CDR. Legacy OLE binary formats (`doc`/`xls`/`ppt`) are quarantined and deleted from source — no CDR attempted.

CDR iterates the ZIP archive directly, dropping VBA binaries, ActiveX entries, `customXml/` (the `customXml`/`customXmlProps` **relationship types** are also in `STRIP_REL_TYPES` so no dangling rel survives — see pitfall #39), `externalLinks/`, `word/externalLinks/`, `queryTables/`, `connections.xml`, `ppt/tags/`, `attachedToolbars/`, embedded OLE/package objects (`word|xl|ppt/embeddings/`), and Office Web Add-in parts (`word|xl|ppt/webextensions/`). Scrubs `.rels` files to remove dangerous relationship types (incl. `aFChunk`, `package`, `connections`) and **rewrites external hyperlink rel Targets to inert** (keeping the rel so `r:id` references don't dangle — defeats UNC NTLM theft / phishing). Sanitises `[Content_Types].xml` to replace macro-enabled OPC part content types (ending in `.main+xml`) and remove VBA Default entries. Scrubs XML for dangerous field codes (`MACROBUTTON`, `DDE`, `DDEAUTO`, `AUTOOPEN`, `AUTOEXIT`, `AUTOCLOSE`, `AUTONEW`, `EXEC`, `AUTO`, `INCLUDE`, `INCLUDETEXT`, `INCLUDEPICTURE`, `LINK`, `WEBSERVICE`, `RTD`, `CALL`, `REGISTER`). The auto-exec and keyword+argument field-code passes run **only inside field carriers** — `<w:instrText>…</w:instrText>` element content and `<w:fldSimple w:instr="…">` attributes, via `_scrub_field_code_carriers`/`_scrub_field_string` — never over the raw XML part (scoping prevents false-positive corruption of legitimate `styles.xml`; see pitfall #40). Also scrubs action attributes (`onClick`, `onAction`), the Excel-formula DDE/WEBSERVICE/DDE-pipe forms (`_strip_xml_macros` n3, XML-boundary-safe), entity-encoded field codes, and **neutralises `<w:altChunk>` elements** (HTML/MHTML import that bypasses the macro scrub). Never re-serialises through an Office library — preserves all content CDR doesn't explicitly touch.

**Unknown extensions FAIL CLOSED:** any extension that is not a handled Office/PDF/image type is quarantined as `unsupported-format` with the source deleted — never uploaded to `SANITISED_BUCKET`. A CDR gate must never label content it did not disarm as sanitised.

`xlsb` files that contain binary sheet entries (`xl/worksheets/sheet*.bin`) are **converted to clean xlsx** via `cdr_xlsb()`: `pyxlsb` reads cell values from BIFF12 records; `openpyxl` writes a fresh xlsx containing only those plain values. All formulas, DDE references, VBA, external links, and metadata are stripped by the format conversion — the BIFF12 binary records never pass through. The output is renamed `xlsb→xlsx`. xlsb files without sheet binaries (VBA-only) continue through the normal ZIP CDR path.

**Known limitations of xlsb conversion:** cell formatting (fonts, colours, borders, column widths) is lost; charts, images, and named ranges are dropped; formula cells produce their last cached value only (not live formulas); string cells depend on `sharedStrings.bin` being present (missing → `None`, not an error); password-protected xlsb files cannot be opened by `pyxlsb` and are routed to the error quarantine path.

**ZIP integrity validation** runs before Office CDR. All of the following result in a **hard reject** — file quarantined, source deleted, no CDR attempted: magic byte failure, non-standard compression methods, duplicate entries, local/central directory method mismatch, or **missing `[Content_Types].xml`** (a valid ZIP that is not an OOXML package — e.g. an arbitrary archive renamed `.docx` — must not be CDR'd and labelled sanitised). Hard rejects are emitted as CloudWatch metric `CDR/Validation/ZipAnomalies`, which `CdrZipAnomalyAlarm` watches.

**PDF:** Uses `pikepdf` to remove `/OpenAction`, `/AA`, `/JavaScript`, `/JS`, `/Names./JavaScript`, `/EmbeddedFiles`. Per-page annotations: deletes **every** `/A` and `/AA` unconditionally (denylist-free — catches `/GoToE`, `/Rendition`, `/SetOCGState`, etc. that an action allowlist missed), scrubs `/FS`+`/EF` on `/FileAttachment` annotations, and neutralises multimedia annotation subtypes (`/RichMedia`, `/Screen`, `/3D`, `/Movie`, `/Sound`) by dropping their content and renaming the subtype. Walks the `/Outlines` (bookmark) tree deleting `/A`/`/AA` (cycle-guarded). Recursively sweeps all AcroForm `/Fields` and widget dictionaries for `/A`, `/AA`, `/JS`, `/JavaScript` and the AcroForm root `/AA`/`/XFA`/`/CO`. Preserves form field visual structure. **Neutralises decoder-RCE image filters** (`/JBIG2Decode`, `/JPXDecode`) on any stream — `_neutralise_pdf_risky_image_filters` rewrites the stream to a 1×1 inert image and drops the filter, so a crafted JBIG2/JPX payload never reaches a viewer's decoder (CVE-2009-0658, CVE-2021-30860 family) while the PDF stays valid (pitfall #42). Because `cdr_pdf` works on pikepdf's **parsed object model** (not a string scan), JS hidden in `/ObjStm` object streams and hex-obfuscated names (`/J#61vaScript`) are caught automatically — pinned by `TestStevensGapRegressions`.

**Images:** Re-encodes through Pillow to create a pixel-only copy, stripping EXIF, ICC, XMP, and GIF comment extension blocks. GIFs are re-encoded as GIF (format and Content-Type preserved; comment blocks explicitly suppressed with `comment=b""`). Multi-frame TIFFs are re-encoded frame-by-frame using `ImageSequence.Iterator` — all frames are preserved, and metadata is stripped from every frame in the process. Single-frame images go through the standard `img.convert().save()` path.

## Key Helpers — Production Reliability

These patterns are non-negotiable. **Never remove or bypass them.**

**`_delete_source_safe(bucket, key)`** — wraps `s3.delete_object` in try/except. Logs a warning on failure but does NOT re-raise. The CDR output is already uploaded; a delete failure must not convert a successful CDR into an error that EventBridge retries.

**`_publish_result_safe(source_bucket, key, status, report)`** — wraps SNS publish in try/except. Logs a warning on failure but does NOT re-raise. Passes through `_truncate_removed()` to cap `removed` lists at 100 entries (both flat and nested) before SNS publish to stay within the 256 KB message limit.

**`_truncate_removed(d)`** — caps `d["removed"]` and `d["report"]["removed"]` at 100 entries at both nesting levels. Handles both flat reports (no nested `"report"` key) and the standard nested shape.

**`_read_zip_entry_safe(src, item)`** — reads ZIP entries in 64 KB chunks with a running byte counter. Raises `ValueError` if the running total exceeds `_MAX_ENTRY_BYTES`. **Does NOT trust `item.file_size`** — the central directory `file_size` field is attacker-controlled and can be falsified to 1 byte while actual decompressed content is gigabytes.

**`_classify_download_error(bucket, key, exc)`** — distinguishes `NoSuchKey` (source already deleted — publish `source-missing` status, no quarantine) from other download failures. `NoSuchKey` is an expected EventBridge retry race condition.

## Environment Variables

| Variable | Required | Purpose |
|---|---|---|
| `SANITISED_BUCKET` | Yes | Destination for clean files |
| `QUARANTINE_BUCKET` | No | Destination for rejected/errored files |
| `RESULT_TOPIC_ARN` | No | SNS topic for CDR result metadata |
| `CDR_MAX_FILE_BYTES` | No | Pre-download size limit in bytes (default 104857600 = 100 MB) |
| `CDR_MAX_ENTRY_BYTES` | No | Per-ZIP-entry decompression limit in bytes (default 209715200 = 200 MB) |
| `CDR_MAX_TOTAL_BYTES` | No | Aggregate decompression budget across all entries of one package (default 1073741824 = 1 GiB) |
| `CDR_MAX_ZIP_ENTRIES` | No | Maximum ZIP entry count (default 20000) |
| `CDR_MAX_TOTAL_IMAGE_PIXELS` | No | Aggregate pixel budget across all frames of one animation (default 80000000 = 80 MP) |
| `CDR_MAX_IMAGE_FRAMES` | No | Maximum animation frame count (default 2000) |

## Structured Logging

All log lines use `key=value` format for CloudWatch Logs Insights queries:

```python
logger.info("CDR complete: bucket=%s key=%s ext=%s removals=%d mode=%s dest=%s", ...)
logger.warning("delete_object failed (sanitised copy is safe): bucket=%s key=%s error=%s", ...)
```

Never log file content or raw byte arrays at INFO or higher.
