# CDR + AV Dual-Layer File Sanitisation Pipeline

## Overview

A serverless, event-driven **Content Disarmament and Reconstruction (CDR)** pipeline on AWS that automatically sanitises uploaded files the moment they land in S3. The pipeline runs CDR and antivirus scanning in parallel, then routes files to clean, sanitised, or quarantine destinations based on the combined result.

Supported formats: all 17 ZIP/OOXML Office extensions, PDF, and images. Legacy OLE binary Office formats (`doc`/`xls`/`ppt`) are quarantined without CDR.

---

## What Problem This Solves

Files uploaded by external users — spreadsheets, PDFs, images — are a common malware delivery vector. Standard antivirus alone only catches *known* threats. CDR takes a different approach: it structurally rebuilds the file from scratch, stripping anything executable or active, regardless of whether the threat is known. The two approaches are complementary:

| Approach | Catches |
|---|---|
| CDR | Unknown threats, zero-days, active content |
| Antivirus | Known malware signatures |

Running both in parallel gives defence-in-depth without one depending on the other.

---

## Architecture

```
Browser / Client App
        │
        │  requests presigned POST URL
        ▼
Backend / API  ──────────────────────────────────────────────────────┐
        │                                                             │
        │  POST direct to S3 with signed policy                      │
        ▼                                                  Presigned POST Policy
S3 Source Bucket  (incoming/ prefix)                       • Content-Type restriction
        │                                                  • key prefix = incoming/
        │  ObjectCreated event notification                • max size = 100 MB
        ▼
Amazon EventBridge
        │
        ├──────────────────────┬──────────────────────────┐
        ▼                      ▼                          │
CDR Lambda              Malware Scan Lambda               │
(parallel)              (parallel)                        │
        │                      │                          │
        └──────────┬───────────┘                          │
                   ▼                                      │
        Result Aggregator Lambda                          │
                   │                                      │
        ┌──────────┼──────────────┐                       │
        ▼          ▼              ▼                       │
  Clean bucket  Sanitised     Quarantine  ◄───────────────┘
                 bucket        bucket      (rejected uploads land here too)
                   │
        S3 Object Tags + CloudWatch + SNS (CdrResultTopic)
```

### Trigger pattern

**Amazon EventBridge fan-out** — the source bucket sends `ObjectCreated` events to EventBridge, which asynchronously invokes both the CDR Lambda and the Malware Scan Lambda in parallel. A Result Aggregator Lambda waits for both results before routing.

Chosen over direct S3 → Lambda because it allows multiple consumers without changing bucket config, and cleanly separates concerns.

---

## Defence-in-Depth Layers

| Layer | Mechanism | Strength |
|---|---|---|
| 1 | Presigned POST policy — `Content-Type` header match | Weak — client-declared only |
| 2 | Magic byte validation — `50 4B 03 04` + format-specific presence check | Strong — byte-level truth |
| 3 | CDR — structural disarmament | Neutralises — even unknown threats |
| 4 | Antivirus scan — signature matching | Catches — known malware |

---

## CDR Lambda Detail

### Pre-download size guard

`s3.head_object` is called before downloading. Files larger than `CDR_MAX_FILE_BYTES` (default 100 MB) are quarantined via `CopyObject` (preserving the full original) and deleted from source without downloading. This prevents OOM Lambda crashes on large uploads.

### Office (ZIP/OOXML) CDR

Operates directly on the ZIP archive without re-encoding through an Office library. Cell values, styles, charts, images, and layout are preserved. Everything CDR doesn't explicitly touch passes through unchanged.

**Removed entirely:**
- `xl/vbaProject.bin`, `word/vbaProject.bin`, `ppt/vbaProject.bin` — VBA macros
- `xl/externalLinks/`, `word/externalLinks/` — external workbook/document references
- `xl/queryTables/` — DDE and web queries
- `xl/connections.xml` — external data source connections
- `xl/activeX/`, `word/activeX/`, `ppt/activeX/` — ActiveX control binaries
- `customXml/` — custom XML data (can carry active content)
- `attachedToolbars/` — attached toolbars
- `ppt/tags/` — PowerPoint tag data

**Scrubbed from XML:**
- `.rels` files — relationship entries for OLE objects, external links, ActiveX, macros, attached templates, sub-documents, frames
- `[Content_Types].xml` — macro-enabled OPC part content types replaced with clean equivalents; VBA Default entries removed
- Sheet/document XML — dangerous field codes neutralised in-place (`MACROBUTTON`, `DDE`, `DDEAUTO`, `AUTO`, `EXEC`, `INCLUDE`, `INCLUDETEXT`, `INCLUDEPICTURE`, `LINK`, `WEBSERVICE`, `RTD`, `CALL`, `REGISTER`; auto-execute variants `AUTOOPEN`, `AUTOEXIT`, `AUTOCLOSE`, `AUTONEW`); `onClick`/`onAction` attributes removed

**Extension remapping:** All 12 macro-enabled extensions are renamed to their clean equivalents (e.g. `xlsm→xlsx`, `docm→docx`, `pptm→pptx`, `xlsb→xlsx`) so downstream consumers cannot mistake the output for macro-capable files.

**xlsb (format conversion):** xlsb files without sheet binaries (VBA-only) are sanitised normally through the ZIP CDR path. xlsb files containing binary sheet data (`xl/worksheets/sheet*.bin`) are converted to clean xlsx via `cdr_xlsb()`:

1. `pyxlsb` opens the xlsb and iterates each sheet row-by-row, reading cached cell values (numbers, booleans, strings)
2. `openpyxl` writes a fresh xlsx workbook containing only those plain values
3. Output is renamed `xlsb→xlsx` and written to the sanitised bucket

This approach ensures no BIFF12 binary records pass through to the output. Formula text is never exposed by `pyxlsb` — only the cached result value is returned — so formula-based DDE payloads (e.g. `=cmd|' /c calc'!A1`) have no representation in the output workbook.

**Known limitations of xlsb conversion:**
- **Cell formatting is lost.** Number formats, fonts, colours, borders, and column widths are not carried across. The output is plain values only.
- **Charts, images, and named ranges are dropped.** Only worksheet cell data is extracted; drawing objects, embedded images, defined names, and print settings are not reproduced.
- **String cells require a shared string table.** If `xl/sharedStrings.bin` is missing or corrupt in the source xlsb, string-valued cells produce `None` in the output rather than failing. Numeric and boolean cells are unaffected.
- **Formula cached values only.** `pyxlsb` returns the last-calculated result of each formula, not the formula text. If a cell was never calculated (e.g. the file was saved without recalculation), the cached value is stale or absent. Downstream consumers will see the cached value, not a live formula.
- **Multi-sheet workbooks are fully supported.** Each sheet is converted in order; sheet names are preserved.
- **Password-protected xlsb files.** `pyxlsb` cannot open encrypted xlsb files. These will raise an exception and be routed to the error quarantine path via the standard CDR error handler.

**Legacy OLE formats** (`doc`, `xls`, `ppt`): quarantined and deleted from source — no CDR attempted.

### PDF CDR

Uses `pikepdf` to remove:
- `/OpenAction`, `/AA` at document level
- `/JavaScript`, `/JS` at document level
- `/Names./JavaScript` — JavaScript name tree
- `/EmbeddedFiles` — embedded file attachments
- Per-page annotation actions: `/Launch`, `/SubmitForm`, `/GoToR`, `/URI`
- AcroForm `/Fields` — recursively sweeps all field and widget dictionaries for `/A`, `/AA`, `/JS`, `/JavaScript`

Preserves form field visual structure (field names, positions, appearance).

### Image CDR

Re-encodes through Pillow to create a pixel-only copy. All EXIF, ICC, XMP metadata is stripped by the re-encode. Supported: `jpg`, `jpeg`, `png`, `gif`, `bmp`, `tiff`, `webp`.

**GIF:** Re-encoded as GIF (format and `Content-Type: image/gif` are preserved). GIF comment extension blocks are explicitly suppressed (`comment=b""`) — Pillow carries them through re-encode by default unless overridden.

**Multi-frame TIFF:** Each frame is decoded independently via `ImageSequence.Iterator` and re-encoded into a fresh pixel-only copy. All frames are preserved in the output. Per-frame IFD tags and EXIF do not survive the round-trip. Single-frame TIFFs go through the standard single-image path.

### ZIP integrity validation

Runs before CDR on all Office files. All checks below result in a **hard reject** — file quarantined, source deleted, no CDR attempted:
- Magic bytes (`50 4B 03 04`) not found
- Non-standard compression methods (anything other than stored/deflate)
- Duplicate ZIP entry names
- Local/central directory compression method mismatch

Hard rejects emit CloudWatch metric `CDR/Validation/ZipAnomalies`.

---

## Reliability Architecture

### Fault-isolated success path

The CDR output upload to `SANITISED_BUCKET` is the only operation that must succeed. All other side effects are best-effort:

- **`_delete_source_safe`** — wraps `s3.delete_object` in try/except, logs warning on failure, never re-raises. A delete failure must not trigger EventBridge retries.
- **`_publish_result_safe`** — wraps SNS publish in try/except, logs warning on failure, never re-raises. SNS unavailability must not block the success response. Truncates the `removed` list to 100 entries to stay within the 256 KB SNS message limit.

### Decompression bomb defence

**`_read_zip_entry_safe`** reads ZIP entries in 64 KB chunks with a running byte counter. It raises `ValueError` if the running total exceeds `CDR_MAX_ENTRY_BYTES` (default 200 MB). Critically, it does NOT trust `item.file_size` — the central directory `file_size` field is attacker-controlled and can be falsified to 1 byte in a crafted zip bomb.

### Download error classification

**`_classify_download_error`** distinguishes `NoSuchKey` (source already deleted — an expected EventBridge retry race) from real download failures. `NoSuchKey` publishes a `source-missing` CDR result without creating a quarantine entry.

### Dead-letter queue

Events that exhaust EventBridge retries land in `CdrDlq` (14-day retention). `CdrDlqAlarm` fires when DLQ depth ≥ 1.

---

## Observability

### CloudWatch alarms

| Alarm | Trigger | Topic |
|---|---|---|
| `cdr-lambda-errors` | Lambda errors ≥ 1 in 60 s | `CdrAlarmTopic` |
| `cdr-lambda-duration-p99` | p99 duration > 250 s | `CdrAlarmTopic` |
| `cdr-lambda-throttles` | Throttles ≥ 1 in 60 s | `CdrAlarmTopic` |
| `cdr-lambda-dlq-depth` | DLQ messages ≥ 1 in 60 s | `CdrAlarmTopic` |
| `cdr-lambda-passthrough` | PassthroughFiles ≥ 1 in 5 min | `CdrAlarmTopic` |

All alarms publish to `CdrAlarmTopic`, which is **separate** from `CdrResultTopic`. This prevents alarm noise from polluting downstream consumers that subscribe to CDR result metadata.

### Structured logging

All log lines use `key=value` format for CloudWatch Logs Insights:
```
CDR complete: bucket=source-bucket key=incoming/file.xlsx ext=xlsx removals=3 mode=full dest=s3://sanitised-bucket/sanitised/incoming/file.xlsx
```

### SNS result payload

Published to `CdrResultTopic` after every file:
```json
{
  "source_bucket": "...",
  "key": "incoming/file.xlsx",
  "status": "sanitised",
  "report": {
    "ext": "xlsx",
    "mode": "full",
    "removed": ["xl/vbaProject.bin", "xl/externalLinks/"],
    "timestamp": "2026-05-06T12:00:00Z"
  }
}
```

Status values: `sanitised`, `quarantined`, `rejected`, `source-missing`, `error`.

---

## Infrastructure

- **Runtime:** Python 3.12, 1024 MB memory, 300 s timeout, 1024 MB `/tmp` ephemeral storage
- **Concurrency:** `ReservedConcurrentExecutions: 20` — prevents OOM bursts from simultaneous large-file processing
- **IaC:** AWS SAM (`src/template.yaml`)
- **Libraries:** `pikepdf`, `Pillow`, `boto3`, `zipfile` (stdlib)
- **Encryption:** AES256 server-side encryption on all buckets
- **Bucket hardening:** all buckets block public access; source and sanitised buckets have versioning enabled
- **Quarantine:** optional — template deploys cleanly with or without a quarantine bucket name (`QuarantineEnabled` condition)

**Deployment and load benchmarking:** See `docs/deployment-runbook.md` for the end-to-end staging guide (build, deploy, smoke test, benchmark, tuning thresholds, cleanup, and known issues). Use `docs/benchmark.py` to run a load test against a live stack — it uploads synthetic or real fixture files concurrently and queries CloudWatch for Duration p50/p99, MaxMemoryUsed, Invocations, Errors, and Throttles, then prints automatic tuning recommendations.

**Tuning thresholds:**

| Metric | Action |
|---|---|
| p99 Duration > 250 s | Increase `Timeout` in `template.yaml` (current: 300 s) |
| p99 Duration > 200 s on PDFs | Increase `MemorySize` to 2048 MB (Lambda CPU scales with RAM) |
| MaxMemoryUsed > 900 MB | Increase `MemorySize` to 2048 MB |
| Throttles > 0 | Increase `ReservedConcurrentExecutions` |
| DLQ depth > 0 | Inspect DLQ messages and investigate root cause |

---

## Configurable Limits

| SAM Parameter | Default | Purpose |
|---|---|---|
| `CdrMaxFileBytes` | 104857600 (100 MB) | Pre-download size limit |
| `CdrMaxEntryBytes` | 209715200 (200 MB) | Per-ZIP-entry decompression limit |

Both are exposed as Lambda environment variables (`CDR_MAX_FILE_BYTES`, `CDR_MAX_ENTRY_BYTES`) and can be tuned without code changes.

---

## Key Design Decisions

**Why EventBridge fan-out over direct S3 → Lambda?**
Fan-out lets CDR and AV run in parallel without coupling. New consumers (e.g. DLP, classification) can be added as EventBridge targets without touching bucket config.

**Why operate on the ZIP directly instead of using an Office library?**
Re-serialising through a full Office library (openpyxl, python-pptx) risks dropping content that the library doesn't model — named ranges, less-common chart types, custom XML parts. Zip-level surgery preserves everything CDR doesn't explicitly touch.

**Why fault-isolate SNS publish and source delete?**
EventBridge interprets any unhandled exception as a failure and retries. If SNS is down and `publish_result` throws, a naive implementation re-CDRs an already-sanitised file on every retry. The fault-isolated pattern ensures the sanitised output is already in place before either side effect is attempted, so a failure in either is just a warning.

**Why not trust `item.file_size` for the decompression bomb limit?**
The central directory `file_size` field in a ZIP is not validated by Python's `zipfile` module. An attacker can craft a zip bomb with `file_size = 1` in the central directory while the actual decompressed content is gigabytes. Reading in chunks with a running counter is the only reliable defence.

**Why delete the original after rejection?**
The source bucket is a transit zone, not storage. A rejected file sitting in `incoming/` is dead weight that could be accidentally served. Deletion on rejection keeps the bucket clean — but the full content is always preserved in quarantine via `CopyObject` first.

**Why a separate alarm SNS topic?**
Downstream services subscribe to `CdrResultTopic` to act on CDR results (route files, update audit logs, etc.). Receiving CloudWatch alarm JSON on that topic breaks their message parsing. `CdrAlarmTopic` is for ops teams; `CdrResultTopic` is for application consumers.
