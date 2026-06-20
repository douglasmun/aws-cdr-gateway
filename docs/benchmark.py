#!/usr/bin/env python3
"""
CDR Lambda load benchmark.

Uploads a set of fixture files to the source S3 bucket (concurrently), waits
for Lambda invocations to complete, then reports p50/p99 Duration and peak
memory usage from CloudWatch.

Usage:
    python docs/benchmark.py --bucket cdr-staging-source-xxx [options]

Options:
    --bucket       Source S3 bucket name (required)
    --files        Directory of fixture files to upload (default: generates synthetics)
    --concurrency  Parallel upload threads (default: 5)
    --count        Total uploads per fixture file (default: 10)
    --region       AWS region (default: from profile/env)
    --wait         Seconds to wait for Lambda invocations after upload (default: 60)

Dependencies: boto3 (pip install boto3)
"""

import argparse
import io
import os
import queue
import sys
import threading
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import boto3
except ImportError:
    sys.exit("boto3 is required: pip install boto3")


# ── Synthetic fixture generators ───────────────────────────────────────────────

def _random_pad(size_bytes: int) -> bytes:
    """Return incompressible pseudo-random bytes of the given size.
    Using os.urandom ensures deflate produces minimal compression, so the
    uploaded object actually reaches the advertised size in S3."""
    return os.urandom(size_bytes)


def _make_docx_with_macro(size_kb: int = 50) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",
                   '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/'
                   'package/2006/content-types"></Types>')
        z.writestr("_rels/.rels",
                   '<?xml version="1.0"?><Relationships xmlns="http://schemas.'
                   'openxmlformats.org/package/2006/relationships"/>')
        z.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0" + b"M" * 512)
        # Use incompressible random bytes so the uploaded ZIP reaches the advertised size
        z.writestr("word/document.xml",
                   "<w:document/>")
        z.writestr("word/padding.bin", _random_pad(max(0, size_kb * 1024 - 600)))
    return buf.getvalue()


def _make_xlsx_with_macros(size_kb: int = 5000) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",
                   '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/'
                   'package/2006/content-types">'
                   '<Override PartName="/xl/workbook.xml"'
                   ' ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/>'
                   '</Types>')
        z.writestr("_rels/.rels",
                   '<?xml version="1.0"?><Relationships xmlns="http://schemas.'
                   'openxmlformats.org/package/2006/relationships"/>')
        z.writestr("xl/vbaProject.bin", b"\xd0\xcf\x11\xe0" + b"M" * 512)
        z.writestr("xl/workbook.xml", "<workbook/>")
        # Use incompressible random bytes so the uploaded ZIP reaches the advertised size
        z.writestr("xl/padding.bin", _random_pad(max(0, size_kb * 1024 - 600)))
    return buf.getvalue()


def _make_pdf_with_js(size_kb: int = 1000) -> bytes:
    try:
        import pikepdf
        pdf = pikepdf.Pdf.new()
        page = pdf.make_indirect(pikepdf.Dictionary(
            Type=pikepdf.Name("/Page"),
            MediaBox=pikepdf.Array([0, 0, 612, 792]),
        ))
        pdf.pages.append(pikepdf.Page(page))
        pdf.Root["/OpenAction"] = pikepdf.Dictionary(
            S=pikepdf.Name("/JavaScript"),
            JS=pikepdf.String("app.alert('benchmark');"),
        )
        out = io.BytesIO()
        pdf.save(out)
        data = out.getvalue()
        # Pad if needed (not essential for PDF benchmarks)
        return data
    except ImportError:
        # Fallback: minimal valid PDF structure
        return b"%PDF-1.4\n1 0 obj<</Type /Catalog /OpenAction<</S /JavaScript /JS (alert(1))>>>>\nendobj\n%%EOF"


def _make_png(size_kb: int = 2000) -> bytes:
    try:
        from PIL import Image
        img = Image.new("RGB", (1024, 1024), color=(128, 64, 32))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except ImportError:
        # 1x1 red PNG
        return (b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
                b'\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00'
                b'\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82')


SYNTHETIC_FIXTURES = [
    ("small_docx.docx",  lambda: _make_docx_with_macro(50),    "small DOCX with VBA (~50 KB)"),
    ("large_xlsx.xlsm",  lambda: _make_xlsx_with_macros(5000), "large XLSM with VBA (~5 MB)"),
    ("pdf_with_js.pdf",  lambda: _make_pdf_with_js(1000),      "PDF with JavaScript (~1 MB)"),
    ("image.png",        lambda: _make_png(2000),               "PNG image (~2 MB, actual size varies)"),
]


# ── Upload worker ──────────────────────────────────────────────────────────────

def _upload_worker(s3, bucket: str, work_q: queue.Queue, results: list, errors: list):
    while True:
        try:
            key, data, label = work_q.get_nowait()
        except queue.Empty:
            break
        t0 = time.monotonic()
        try:
            s3.put_object(Bucket=bucket, Key=key, Body=data)
            elapsed = time.monotonic() - t0
            results.append((label, elapsed))
            print(f"  uploaded {key} ({len(data)//1024} KB) in {elapsed:.2f}s")
        except Exception as exc:
            errors.append((key, str(exc)))
            print(f"  ERROR uploading {key}: {exc}", file=sys.stderr)
        finally:
            work_q.task_done()


# ── CloudWatch metrics query ───────────────────────────────────────────────────

def _round_up_60(seconds: float) -> int:
    """Round seconds up to the nearest 60-second multiple (CloudWatch requirement)."""
    return max(60, int(seconds + 59) // 60 * 60)


def _query_metrics(cw, fn: str, logs, log_group: str, start: datetime, end: datetime) -> dict:
    """Query CloudWatch Metrics for Lambda counters and parse REPORT lines from
    CloudWatch Logs for MaxMemoryUsed (not available as a standard AWS/Lambda metric)."""
    results = {}
    # Period must be a multiple of 60 s for standard Lambda metrics.
    period = _round_up_60((end - start).total_seconds())

    # Duration p50 / p99
    resp = cw.get_metric_statistics(
        Namespace="AWS/Lambda",
        MetricName="Duration",
        Dimensions=[{"Name": "FunctionName", "Value": fn}],
        StartTime=start,
        EndTime=end,
        Period=period,
        ExtendedStatistics=["p50", "p99"],
    )
    if resp["Datapoints"]:
        dp = resp["Datapoints"][0]
        results["duration_p50_ms"] = dp.get("ExtendedStatistics", {}).get("p50")
        results["duration_p99_ms"] = dp.get("ExtendedStatistics", {}).get("p99")

    # Invocation count
    resp = cw.get_metric_statistics(
        Namespace="AWS/Lambda",
        MetricName="Invocations",
        Dimensions=[{"Name": "FunctionName", "Value": fn}],
        StartTime=start,
        EndTime=end,
        Period=period,
        Statistics=["Sum"],
    )
    if resp["Datapoints"]:
        results["invocations"] = int(resp["Datapoints"][0].get("Sum", 0))

    # Error count
    resp = cw.get_metric_statistics(
        Namespace="AWS/Lambda",
        MetricName="Errors",
        Dimensions=[{"Name": "FunctionName", "Value": fn}],
        StartTime=start,
        EndTime=end,
        Period=period,
        Statistics=["Sum"],
    )
    if resp["Datapoints"]:
        results["errors"] = int(resp["Datapoints"][0].get("Sum", 0))

    # Throttles
    resp = cw.get_metric_statistics(
        Namespace="AWS/Lambda",
        MetricName="Throttles",
        Dimensions=[{"Name": "FunctionName", "Value": fn}],
        StartTime=start,
        EndTime=end,
        Period=period,
        Statistics=["Sum"],
    )
    if resp["Datapoints"]:
        results["throttles"] = int(resp["Datapoints"][0].get("Sum", 0))

    # MaxMemoryUsed is not a standard AWS/Lambda CloudWatch metric — it only appears
    # in Lambda REPORT log lines. Parse them from CloudWatch Logs Insights.
    if log_group:
        try:
            import re as _re
            query_resp = logs.start_query(
                logGroupName=log_group,
                startTime=int(start.timestamp()),
                endTime=int(end.timestamp()),
                queryString="filter @message like /REPORT/ | parse @message \"Max Memory Used: * MB\" as mem | stats max(mem) as max_mem",
                limit=1,
            )
            query_id = query_resp["queryId"]
            # Poll until complete (up to 30 s)
            for _ in range(30):
                time.sleep(1)
                status_resp = logs.get_query_results(queryId=query_id)
                if status_resp["status"] in ("Complete", "Failed", "Cancelled", "Timeout"):
                    break
            if status_resp["status"] == "Complete" and status_resp["results"]:
                for field in status_resp["results"][0]:
                    if field.get("field") == "max_mem":
                        try:
                            results["max_memory_mb"] = float(field["value"])
                        except (ValueError, TypeError):
                            pass
        except Exception as exc:
            print(f"  (MaxMemoryUsed log query failed: {exc})", file=sys.stderr)

    return results


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CDR Lambda load benchmark")
    parser.add_argument("--bucket",      required=True, help="Source S3 bucket name")
    parser.add_argument("--files",       default=None,  help="Directory of fixture files")
    parser.add_argument("--concurrency", type=int, default=5)
    parser.add_argument("--count",       type=int, default=10,
                        help="Uploads per fixture file")
    parser.add_argument("--function",    default="cdr-lambda",
                        help="Lambda function name for CloudWatch queries (default: cdr-lambda)")
    parser.add_argument("--log-group",   default=None,
                        help="CloudWatch Logs group for the Lambda (e.g. /aws/lambda/cdr-lambda). "
                             "Required for MaxMemoryUsed reporting.")
    parser.add_argument("--region",      default=None)
    parser.add_argument("--wait",        type=int, default=60,
                        help="Seconds to wait after uploads for Lambda to finish")
    args = parser.parse_args()

    session = boto3.session.Session(region_name=args.region)
    s3 = session.client("s3")
    cw = session.client("cloudwatch")
    logs = session.client("logs")

    # Build fixture list
    fixtures: list[tuple[str, bytes, str]] = []

    if args.files:
        fixture_dir = Path(args.files)
        if not fixture_dir.is_dir():
            sys.exit(f"--files path does not exist: {fixture_dir}")
        # Skip the fixture-directory's own tooling/docs (generate_fixtures.py, README.md):
        # uploading them sends unsupported extensions through the Lambda, tripping the
        # passthrough alarm and skewing invocation counts.
        skip_ext = {".py", ".md"}
        for f in sorted(fixture_dir.iterdir()):
            if f.is_file() and f.suffix.lower() not in skip_ext:
                fixtures.append((f.name, f.read_bytes(), f.name))
        if not fixtures:
            sys.exit(f"No uploadable fixtures found in {fixture_dir}")
    else:
        print("No --files directory given — generating synthetic fixtures.")
        for name, gen, desc in SYNTHETIC_FIXTURES:
            print(f"  generating {desc}...")
            fixtures.append((name, gen(), desc))

    # Build work queue: count copies of each fixture
    prefix = f"benchmark/{int(time.time())}"
    work_q: queue.Queue = queue.Queue()
    total_uploads = 0
    for i in range(args.count):
        for name, data, label in fixtures:
            key = f"{prefix}/{i:04d}/{name}"
            work_q.put((key, data, label))
            total_uploads += 1

    print(f"\nUploading {total_uploads} files to s3://{args.bucket}/{prefix}/")
    print(f"Concurrency: {args.concurrency}, fixtures: {len(fixtures)}, copies each: {args.count}")
    print()

    bench_start = datetime.now(timezone.utc)
    upload_results: list = []
    upload_errors: list = []

    threads = [
        threading.Thread(
            target=_upload_worker,
            args=(s3, args.bucket, work_q, upload_results, upload_errors),
            daemon=True,
        )
        for _ in range(args.concurrency)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    upload_end = datetime.now(timezone.utc)
    upload_elapsed = (upload_end - bench_start).total_seconds()
    print(f"\nAll uploads complete in {upload_elapsed:.1f}s "
          f"({len(upload_errors)} errors)")

    if upload_errors:
        print(f"\nUpload errors ({len(upload_errors)}):")
        for key, err in upload_errors:
            print(f"  {key}: {err}")

    # Wait for Lambda invocations to drain
    print(f"\nWaiting {args.wait}s for Lambda invocations to complete...")
    time.sleep(args.wait)

    bench_end = datetime.now(timezone.utc)
    # Query a window that covers uploads + wait period, with 30s buffer
    metric_start = bench_start - timedelta(seconds=30)
    metric_end   = bench_end   + timedelta(seconds=30)

    log_group = args.log_group or f"/aws/lambda/{args.function}"
    print(f"\nQuerying CloudWatch metrics for function: {args.function}")
    print(f"  (MaxMemoryUsed parsed from log group: {log_group})")
    metrics = _query_metrics(cw, args.function, logs, log_group, metric_start, metric_end)

    # ── Report ─────────────────────────────────────────────────────────────────
    print()
    print("=" * 60)
    print("BENCHMARK RESULTS")
    print("=" * 60)
    print(f"  Uploads sent:       {total_uploads}")
    print(f"  Upload errors:      {len(upload_errors)}")
    print(f"  Upload throughput:  {total_uploads / upload_elapsed:.1f} files/s")
    print()
    print(f"  Lambda invocations: {metrics.get('invocations', 'N/A')}")
    print(f"  Lambda errors:      {metrics.get('errors', 'N/A')}")
    print(f"  Throttles:          {metrics.get('throttles', 'N/A')}")
    print()

    p50 = metrics.get("duration_p50_ms")
    p99 = metrics.get("duration_p99_ms")
    mem = metrics.get("max_memory_mb")

    print(f"  Duration p50:       {f'{p50:.0f} ms' if p50 else 'N/A'}")
    print(f"  Duration p99:       {f'{p99:.0f} ms' if p99 else 'N/A'}")
    print(f"  Max memory used:    {f'{mem:.0f} MB' if mem else 'N/A'}")
    print()

    # Tuning recommendations
    issues = []
    if p99 and p99 > 250_000:
        issues.append(f"  WARN  p99 {p99/1000:.0f}s exceeds 250s threshold — increase Timeout in template.yaml")
    if p99 and p99 > 200_000:
        issues.append(f"  WARN  p99 {p99/1000:.0f}s > 200s on PDFs — consider MemorySize 2048 MB")
    if mem and mem > 900:
        issues.append(f"  WARN  Peak memory {mem:.0f} MB > 900 MB — increase MemorySize to 2048 MB")
    if metrics.get("throttles", 0) > 0:
        issues.append(f"  WARN  {metrics['throttles']} throttle(s) — increase ReservedConcurrentExecutions")
    if metrics.get("errors", 0) > 0:
        issues.append(f"  ERROR {metrics['errors']} Lambda error(s) — check CloudWatch Logs")

    if issues:
        print("Tuning recommendations:")
        for i in issues:
            print(i)
    else:
        print("  All metrics within thresholds. No tuning required.")

    print("=" * 60)

    # Exit non-zero if there were Lambda errors
    if metrics.get("errors", 0) > 0 or upload_errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
