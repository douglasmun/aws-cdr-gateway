"""
CDR Lambda — Content Disarmament and Reconstruction
Triggered by EventBridge on S3 ObjectCreated events.

Supported formats:
  Office  — .docx .xlsx .pptx and all ZIP/OOXML variants (removes macros, OLE, external links)
  PDF     — strips JS, OpenAction, Launch, form submit actions, embedded files
  Images  — re-encodes via Pillow to purge EXIF / ICC exploits

Processing flow (see ``handler``):
  download → size/ZIP-structure validation → fail-closed routing by extension →
  format-specific CDR (``cdr_office`` / ``cdr_pdf`` / ``cdr_image``) → upload to
  SANITISED_BUCKET → publish result + delete source. Rejected/errored/unsupported files
  are quarantined instead. Unknown extensions FAIL CLOSED — they are never labelled
  sanitised.

Design rules that must not be weakened:
  * Side effects (SNS publish, source delete, metrics) are fault-isolated — they can never
    turn a successful CDR into an EventBridge retry.
  * ZIP entries are read through ``_read_zip_entry_safe`` (chunked counter, never trusts
    the central-directory ``file_size``) to defend against decompression bombs.
  * CDR drops/neutralises content in place; it never re-serialises through an Office
    library, so anything not explicitly touched is preserved.

Environment variables:
  SANITISED_BUCKET     destination bucket for clean files (required)
  QUARANTINE_BUCKET    destination for rejected/errored files (optional)
  RESULT_TOPIC_ARN     SNS topic for CDR result metadata (optional)
  CDR_MAX_FILE_BYTES   pre-download size limit in bytes (default 104857600 = 100 MB)
  CDR_MAX_ENTRY_BYTES  per-ZIP-entry decompression limit (default 209715200 = 200 MB)
"""

import html
import io
import json
import logging
import os
import re
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone
from typing import Optional

import boto3
import openpyxl
import pikepdf
import pyxlsb
from PIL import Image, ImageSequence

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3  = boto3.client("s3")
sns = boto3.client("sns")
cw  = boto3.client("cloudwatch")

SANITISED_BUCKET  = os.environ["SANITISED_BUCKET"]
QUARANTINE_BUCKET = os.environ.get("QUARANTINE_BUCKET", "")
RESULT_TOPIC_ARN  = os.environ.get("RESULT_TOPIC_ARN", "")

_MAX_FILE_BYTES  = int(os.environ.get("CDR_MAX_FILE_BYTES",  str(100 * 1024 * 1024)))
_MAX_ENTRY_BYTES = int(os.environ.get("CDR_MAX_ENTRY_BYTES", str(200 * 1024 * 1024)))

# ── OOXML (Office) dangerous relationship types ────────────────────────────────
STRIP_REL_TYPES: set[str] = {
    "http://schemas.microsoft.com/office/2006/relationships/vbaProject",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/externalLink",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/externalLinkPath",
    "http://schemas.microsoft.com/office/2006/relationships/attachedToolbars",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/queryTable",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/connections",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/control",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/subDocument",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/frame",
    # altChunk imports an arbitrary HTML/MHTML/RTF chunk that the field/macro scrub never
    # inspects (it only scans the host document.xml) — active/remote-content smuggling.
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/aFChunk",
    # Embedded package parts (the relationship form of an embedded OLE/package object).
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/package",
    # Office Web Add-in (task pane / web extension) relationships.
    "http://schemas.microsoft.com/office/2011/relationships/webextensiontaskpanes",
    "http://schemas.microsoft.com/office/2011/relationships/webextension",
}

# External hyperlink relationship type. NOT in STRIP_REL_TYPES because deleting the rel
# would dangle the document's r:id reference — instead its Target is rewritten to inert in
# _strip_rels (UNC paths leak NTLM creds; arbitrary URLs enable phishing/SSRF).
HYPERLINK_REL_TYPE = (
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"
)

STRIP_ZIP_ENTRIES: set[str] = {
    "word/vbaProject.bin",
    "xl/vbaProject.bin",
    "ppt/vbaProject.bin",
    "word/activeX",
    "xl/activeX",
    "ppt/activeX",
    "customXml/",
    "word/attachedToolbars/",
    "word/externalLinks/",
    "xl/externalLinks/",
    "xl/macrosheets/",
    "xl/queryTables/",
    "xl/connections.xml",
    "ppt/tags/",
    # Embedded OLE/package objects (oleObject*.bin, renamed .exe/.lnk/.hta, or a nested
    # macro doc). The oleObject relationship is already stripped, but the payload bytes
    # remain extractable unless the part itself is dropped.
    "word/embeddings/",
    "xl/embeddings/",
    "ppt/embeddings/",
    # Office Web Add-ins (task panes / content add-ins live under webextensions/). A
    # webextension auto-loads remote code from an attacker-controlled SourceLocation
    # without any VBA — remote-content execution gated only by tenant/admin policy and
    # consent prompts. Drop the parts (taskpanes.xml + the webextension*.xml definitions).
    "word/webextensions/",
    "xl/webextensions/",
    "ppt/webextensions/",
    # PostScript/EPS image parts (typically under <app>/media/). EPS is a Turing-complete
    # interpreter language and a historic RCE surface — drop the payload bytes; the
    # matching [Content_Types].xml declaration is stripped in _sanitise_content_types.
    ".eps",
    ".ps",
}

OFFICE_EXTS: set[str] = {
    "docx", "docm", "dotx", "dotm",
    "xlsx", "xlsm", "xltx", "xltm", "xlam", "xlsb",
    "pptx", "pptm", "potx", "potm", "ppsx", "ppsm", "ppam",
}

LEGACY_EXTS: set[str] = {"doc", "xls", "ppt"}

# Formats DELIBERATELY rejected — never given a CDR handler. These carry active content
# as loose, parser-divergent structure (embedded/linked OLE, remote-template refs, control
# words a forgiving consumer acts on) rather than as cleanly-excisable content. A
# reconstruction pass can only defend the grammar IT parses; the attacker targets the
# grammar the *consumer* parses. RTF history bears this out: CVE-2017-0199 (remote OLE
# template), CVE-2017-11882 / CVE-2018-0802 (Equation Editor), CVE-2023-21716 (heap
# corruption in the font table). They are quarantined fail-closed by a dedicated handler
# block that runs BEFORE ZIP validation and the unknown-extension gate — listed explicitly
# so the rejection is a documented, order-independent decision, not an accidental gap a
# future contributor "fixes" by adding a handler. See pitfall #38.
FAIL_CLOSED_EXTS: set[str] = {"rtf"}

EXT_REMAP: dict[str, str] = {
    "docm": "docx", "dotm": "dotx",
    "xlsm": "xlsx", "xltm": "xltx", "xlam": "xlsx", "xlsb": "xlsx",
    "pptm": "pptx", "potm": "potx", "ppsm": "ppsx", "ppam": "pptx",
}

# Includes both container-level types and real OPC part-level (*.main+xml) types.
MACRO_CONTENT_TYPE_REMAP: dict[str, str] = {
    "application/vnd.ms-word.document.macroEnabled.12":
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-word.document.macroEnabled.main+xml":
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
    "application/vnd.ms-word.template.macroEnabled.12":
        "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
    "application/vnd.ms-word.template.macroEnabledTemplate.main+xml":
        "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml",
    "application/vnd.ms-excel.sheet.macroEnabled.12":
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-excel.sheet.macroEnabled.main+xml":
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
    "application/vnd.ms-excel.sheet.binary.macroEnabled.12":
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-excel.template.macroEnabled.12":
        "application/vnd.openxmlformats-officedocument.spreadsheetml.template",
    "application/vnd.ms-excel.template.macroEnabled.main+xml":
        "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml",
    "application/vnd.ms-excel.addin.macroEnabled.12":
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-powerpoint.presentation.macroEnabled.12":
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml":
        "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
    "application/vnd.ms-powerpoint.template.macroEnabled.12":
        "application/vnd.openxmlformats-officedocument.presentationml.template",
    "application/vnd.ms-powerpoint.template.macroEnabled.main+xml":
        "application/vnd.openxmlformats-officedocument.presentationml.template.main+xml",
    "application/vnd.ms-powerpoint.slideshow.macroEnabled.12":
        "application/vnd.openxmlformats-officedocument.presentationml.slideshow",
    "application/vnd.ms-powerpoint.slideshow.macroEnabled.main+xml":
        "application/vnd.openxmlformats-officedocument.presentationml.slideshow.main+xml",
    "application/vnd.ms-powerpoint.addin.macroEnabled.12":
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}

# PostScript/EPS content types (lowercased). EPS is a Turing-complete interpreter
# language and a historic RCE surface; a valid OOXML package can legitimately declare
# such a part, so we strip both the [Content_Types].xml declaration and the part bytes.
POSTSCRIPT_CONTENT_TYPES: set[str] = {
    "application/postscript",
    "application/eps",
    "application/x-eps",
    "image/eps",
    "image/x-eps",
}


def _is_postscript_ct(ct: str) -> bool:
    """True if ``ct`` is a PostScript/EPS content type. Normalises case, surrounding
    whitespace, and any RFC-2045 parameter suffix (``;charset=…``) before comparison so
    a declaration like ``application/postscript; charset=utf-8`` cannot evade the set."""
    return ct.split(";", 1)[0].strip().lower() in POSTSCRIPT_CONTENT_TYPES

_ZIP_MAGIC           = b"\x50\x4b\x03\x04"
_SAFE_COMPRESS_METHODS = {0, 8}  # stored, deflate

# ── Entry point ────────────────────────────────────────────────────────────────

def handler(event: dict, context) -> dict:
    """Lambda entry point — receives an EventBridge S3 ObjectCreated event."""
    detail = event.get("detail", {})
    try:
        bucket = detail["bucket"]["name"]
        key    = detail["object"]["key"]
    except KeyError as exc:
        logger.error("Malformed EventBridge event — missing field %s: %s", exc, json.dumps(event)[:512])
        raise ValueError(f"Malformed event: missing {exc}") from exc

    size = detail.get("object", {}).get("size", 0)
    logger.info("CDR start: bucket=%s key=%s size=%d", bucket, key, size)

    # Validate key for path traversal (S3 keys are literal but defend against confused callers)
    if ".." in key.split("/"):
        logger.warning("Key contains path traversal segments, rejecting: %s", key)
        _publish_result_safe(bucket, key, "rejected", {"reason": "invalid key"})
        return {"status": "rejected", "reason": "invalid key"}

    # ── Pre-download size guard ───────────────────────────────────────────────
    if size > _MAX_FILE_BYTES:
        logger.warning("File too large: key=%s size=%d max=%d", key, size, _MAX_FILE_BYTES)
        if QUARANTINE_BUCKET:
            try:
                s3.copy_object(
                    CopySource={"Bucket": bucket, "Key": key},
                    Bucket=QUARANTINE_BUCKET,
                    Key=f"oversized/{key}",
                    TaggingDirective="REPLACE",
                    Tagging="cdr-status=rejected&cdr-reason=file-too-large",
                )
            except Exception as exc:
                logger.warning("Could not copy oversized file to quarantine: key=%s error=%s", key, exc)
        _publish_result_safe(bucket, key, "rejected", {"reason": "file too large", "size": size})
        return {"status": "rejected", "reason": "file too large"}

    # ── Download ──────────────────────────────────────────────────────────────
    try:
        file_bytes, content_type = _download(bucket, key)
    except Exception as exc:
        _classify_download_error(bucket, key, exc)
        raise

    ext           = key.rsplit(".", 1)[-1].lower() if "." in key else ""
    sanitised_ext = EXT_REMAP.get(ext, ext)
    zip_anomalies: list[str] = []

    # ── Legacy binary formats ─────────────────────────────────────────────────
    if ext in LEGACY_EXTS:
        logger.warning("Unsupported legacy format: key=%s ext=%s", key, ext)
        if QUARANTINE_BUCKET:
            try:
                _upload(QUARANTINE_BUCKET, f"unsupported/{key}", file_bytes, content_type,
                        {"cdr-status": "unsupported-format", "cdr-original-ext": ext,
                         "cdr-timestamp": _now()})
            except Exception as q_exc:
                logger.warning("Quarantine upload failed: key=%s error=%s", key, q_exc)
        _publish_result_safe(bucket, key, "unsupported-format",
                             {"reason": "OLE binary format not supported", "original_ext": ext})
        _delete_source_safe(bucket, key)
        return {"status": "unsupported-format", "reason": "OLE binary format not supported"}

    # ── Deliberately-rejected carriers — FAIL CLOSED (highest priority) ───────
    # RTF (and any other FAIL_CLOSED_EXTS member) is rejected BY DESIGN — never given a
    # CDR handler. This check runs FIRST, before ZIP validation and the unknown-extension
    # gate, so the rejection is order-independent: even if a future edit wrongly adds the
    # extension to OFFICE_EXTS, it lands here and never reaches cdr_office(). See pitfall #38.
    if ext in FAIL_CLOSED_EXTS:
        logger.warning("Deliberately-rejected format — quarantine (fail closed): "
                       "key=%s ext=%s", key, ext)
        _emit_passthrough_metric(ext)
        if QUARANTINE_BUCKET:
            try:
                _upload(QUARANTINE_BUCKET, f"unsupported/{key}", file_bytes, content_type,
                        {"cdr-status": "unsupported-format", "cdr-original-ext": ext,
                         "cdr-timestamp": _now()})
            except Exception as q_exc:
                logger.warning("Quarantine upload failed: key=%s error=%s", key, q_exc)
        _publish_result_safe(bucket, key, "unsupported-format",
                             {"reason": f"format rejected by design: {ext}", "original_ext": ext})
        _delete_source_safe(bucket, key)
        return {"status": "unsupported-format", "reason": f"format rejected by design: {ext}"}

    # ── ZIP structural validation ─────────────────────────────────────────────
    if ext in OFFICE_EXTS:
        valid, zip_anomalies = _validate_zip_structure(file_bytes)
        if not valid:
            logger.warning("ZIP validation failed: key=%s reason=%s", key, zip_anomalies)
            _emit_zip_anomaly_metric()
            if QUARANTINE_BUCKET:
                try:
                    _upload(QUARANTINE_BUCKET, f"rejected/{key}", file_bytes, content_type,
                            {"cdr-status": "rejected", "cdr-reason": zip_anomalies[0][:256],
                             "cdr-timestamp": _now()})
                except Exception as q_exc:
                    logger.warning("Quarantine upload failed: key=%s error=%s", key, q_exc)
            _publish_result_safe(bucket, key, "rejected",
                                 {"reason": zip_anomalies[0], "original_ext": ext})
            _delete_source_safe(bucket, key)
            return {"status": "rejected", "reason": zip_anomalies[0]}
        # _validate_zip_structure returns (False, [anomaly]) on any anomaly (hard reject
        # above) or (True, []) when clean — it never returns (True, non-empty). So past
        # this point zip_anomalies is always empty; there is no "valid-but-anomalous" path.

    # ── Unknown extension — FAIL CLOSED ───────────────────────────────────────
    # A CDR gate must never label content it did not disarm as "sanitised". An
    # unrecognised extension (.svg, .html, .lnk, .iso, …) is quarantined with the source
    # preserved-then-deleted — it must NOT reach SANITISED_BUCKET. Carriers like SVG/HTML
    # are active-content vectors; passing them through inverts the trust label on the
    # sanitised bucket. (RTF and other deliberately-rejected carriers are already handled
    # by the FAIL_CLOSED_EXTS block above.) The detective passthrough metric still fires.
    if (
        ext not in OFFICE_EXTS
        and ext != "pdf"
        and ext not in ("jpg", "jpeg", "png", "gif", "bmp", "tiff", "webp")
    ):
        logger.warning("Unknown extension — quarantine (fail closed): key=%s ext=%s", key, ext)
        _emit_passthrough_metric(ext)
        if QUARANTINE_BUCKET:
            try:
                _upload(QUARANTINE_BUCKET, f"unsupported/{key}", file_bytes, content_type,
                        {"cdr-status": "unsupported-format", "cdr-original-ext": ext,
                         "cdr-timestamp": _now()})
            except Exception as q_exc:
                logger.warning("Quarantine upload failed: key=%s error=%s", key, q_exc)
        _publish_result_safe(bucket, key, "unsupported-format",
                             {"reason": f"unsupported extension: {ext}", "original_ext": ext})
        _delete_source_safe(bucket, key)
        return {"status": "unsupported-format", "reason": f"unsupported extension: {ext}"}

    # ── CDR dispatch ──────────────────────────────────────────────────────────
    try:
        if ext in OFFICE_EXTS:
            clean_bytes, report = cdr_office(file_bytes, ext)
        elif ext == "pdf":
            clean_bytes, report = cdr_pdf(file_bytes)
        else:  # one of the image extensions, per the guard above
            clean_bytes, report = cdr_image(file_bytes, ext)
    except Exception as exc:
        logger.exception("CDR processing failed: key=%s error=%s", key, exc)
        if QUARANTINE_BUCKET:
            try:
                _upload(QUARANTINE_BUCKET, f"error/{key}", file_bytes, content_type,
                        {"cdr-status": "error", "cdr-error": str(exc)[:256]})
            except Exception as q_exc:
                logger.warning("Quarantine upload failed: key=%s error=%s", key, q_exc)
        _publish_result_safe(bucket, key, "error", {"error": str(exc), "original_ext": ext})
        raise

    # ── Upload sanitised output ───────────────────────────────────────────────
    dest_key              = _sanitised_key(key, sanitised_ext)
    cdr_mode              = report.get("cdr_mode", "full")
    sanitised_content_type = _content_type_for_ext(sanitised_ext, content_type)
    removal_count         = len(report.get("removed", []))

    _upload(
        SANITISED_BUCKET, dest_key, clean_bytes, sanitised_content_type,
        {
            "cdr-status":       "sanitised",
            "cdr-source":       f"s3://{bucket}/{key}",
            "cdr-timestamp":    _now(),
            "cdr-removals":     str(removal_count),
            "cdr-original-ext": ext,
            "cdr-zip-anomaly":  "true" if zip_anomalies else "false",
            "cdr-mode":         cdr_mode,
        },
    )

    logger.info("CDR complete: key=%s dest=%s ext=%s removals=%d mode=%s",
                key, dest_key, ext, removal_count, cdr_mode)

    result_payload = {
        "original_ext":  ext,
        "sanitised_ext": sanitised_ext,
        "cdr_mode":      cdr_mode,
        "zip_anomalies": zip_anomalies,
        "report":        report,
    }
    _publish_result_safe(bucket, key, "sanitised", result_payload)
    _delete_source_safe(bucket, key)

    return {
        "status":      "sanitised",
        "destination": f"s3://{SANITISED_BUCKET}/{dest_key}",
        "report":      result_payload,
    }


# ── Office CDR ─────────────────────────────────────────────────────────────────

def _postscript_override_parts(ct_xml: bytes) -> set[str]:
    """Parse ``[Content_Types].xml`` and return the set of normalised part names (lower,
    leading '/' stripped) declared with a PostScript/EPS content type via an ``Override``.

    This is the authoritative signal for the part-byte strip: an OOXML ``Override`` binds a
    content type to an exact PartName regardless of file extension, so an EPS payload can be
    declared PostScript while stored as ``word/media/image1.png``. The ``.eps``/``.ps``
    suffix rule in STRIP_ZIP_ENTRIES would miss that; this closes the bypass. Returns an
    empty set on unparseable XML (the ZIP validator already requires a present, well-formed
    Content-Types part, and the suffix rule remains as a backstop)."""
    parts: set[str] = set()
    try:
        root = ET.fromstring(ct_xml)
    except ET.ParseError:
        return parts
    ns = "http://schemas.openxmlformats.org/package/2006/content-types"
    for child in root:
        if child.tag != f"{{{ns}}}Override":
            continue
        if not _is_postscript_ct(child.get("ContentType", "")):
            continue
        pn = child.get("PartName", "").replace("\\", "/").lstrip("/").lower()
        if pn:
            parts.add(pn)
    return parts


def cdr_office(data: bytes, ext: str) -> tuple[bytes, dict]:
    """Disarm an OOXML (ZIP) Office file by rebuilding the archive entry-by-entry.

    Drops dangerous parts (VBA, ActiveX, embeddings, external links, …), scrubs the
    surviving `.rels`, `[Content_Types].xml`, and XML parts, and dispatches xlsb worksheet
    binaries to ``cdr_xlsb``. Never re-serialises through an Office library, so anything
    not explicitly touched is preserved byte-for-byte.

    Returns ``(clean_bytes, report)`` where report is ``{"format", "removed", "cdr_mode"}``.
    """
    removed: list[str] = []
    out_buf = io.BytesIO()

    with zipfile.ZipFile(io.BytesIO(data), "r") as src:
        # Pre-pass: resolve which parts [Content_Types].xml declares as PostScript via an
        # Override on an arbitrary PartName. infolist() order is not guaranteed, so this
        # must run before the main loop to drop such parts wherever they appear.
        ps_parts: set[str] = set()
        for item in src.infolist():
            if item.filename.replace("\\", "/").lower() == "[content_types].xml":
                try:
                    ps_parts = _postscript_override_parts(_read_zip_entry_safe(src, item))
                except ValueError:
                    ps_parts = set()  # bomb-guard trip; suffix rule remains the backstop
                break

        with zipfile.ZipFile(out_buf, "w", compression=zipfile.ZIP_DEFLATED) as dst:
            for item in src.infolist():
                # Normalise backslashes: spec mandates forward slashes
                name_lower = item.filename.replace("\\", "/").lower()

                # 1. Drop entries matching dangerous file/prefix patterns
                skip = False
                for pattern in STRIP_ZIP_ENTRIES:
                    if pattern.endswith("/"):
                        if name_lower.startswith(pattern.lower()):
                            removed.append(item.filename)
                            skip = True
                            break
                    else:
                        if name_lower.endswith(pattern.lower()):
                            removed.append(item.filename)
                            skip = True
                            break
                if skip:
                    continue

                # 1b. Drop parts declared PostScript/EPS by an Override (content-type
                #     -driven, regardless of file extension — closes the Override bypass).
                if name_lower in ps_parts:
                    removed.append(item.filename)
                    continue

                # 2. Drop ActiveX control bins/xmls
                if re.search(r"activex/activex\d*\.(bin|xml)$", name_lower):
                    removed.append(item.filename)
                    continue

                # 3. Decompression bomb guard — read in chunks to catch falsified file_size
                raw = _read_zip_entry_safe(src, item)

                # 4. Sanitise [Content_Types].xml
                if name_lower == "[content_types].xml":
                    raw, ct_removed = _sanitise_content_types(raw)
                    removed.extend(ct_removed)

                # 5. Scrub relationship files
                elif name_lower.endswith(".rels"):
                    raw, rels_removed = _strip_rels(raw)
                    removed.extend(rels_removed)

                # 6. Scrub macro attributes from XML content
                elif name_lower.endswith(".xml"):
                    raw, xml_removed = _strip_xml_macros(raw, item.filename)
                    removed.extend(xml_removed)

                # 7. xlsb worksheet binary — convert the whole file via cdr_xlsb()
                #    rather than attempting ZIP-level surgery on BIFF12 records. Only
                #    worksheet binaries (xl/worksheets/sheet*.bin) trigger conversion;
                #    other .bin parts (e.g. xl/workbook.bin metadata) must not divert a
                #    VBA-only/metadata-only xlsb away from the normal ZIP CDR path.
                elif (
                    ext == "xlsb"
                    and name_lower.startswith("xl/worksheets/sheet")
                    and name_lower.endswith(".bin")
                ):
                    return cdr_xlsb(data)

                dst.writestr(item, raw)

    return out_buf.getvalue(), {"format": ext, "removed": removed, "cdr_mode": "full"}


def cdr_xlsb(data: bytes) -> tuple[bytes, dict]:
    """Convert an xlsb file to clean xlsx by extracting cell values via pyxlsb
    and re-serialising with openpyxl. Strips all BIFF12 formula records, DDE
    references, external links, VBA, and metadata — only plain cell values survive.

    Security notes:
    - String values starting with '=' are forced to plain text to prevent openpyxl
      from serialising them as live formulas in the output xlsx.
    - Each xlsb ZIP entry is read through _read_zip_entry_safe before pyxlsb processes
      the file, enforcing the same decompression-bomb limit as the standard ZIP CDR path.
    """
    removed = ["BIFF12 binary sheet(s) converted to xlsx (all formulas, DDE, and active content stripped)"]

    # Enforce per-entry decompression limit on the xlsb ZIP before handing to pyxlsb.
    # pyxlsb reads entries internally, bypassing _read_zip_entry_safe — pre-reading
    # all entries here ensures a decompression bomb cannot OOM the Lambda.
    with zipfile.ZipFile(io.BytesIO(data), "r") as _zf:
        for _item in _zf.infolist():
            _read_zip_entry_safe(_zf, _item)  # raises ValueError if entry > _MAX_ENTRY_BYTES

    wb_out = openpyxl.Workbook(write_only=False)
    wb_out.remove(wb_out.active)  # remove default empty sheet

    with pyxlsb.open_workbook(io.BytesIO(data)) as wb_in:
        for sheet_name in wb_in.sheets:
            ws_out = wb_out.create_sheet(title=sheet_name)
            with wb_in.get_sheet(sheet_name) as ws_in:
                for row in ws_in.rows(sparse=True):
                    if not row:
                        continue
                    max_col = max(cell.c for cell in row)
                    out_row: list = [None] * (max_col + 1)
                    for cell in row:
                        v = cell.v
                        # Force string cells starting with '=' to plain text.
                        # openpyxl treats any cell value beginning with '=' as a formula
                        # expression. A crafted xlsb can carry a FORMULA_STRING cached
                        # result like '=DDE("cmd","/c calc")' which would be serialised
                        # as a live <f> element. Prefixing with a leading apostrophe is
                        # the standard Excel "force-text" convention and prevents this.
                        if isinstance(v, str) and v.startswith("="):
                            v = "'" + v
                        out_row[cell.c] = v
                    ws_out.append(out_row)

    out_buf = io.BytesIO()
    wb_out.save(out_buf)
    return out_buf.getvalue(), {
        "format": "xlsb",
        "converted_to": "xlsx",
        "removed": removed,
        "cdr_mode": "full",
    }


def _read_zip_entry_safe(src: zipfile.ZipFile, item: zipfile.ZipInfo) -> bytes:
    """Read a ZIP entry in chunks, raising if the actual decompressed size exceeds the limit.
    Does not trust item.file_size which can be falsified in the central directory."""
    chunks: list[bytes] = []
    total = 0
    with src.open(item) as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_ENTRY_BYTES:
                raise ValueError(
                    f"ZIP entry '{item.filename}' exceeds decompression limit {_MAX_ENTRY_BYTES}"
                )
            chunks.append(chunk)
    return b"".join(chunks)


def _strip_rels(data: bytes) -> tuple[bytes, list[str]]:
    """Scrub an OPC ``.rels`` part: drop relationships of dangerous types (VBA, OLE,
    external links, altChunk, …) and rewrite external hyperlink Targets to inert while
    keeping the rel (so the document's ``r:id`` references don't dangle).

    Returns ``(rels_bytes, removed)``; unparseable XML is returned unchanged.
    """
    removed: list[str] = []
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return data, removed

    ns = "http://schemas.openxmlformats.org/package/2006/relationships"
    to_remove = []
    for child in list(root):
        rel_type = child.get("Type", "")
        if rel_type in STRIP_REL_TYPES:
            to_remove.append(child)
            removed.append(f"rel:{child.get('Id')} type={rel_type.split('/')[-1]}")
            continue

        # External hyperlinks: neutralise the Target in place rather than deleting the rel
        # (deleting would dangle the document's r:id reference). UNC targets (\\host\share)
        # leak NTLM credentials; arbitrary URLs enable phishing/SSRF on click.
        if (
            rel_type == HYPERLINK_REL_TYPE
            and child.get("TargetMode") == "External"
            and child.get("Target")
        ):
            child.set("Target", "https://_CDR_REMOVED_/")
            removed.append(f"rel:{child.get('Id')} external hyperlink target neutralised")

    for child in to_remove:
        root.remove(child)

    ET.register_namespace("", ns)
    return ET.tostring(root, encoding="unicode", xml_declaration=False).encode(), removed


def _sanitise_content_types(data: bytes) -> tuple[bytes, list[str]]:
    """Rewrite ``[Content_Types].xml``: remap macro-enabled OPC part content types to
    their clean equivalents (both the ``*.main+xml`` Override and ``.12`` Default forms)
    and drop VBA/ActiveX Default entries.

    Returns ``(content_types_bytes, removed)``; unparseable XML is returned unchanged.
    """
    removed: list[str] = []
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return data, removed

    ns = "http://schemas.openxmlformats.org/package/2006/content-types"
    ET.register_namespace("", ns)

    to_remove = []
    for child in list(root):
        ct = child.get("ContentType", "")

        if ct in MACRO_CONTENT_TYPE_REMAP:
            child.set("ContentType", MACRO_CONTENT_TYPE_REMAP[ct])
            removed.append(f"content-type replaced: {ct.split('.')[-1]}")

        elif child.tag == f"{{{ns}}}Default" and (
            "vba" in ct.lower() or "activex" in ct.lower()
        ):
            to_remove.append(child)
            removed.append(f"content-type removed: {ct}")

        elif child.tag == f"{{{ns}}}Override" and "activex" in ct.lower():
            to_remove.append(child)
            removed.append(f"content-type removed: {ct}")

        # PostScript/EPS parts declare a Turing-complete interpreter language (the
        # GhostScript -dSAFER bypass family is real history). Drop the declaration in
        # both Default and Override forms. Part bytes are dropped by STRIP_ZIP_ENTRIES
        # (suffix) AND by the content-type-driven pre-pass in cdr_office (which catches a
        # PostScript Override on an arbitrarily-named part, e.g. /word/media/image1.png).
        elif _is_postscript_ct(ct):
            to_remove.append(child)
            removed.append(f"content-type removed: {ct}")

    for child in to_remove:
        root.remove(child)

    return ET.tostring(root, encoding="unicode", xml_declaration=False).encode(), removed


# Field-code keywords that are dangerous regardless of arguments. Used to decide whether
# a run of entity-encoded characters decodes to a threat that must be neutralised.
_ENCODED_FIELD_KEYWORDS = (
    "AUTOOPEN", "AUTOEXIT", "AUTOCLOSE", "AUTONEW", "MACROBUTTON", "DDEAUTO", "DDE",
    "EXEC", "INCLUDETEXT", "INCLUDEPICTURE", "INCLUDE", "WEBSERVICE", "HYPERLINK",
    "RTD", "CALL", "REGISTER", "LINK",
)

# A run of ASCII letters and/or numeric character references, e.g. &#68;&#68;&#69; or
# &#77;ACROBUTTON (partial encoding). Such a run only ever spans plain text — never markup
# — so neutralising it cannot corrupt XML structure or disturb legitimate single escapes
# like &amp; (which decodes to '&', not a letter, so it is not absorbed into a run).
#
# A SINGLE quantified alternation `(?:A|B)+` is used deliberately: the earlier form with
# two unbounded `(?:...)*` groups around a required token had quadratic backtracking
# (a long letter run with no '&#...;' made .sub() retry from every index → ReDoS). The
# `_replace` callback applies the "must contain an actual numeric reference" condition
# instead of the regex, so correctness is preserved without the backtracking shape.
_NUMERIC_ENTITY_RUN = re.compile(r'(?:[A-Za-z]|&#[xX]?[0-9a-fA-F]+;)+')


def _neutralise_encoded_field_codes(text: str) -> tuple[str, int]:
    """Strip entity-encoded field-code keywords without decoding the whole document.

    Returns (text, count). Only runs that actually contain a numeric character reference
    AND decode to a dangerous keyword are replaced; everything else — including benign
    single escapes such as ``&amp;`` and plain words — is left byte-for-byte unchanged.
    """
    if "&#" not in text:  # cheap short-circuit: no numeric references → nothing to do
        return text, 0
    count = 0

    def _replace(match: "re.Match[str]") -> str:
        nonlocal count
        run = match.group(0)
        if "&#" not in run:  # a pure-letter run is never an encoded keyword
            return run
        if any(kw in html.unescape(run).upper() for kw in _ENCODED_FIELD_KEYWORDS):
            count += 1
            return "_CDR_REMOVED_"
        return run

    return _NUMERIC_ENTITY_RUN.sub(_replace, text), count


def _strip_xml_macros(data: bytes, filename: str) -> tuple[bytes, list[str]]:
    """Neutralise dangerous content inside an Office XML part via text-level regex passes.

    Covers: entity-encoded field codes (e.g. ``&#68;&#68;&#69;`` = DDE), auto-exec and
    keyword+argument field codes (AUTOOPEN, DDE, WEBSERVICE, …), ``onClick``/``onAction``
    action attributes, the DDE pipe form (``cmd|'/c calc'!A1``), and ``<w:altChunk>``
    imports. Matches in place (replacing with ``_CDR_REMOVED_``) so XML structure and
    benign escapes like ``&amp;`` survive — it never decodes the whole part.

    Returns ``(xml_bytes, removed)``.
    """
    removed: list[str] = []
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return data, removed

    # Neutralise entity-encoded field codes (e.g. &#68;&#68;&#69; = "DDE") WITHOUT
    # decoding the whole document. Word entity-decodes content before evaluating field
    # codes, so an attacker can hide a keyword inside numeric character references. A
    # numeric character reference only ever encodes a single text character — never XML
    # markup — so collapsing a run of them and checking whether it decodes to a dangerous
    # keyword lets us strip the threat while leaving legitimate escapes like &amp; intact.
    text, n_ent = _neutralise_encoded_field_codes(text)
    if n_ent:
        removed.append(f"{filename}: {n_ent} entity-encoded field code(s)")

    # Auto-execute names that carry no argument (AUTOOPEN fires on document open, etc.)
    cleaned, n_auto = re.subn(
        r'\b(AUTOOPEN|AUTOEXIT|AUTOCLOSE|AUTONEW)\b',
        r'\1_CDR_REMOVED_',
        text,
        flags=re.IGNORECASE,
    )
    # Keyword + argument form: neutralise the argument, preserving field structure.
    # INCLUDE/INCLUDETEXT/INCLUDEPICTURE/LINK — fetch external resources (SSRF/exfil).
    # WEBSERVICE — auto-fetches a URL when document opens, direct SSRF; the no-parens
    #   Word field form is not caught by the n3 pattern which requires '('.
    # HYPERLINK — UNC paths trigger NTLM credential theft; include the no-parens form.
    cleaned, n_kw = re.subn(
        r'\b(MACROBUTTON|DDE|DDEAUTO|AUTO|EXEC|INCLUDE|INCLUDETEXT|INCLUDEPICTURE|LINK'
        r'|WEBSERVICE|HYPERLINK)\s+\S+',
        r'\1 _CDR_REMOVED_',
        cleaned,
        flags=re.IGNORECASE,
    )
    n = n_auto + n_kw
    if n:
        removed.append(f"{filename}: {n} dangerous field code(s)")

    cleaned, n2 = re.subn(
        r'''\b(onClick|onAction|r:link|r:action)=(?:"[^"]*"|'[^']*')''',
        '',
        cleaned,
    )
    if n2:
        removed.append(f"{filename}: {n2} action attribute(s)")

    # altChunk imports an external HTML/MHTML/RTF chunk into the document; the imported
    # content bypasses every field/macro scrub (which only sees the host part). The
    # aFChunk relationship is dropped in STRIP_REL_TYPES, but also rename the element so
    # the import cannot fire even if a rel survives. Handles both <w:altChunk .../> and
    # paired <w:altChunk>…</w:altChunk> by neutralising the tag name.
    cleaned, n_alt = re.subn(
        r'(<|</)\s*[A-Za-z0-9]*:?altChunk\b',
        r'\1_CDR_REMOVED_altChunk',
        cleaned,
        flags=re.IGNORECASE,
    )
    if n_alt:
        removed.append(f"{filename}: {n_alt} altChunk import(s) neutralised")

    # DDE pipe pattern allows spaces in the argument (e.g. cmd|' /c calc'!A1). The app
    # name before the pipe may be bare, double-quoted, single-quoted, or bracketed —
    # Excel accepts "cmd"|, 'cmd'|, and [cmd]| forms, so all must be neutralised.
    #
    # Quantifiers are BOUNDED ({1,64} / {1,256}) to prevent quadratic backtracking: an
    # unbounded app-name alternative followed by unbounded [^!]+ with no '!suffix' made
    # the engine retry O(n^2) on a long `a…|b…` string → ReDoS. The argument also excludes
    # '<' and '>' so a match cannot span an XML tag boundary and corrupt structure.
    #
    # The post-'!' item is anchored to an EXCEL CELL REFERENCE shape (A1 / $B$2 / R1C1)
    # rather than any word — a real DDE link target is always a cell ref. This avoids the
    # false positive on benign prose like "Profit|Loss!Important" (which would otherwise be
    # corrupted to an unbalanced "_CDR_REMOVED_(").
    cleaned, n3 = re.subn(
        r"\b(WEBSERVICE|RTD|HYPERLINK|DDE|DDEAUTO|CALL|REGISTER)\s*\("
        r'|(?:"[^"]{1,256}"|\'[^\']{1,256}\'|\[[^\]]{1,256}\]|[^\s\[\]"\'|<>]{1,64})'
        r'\|[^!<>]{1,256}!(?:\$?[A-Za-z]{1,3}\$?[0-9]{1,7}|R[0-9]{1,7}C[0-9]{1,7})\b',
        '_CDR_REMOVED_',
        cleaned,
        flags=re.IGNORECASE,
    )
    if n3:
        removed.append(f"{filename}: {n3} dangerous formula/DDE reference(s)")

    return cleaned.encode("utf-8"), removed


# ── PDF CDR ────────────────────────────────────────────────────────────────────

def cdr_pdf(data: bytes) -> tuple[bytes, dict]:
    """Disarm a PDF with pikepdf: remove catalog-level active content (``/OpenAction``,
    ``/AA``, JavaScript, ``/Names./EmbeddedFiles``), sweep AcroForm fields and root, walk
    pages (all annotation ``/A``/``/AA``, ``/FileAttachment`` file specs, multimedia
    subtypes) and the outline tree, then re-serialise via ``pdf.save()`` — which also
    drops any appended/polyglot bytes.

    Returns ``(clean_bytes, {"format": "pdf", "removed": [...]})``.
    """
    removed: list[str] = []

    with pikepdf.open(io.BytesIO(data)) as pdf:
        catalog = pdf.Root

        for dangerous_key in ("/OpenAction", "/AA", "/JavaScript", "/JS", "/Names", "/AcroForm"):
            if dangerous_key in catalog:
                if dangerous_key == "/AcroForm":
                    acroform = catalog["/AcroForm"]
                    # /AA (Additional Actions) on the AcroForm root fires JavaScript on
                    # form calculate/focus — strip it here; the catalog-level /AA loop
                    # above only covers catalog["/AA"], not the AcroForm dict's own.
                    for action_key in ("/XFA", "/CO", "/AA"):
                        if action_key in acroform:
                            del acroform[action_key]
                            removed.append(f"AcroForm{action_key}")
                    removed.extend(_strip_acroform_fields(acroform.get("/Fields", [])))
                elif dangerous_key == "/Names":
                    _DANGEROUS_NAMES = {"/JavaScript", "/EmbeddedFiles", "/AlternatePresentations"}
                    names_dict = catalog["/Names"]
                    for name_key in _DANGEROUS_NAMES:
                        if name_key in names_dict:
                            del names_dict[name_key]
                            removed.append(f"/Names.{name_key}")
                else:
                    del catalog[dangerous_key]
                    removed.append(dangerous_key)

        for page_num, page in enumerate(pdf.pages):
            removed.extend(_strip_pdf_page(page, page_num))

        removed.extend(_strip_pdf_outlines(catalog))

        if "/Metadata" in catalog:
            del catalog["/Metadata"]
            removed.append("/Metadata")
        try:
            if pdf.docinfo:
                pdf.docinfo.clear()
                removed.append("/Info")
        except Exception as exc:
            logger.warning("Could not clear PDF docinfo: %s", exc)

        out_buf = io.BytesIO()
        pdf.save(out_buf)

    return out_buf.getvalue(), {"format": "pdf", "removed": removed}


def _strip_pdf_page(page, page_num: int) -> list[str]:
    """Strip active content from one PDF page: the page ``/AA``, plus every annotation's
    ``/A``/``/AA`` actions, ``/FileAttachment`` file specs, and multimedia subtypes.
    Returns the list of removals (for the report)."""
    removed: list[str] = []

    if "/AA" in page:
        del page["/AA"]
        removed.append(f"page[{page_num}]/AA")

    # Multimedia annotation subtypes carry executable/remote payloads in /RichMediaContent,
    # /Movie, /Sound dicts that the action sweep never inspects. Neutralise the subtype so
    # the viewer treats the annotation as inert (the visual rectangle remains).
    MULTIMEDIA_SUBTYPES = {"/RichMedia", "/Screen", "/3D", "/Movie", "/Sound"}
    if "/Annots" in page:
        for annot in page["/Annots"]:
            try:
                subtype = annot.get("/Subtype")
                # /FileAttachment annotations embed a file directly on the page via a
                # /FS file specification — a smuggling path around the catalog-level
                # /Names./EmbeddedFiles strip. Scrub the file spec so nothing extractable
                # remains; the visible annotation is left as an inert marker.
                if subtype == "/FileAttachment":
                    for fs_key in ("/FS", "/EF"):
                        if fs_key in annot:
                            del annot[fs_key]
                    removed.append(f"page[{page_num}] FileAttachment file spec")
                if subtype in MULTIMEDIA_SUBTYPES:
                    for mm_key in ("/RichMediaContent", "/RichMediaSettings", "/Movie", "/Sound"):
                        if mm_key in annot:
                            del annot[mm_key]
                    annot["/Subtype"] = pikepdf.Name("/CDRRemoved")
                    removed.append(f"page[{page_num}] {subtype} multimedia annotation")
                # Delete every action unconditionally. The action denylist approach left
                # gaps (/GoToE, /Rendition, /SetOCGState, …); a CDR tool should drop ALL
                # annotation actions — the visual annotation stays inert, consistent with
                # how _strip_acroform_fields already treats form fields.
                if "/A" in annot:
                    del annot["/A"]
                    removed.append(f"page[{page_num}] annot/A")
                if "/AA" in annot:
                    del annot["/AA"]
                    removed.append(f"page[{page_num}] annot/AA")
            except Exception as exc:
                logger.debug("Skipped malformed annotation on page %d: %s", page_num, exc)

    return removed


def _strip_pdf_outlines(catalog) -> list[str]:
    """Walk the document outline (bookmark) tree, deleting /A and /AA actions. An outline
    item's action (/JavaScript, /Launch, …) fires on bookmark click and is never reached
    by the page/annotation/AcroForm sweeps."""
    removed: list[str] = []
    if "/Outlines" not in catalog:
        return removed

    seen: set = set()

    def _walk(node, depth: int) -> None:
        # Depth + identity guard against malicious cyclic /Next or /First chains.
        if node is None or depth > 1000:
            return
        try:
            ident = node.objgen
        except Exception:
            ident = None
        if ident is not None:
            if ident in seen:
                return
            seen.add(ident)
        try:
            for action_key in ("/A", "/AA"):
                if action_key in node:
                    del node[action_key]
                    removed.append(f"outline{action_key}")
            child = node.get("/First")
            if child is not None:
                _walk(child, depth + 1)
            nxt = node.get("/Next")
            if nxt is not None:
                _walk(nxt, depth + 1)
        except Exception as exc:
            logger.debug("Skipped malformed outline node: %s", exc)

    try:
        _walk(catalog["/Outlines"].get("/First"), 0)
    except Exception as exc:
        logger.debug("Could not walk outlines: %s", exc)
    return removed


def _strip_acroform_fields(fields) -> list[str]:
    """Recursively strip dangerous action keys from AcroForm field/widget dicts."""
    removed: list[str] = []
    try:
        for field in fields:
            try:
                for key in ("/A", "/AA", "/JS", "/JavaScript"):
                    if key in field:
                        del field[key]
                        removed.append(f"AcroForm field {key}")
                if "/Kids" in field:
                    removed.extend(_strip_acroform_fields(field["/Kids"]))
            except Exception as exc:
                logger.debug("Skipped malformed AcroForm field: %s", exc)
    except Exception as exc:
        logger.debug("Could not iterate AcroForm fields: %s", exc)
    return removed


# ── Image CDR ──────────────────────────────────────────────────────────────────

def cdr_image(data: bytes, ext: str) -> tuple[bytes, dict]:
    """Re-encode an image through Pillow to produce a pixel-only copy, discarding all
    metadata channels (EXIF/ICC/XMP, GIF comment blocks). Multi-frame TIFFs are
    re-encoded frame-by-frame so metadata is stripped from every frame; the output keeps
    the original format/Content-Type.

    Returns ``(clean_bytes, {"format", "removed", "original_bytes", "sanitised_bytes"})``.
    """
    removed: list[str] = []
    original_size = len(data)

    fmt_map = {"jpg": "JPEG", "jpeg": "JPEG", "png": "PNG",
               "bmp": "BMP", "tiff": "TIFF", "webp": "WEBP", "gif": "GIF"}
    save_fmt = fmt_map.get(ext, "PNG")

    with Image.open(io.BytesIO(data)) as img:
        if img.info.get("exif") or img.info.get("IFD"):
            removed.append("EXIF")
        if "icc_profile" in img.info:
            removed.append("ICC profile")
        if "xmp" in img.info:
            removed.append("XMP")
        if img.info.get("comment"):
            removed.append("comment")

        n_frames = getattr(img, "n_frames", 1)
        out_buf = io.BytesIO()

        if save_fmt == "TIFF" and n_frames > 1:
            # Re-encode every frame through Pillow to produce a pixel-only multi-frame TIFF.
            # Iterating via ImageSequence ensures each frame is decoded independently and
            # no IFD tags or per-frame metadata survive the round-trip.
            frames = [frame.convert("RGB").copy()
                      for frame in ImageSequence.Iterator(img)]
            frames[0].save(
                out_buf, format="TIFF",
                save_all=True, append_images=frames[1:],
            )
            removed.append(f"multi-frame TIFF metadata ({n_frames} frames re-encoded)")
        else:
            target_mode = "RGBA" if (ext == "png" and img.mode in ("RGBA", "LA", "PA")) else "RGB"
            clean_img = img.convert(target_mode)

            save_kwargs: dict = {}
            if save_fmt == "JPEG":
                save_kwargs = {"quality": 95, "optimize": True}
            elif save_fmt == "PNG":
                save_kwargs = {"optimize": True}
            elif save_fmt == "GIF":
                # Explicitly suppress comment extension blocks — Pillow carries them
                # through re-encode unless overridden.
                save_kwargs = {"comment": b""}

            clean_img.save(out_buf, format=save_fmt, **save_kwargs)

        new_size = out_buf.tell()

    return out_buf.getvalue(), {
        "format":          ext,
        "removed":         removed,
        "original_bytes":  original_size,
        "sanitised_bytes": new_size,
    }


# ── Helpers ────────────────────────────────────────────────────────────────────

def _download(bucket: str, key: str) -> tuple[bytes, str]:
    """Fetch an S3 object, returning ``(body, content_type)``. Raises ``ValueError`` if
    the object's ``ContentLength`` exceeds ``_MAX_FILE_BYTES`` (a download-time size guard,
    independent of the pre-download EventBridge check)."""
    resp = s3.get_object(Bucket=bucket, Key=key)
    # Defence-in-depth against a post-event object swap: the EventBridge size field is
    # checked pre-download, but the object could be replaced before we read it. Trust the
    # S3 response headers, not the event, and refuse to buffer a multi-GB body into the
    # 1024 MB container. A terminal ValueError here exhausts retries into the DLQ (alarmed)
    # rather than OOM-crashing mid-read.
    content_length = resp.get("ContentLength", 0)
    if content_length > _MAX_FILE_BYTES:
        raise ValueError(
            f"S3 object content length {content_length} exceeds max {_MAX_FILE_BYTES}"
        )
    return resp["Body"].read(), resp["ContentType"]


def _classify_download_error(bucket: str, key: str, exc: Exception) -> None:
    """Log a structured message distinguishing NoSuchKey from other download failures."""
    from botocore.exceptions import ClientError
    if isinstance(exc, ClientError) and exc.response["Error"]["Code"] == "NoSuchKey":
        logger.warning("Source object not found (possible race/double-process): bucket=%s key=%s", bucket, key)
        _publish_result_safe(bucket, key, "source-missing", {"reason": "NoSuchKey"})
    else:
        logger.error("Download failed: bucket=%s key=%s error=%s", bucket, key, exc)


# S3 permits letters, digits, spaces, and + - = . _ : / @ in a tag key/value, and the
# value must be the LITERAL string (percent-encoding is rejected as InvalidTag). But the
# Tagging request is a `k=v&k=v` query string, so '=' and '&' inside a value break parsing
# (InvalidArgument) and could let an attacker-controlled filename inject extra pairs.
# We therefore allow S3's set MINUS '=' and '&', replacing anything else with '_'.
_TAG_SAFE = re.compile(r"[^A-Za-z0-9 +\-._:/@]")


def _enc_tag(value: str, limit: int) -> str:
    """Make a string safe to use as an S3 object-tag key/value: replace any character
    outside S3's allowed set with '_' (this also neutralises '&'/'=' injection), then cap
    at ``limit`` chars (S3 allows 128 for keys, 256 for values)."""
    return _TAG_SAFE.sub("_", value)[:limit]


def _upload(bucket: str, key: str, data: bytes,
            content_type: str, tags: dict[str, str]) -> None:
    """Put an object to S3 with AES256 encryption and a sanitised tag set. Tag keys/values
    are reduced to S3's allowed character set (see ``_enc_tag``), which also prevents
    ``&``/``=`` tag-pair injection from an attacker-controlled filename."""
    tag_str = "&".join(
        f"{_enc_tag(k, 128)}={_enc_tag(v, 256)}" for k, v in tags.items()
    )
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=data,
        ContentType=content_type,
        Tagging=tag_str,
        ServerSideEncryption="AES256",
    )


_EXT_CONTENT_TYPE: dict[str, str] = {
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "dotx": "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "xltx": "application/vnd.openxmlformats-officedocument.spreadsheetml.template",
    "xlsb": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "potx": "application/vnd.openxmlformats-officedocument.presentationml.template",
    "ppsx": "application/vnd.openxmlformats-officedocument.presentationml.slideshow",
    "pdf":  "application/pdf",
    "jpg":  "image/jpeg",
    "jpeg": "image/jpeg",
    "png":  "image/png",
    "gif":  "image/gif",
    "bmp":  "image/bmp",
    "tiff": "image/tiff",
    "webp": "image/webp",
}


def _content_type_for_ext(ext: str, fallback: str) -> str:
    """Map an extension to its canonical MIME type, or return ``fallback`` if unknown."""
    return _EXT_CONTENT_TYPE.get(ext, fallback)


def _sanitised_key(key: str, sanitised_ext: Optional[str] = None) -> str:
    """Build the destination key under the ``sanitised/`` prefix, optionally swapping the
    extension (e.g. ``docm`` → ``docx`` after macro removal)."""
    if sanitised_ext and "." in key:
        base = key.rsplit(".", 1)[0]
        key  = f"{base}.{sanitised_ext}"
    return f"sanitised/{key}"


def _now() -> str:
    """Current UTC time as an ISO-8601 string (used in result/tag timestamps)."""
    return datetime.now(timezone.utc).isoformat()


# SNS hard limit is 256 KB. Leave headroom for the envelope (source/status/timestamp
# keys, JSON structure) and for multi-byte UTF-8 expansion of attacker-controlled names.
_SNS_REMOVED_BYTE_BUDGET = 200 * 1024


def _cap_removed_by_bytes(items: list, budget: int) -> list:
    """Trim a 'removed' list so its JSON-serialised size stays within budget bytes.

    Entry names are attacker-controlled and can be tens of KB each, so a fixed entry
    count is not enough to keep an SNS message under 256 KB — bound by serialised size.
    """
    kept: list = []
    used = 0
    for i, entry in enumerate(items):
        size = len(json.dumps(entry)) + 1  # +1 for the comma separator
        if used + size > budget:
            kept.append(f"... and {len(items) - i} more (truncated)")
            return kept
        kept.append(entry)
        used += size
    return kept


def _truncate_removed(d: dict) -> dict:
    """Return a copy of d with any 'removed' list capped at 100 entries AND bounded by
    serialised byte size, at any nesting level, so the SNS message stays under 256 KB."""
    d = dict(d)
    if isinstance(d.get("removed"), list):
        capped = d["removed"]
        if len(capped) > 100:
            capped = capped[:100] + [f"... and {len(d['removed']) - 100} more"]
        d["removed"] = _cap_removed_by_bytes(capped, _SNS_REMOVED_BYTE_BUDGET)
    if isinstance(d.get("report"), dict):
        inner = d["report"]
        if isinstance(inner.get("removed"), list):
            inner = dict(inner)
            capped = inner["removed"]
            if len(capped) > 100:
                capped = capped[:100] + [f"... and {len(inner['removed']) - 100} more"]
            inner["removed"] = _cap_removed_by_bytes(capped, _SNS_REMOVED_BYTE_BUDGET)
            d["report"] = inner
    return d


def _publish_result_safe(source_bucket: str, key: str, status: str, report: dict) -> None:
    """Publish to SNS; on failure log a warning but never block the success/delete path."""
    if not RESULT_TOPIC_ARN:
        return
    try:
        # Inside the try: truncation/serialisation must not be able to break the
        # success/delete path either (fault isolation covers the whole publish).
        report = _truncate_removed(report)
        sns.publish(
            TopicArn=RESULT_TOPIC_ARN,
            Subject=f"CDR/{status}: {key}"[:100],
            Message=json.dumps({
                "source":    f"s3://{source_bucket}/{key}",
                "status":    status,
                "timestamp": _now(),
                "report":    report,
            }),
            MessageAttributes={
                "status": {"DataType": "String", "StringValue": status},
            },
        )
    except Exception as exc:
        logger.warning("SNS publish failed: bucket=%s key=%s status=%s error=%s",
                       source_bucket, key, status, exc)


def _delete_source_safe(bucket: str, key: str) -> None:
    """Delete source object; on failure log a warning but never raise."""
    try:
        s3.delete_object(Bucket=bucket, Key=key)
    except Exception as exc:
        logger.warning("delete_object failed (sanitised copy is safe): bucket=%s key=%s error=%s",
                       bucket, key, exc)


def _emit_zip_anomaly_metric() -> None:
    """Publish one ``CDR/Validation/ZipAnomalies`` datapoint on a ZIP structural
    hard-reject. Failure to emit is logged, never raised (metrics must not break CDR)."""
    try:
        cw.put_metric_data(
            Namespace="CDR/Validation",
            MetricData=[{"MetricName": "ZipAnomalies", "Value": 1, "Unit": "Count"}],
        )
    except Exception as exc:
        logger.warning("CloudWatch metric emission failed: %s", exc)


def _emit_passthrough_metric(ext: str) -> None:
    """Emit a metric when an unknown extension is seen (now quarantined, fail-closed).

    Emits TWO datapoints: a dimensionless rollup that CdrPassthroughAlarm watches (a
    CloudWatch alarm cannot aggregate across dimension values), plus a per-extension
    breakdown for diagnostics. The dimensionless point is mandatory — without it the
    alarm monitors a series that never receives data and stays permanently non-breaching.
    """
    try:
        cw.put_metric_data(
            Namespace="CDR/Validation",
            MetricData=[
                {"MetricName": "PassthroughFiles", "Value": 1, "Unit": "Count"},
                {"MetricName": "PassthroughFiles", "Value": 1, "Unit": "Count",
                 "Dimensions": [{"Name": "Extension", "Value": ext[:32]}]},
            ],
        )
    except Exception as exc:
        logger.warning("CloudWatch passthrough metric emission failed: %s", exc)


def _validate_zip_structure(data: bytes) -> tuple[bool, list[str]]:
    """
    Validate ZIP structural integrity before CDR.
    Returns (is_valid_zip, anomalies).
    is_valid_zip=False → hard reject (quarantine + delete source).
    """
    if len(data) < 4:
        return False, ["file too small to be a valid ZIP"]

    if data[:4] != _ZIP_MAGIC:
        return False, [f"invalid magic bytes: {data[:4].hex().upper()} (expected 504B0304)"]

    try:
        zf_ctx = zipfile.ZipFile(io.BytesIO(data), "r")
    except zipfile.BadZipFile as exc:
        return False, [f"corrupt ZIP: {exc}"]

    anomalies: list[str] = []
    with zf_ctx as zf:
        names: list[str] = []
        for info in zf.infolist():
            if info.compress_type not in _SAFE_COMPRESS_METHODS:
                return False, [
                    f"non-standard compression method {info.compress_type} "
                    f"on entry '{info.filename}'"
                ]

            try:
                raw_offset   = info.header_offset
                local_method = int.from_bytes(data[raw_offset + 8: raw_offset + 10], "little")
                if local_method != info.compress_type:
                    return False, [
                        f"compression method mismatch on '{info.filename}': "
                        f"local={local_method} central={info.compress_type}"
                    ]
            except Exception:
                pass

            names.append(info.filename)

        seen: set[str] = set()
        for name in names:
            if name in seen:
                return False, [f"duplicate ZIP entry: '{name}'"]
            seen.add(name)

        # Every OOXML package MUST contain [Content_Types].xml at the root. A ZIP that
        # lacks it is not a real Office document — reject rather than CDR-and-label it
        # "sanitised" (an arbitrary ZIP renamed .docx would otherwise pass through).
        if not any(n.replace("\\", "/").lower() == "[content_types].xml" for n in names):
            return False, ["not an OOXML package: missing [Content_Types].xml"]

    return True, anomalies
