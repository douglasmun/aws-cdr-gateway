#!/usr/bin/env python3
"""Sweep the OPC declaration mechanisms for parts CDR never scrubs.

Usage:
    /tmp/cdrvenv/bin/python tools/opc_declaration_sweep.py

Background — this is the technique that found pitfalls #54 and #55.

`cdr_office` scrubs a part when its name ends .xml/.vml, or when an Override in
[Content_Types].xml names it. OPC offers OTHER ways to bind a part to a content
type, and any mechanism CDR does not resolve is a part a real consumer executes
and CDR leaves live. #54 was the Override gap; #55 was Default-by-extension, one
layer below the #54 fix. Re-run this whenever the part-resolution logic changes.

Each case is judged by three questions, in order — skipping any of them is how a
probe lies to you:

  1. PRECONDITION: can an independent parser (python-docx) see the payload in
     the *input*? A package no consumer can open proves nothing about CDR, and
     several synthetic fixtures fail here for unrelated reasons.
  2. EXPLOITABILITY: can python-docx still see the payload in the *sanitised*
     output? Surviving bytes in an unreachable part are inert dead weight, not
     a finding. Only a payload an independent parser resolves is a bypass.
  3. ATTRIBUTION: did CDR actually report removing something? If the marker
     vanished while CDR reported no removal, something other than the scrub ate
     the payload and the audit record cannot be trusted.

Only a case that answers all three reports PASS. Anything the harness cannot
prove — a crash, an unparseable output, an unopenable input — is ERROR or SKIP
and fails the run with exit 2. Translating "could not prove" into "clean" is the
one failure mode that makes an audit tool worse than no tool at all. In
particular only `CdrReject` counts as fail-closed: the handler routes it to
quarantine/rejected, whereas a generic exception goes to quarantine/error, so
conflating the two would report a crash regression as a clean sweep.

The payload marker is DDEPAYLOADMARK, not DDEAUTO: the scrub deliberately
neutralises the executable path and leaves the inert DDEAUTO keyword behind
(pitfall #13), so grepping for the keyword reports false bypasses on correctly
sanitised files.
"""
import io
import os
import sys
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

# lambda_function builds an S3 client at MODULE SCOPE, so importing it reaches for
# real credentials. Without these, boto3's login provider raises MissingDependency
# (botocore[crt]) before a single line of CDR code runs. Same trap as tools/disarm.py.
os.environ.setdefault("SANITISED_BUCKET", "t")
os.environ.setdefault("QUARANTINE_BUCKET", "t")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "x")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "x")
os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")

import lambda_function as cdr  # noqa: E402

try:
    import docx  # noqa: E402
except ImportError:
    sys.exit("python-docx required: /tmp/cdrvenv/bin/pip install python-docx")

MARK = "DDEPAYLOADMARK"
PAYLOAD = (
    '<?xml version="1.0"?><w:document '
    'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    "<w:body><w:p><w:r><w:instrText>DDEAUTO "
    f'c:\\\\windows\\\\{MARK}.exe "/c calc"</w:instrText></w:r></w:p></w:body></w:document>'
)
WML = (
    "application/vnd.openxmlformats-officedocument."
    "wordprocessingml.document.main+xml"
)
OFFICE_REL = (
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
)


def build(part_name, ct_body, rel_target):
    """Assemble a minimal .docx binding `part_name` via the given declaration."""
    ct = (
        '<?xml version="1.0"?><Types '
        'xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType='
        '"application/vnd.openxmlformats-package.relationships+xml"/>'
        + ct_body
        + "</Types>"
    )
    rels = (
        '<?xml version="1.0"?><Relationships '
        'xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f'<Relationship Id="rId1" Type="{OFFICE_REL}" Target="{rel_target}"/>'
        "</Relationships>"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ct)
        z.writestr("_rels/.rels", rels)
        z.writestr(part_name, PAYLOAD)
    return buf.getvalue()


def visible_to_parser(raw):
    """True if python-docx resolves the part and sees the payload."""
    try:
        return MARK in docx.Document(io.BytesIO(raw)).element.xml
    except Exception:
        return None


PASS, BYPASS, SKIP, ERROR = "PASS", "BYPASS", "SKIP", "ERROR"


def check(label, raw):
    """Judge one case. Anything the harness cannot prove is ERROR, never PASS."""
    if visible_to_parser(raw) is not True:
        print(f"  SKIP     {label}")
        print("           input not resolvable by python-docx - proves nothing")
        return SKIP

    try:
        clean, report = cdr.cdr_office(raw, "docx")
    except cdr.CdrReject as exc:
        # Only a deliberate reject is fail-closed. The handler routes CdrReject to
        # quarantine/rejected but a generic exception to quarantine/error, so
        # conflating them would report a crash regression as a clean audit.
        print(f"  PASS     {label}")
        print(f"           rejected fail-closed (CdrReject: {exc})")
        return PASS
    except Exception as exc:
        print(f"  ERROR    {label}")
        print(f"           cdr_office crashed: {type(exc).__name__}: {exc}")
        print("           NOT a clean result - the payload was never scrubbed")
        return ERROR

    visible = visible_to_parser(clean)
    if visible is True:
        print(f"  BYPASS   {label}")
        print(f"           python-docx still resolves {MARK} in the OUTPUT")
        print(f"           report: {report.get('removed', [])!r}")
        return BYPASS
    if visible is None:
        # The oracle failed, so exploitability is unknown. A corrupt output, or one
        # python-docx rejects while another Office consumer opens, must not read as
        # clean - parser disagreement is this project's recurring bug class.
        print(f"  ERROR    {label}")
        print("           python-docx could not parse the OUTPUT - exploitability unknown")
        return ERROR

    removed = report.get("removed", [])
    if not removed:
        # The marker vanished but CDR claims it removed nothing. Something other than
        # the scrub ate the payload, so the audit record cannot be trusted.
        print(f"  ERROR    {label}")
        print("           payload gone but CDR reported no removal - unexplained")
        return ERROR

    print(f"  PASS     {label}")
    print(f"           payload no longer resolvable; removed={len(removed)}")
    return PASS


CASES = [
    (
        "Override names the part (pitfall #54)",
        "word/document.bin",
        f'<Override PartName="/word/document.bin" ContentType="{WML}"/>',
        "word/document.bin",
    ),
    (
        "Default binds the extension, no Override (pitfall #55)",
        "word/document.bin",
        f'<Default Extension="bin" ContentType="{WML}"/>',
        "word/document.bin",
    ),
    (
        "Default on an unusual extension",
        "word/document.dat",
        f'<Default Extension="dat" ContentType="{WML}"/>',
        "word/document.dat",
    ),
    # Rel-target spelling cases MUST use a non-.xml part. On word/document.xml the
    # suffix rule scrubs the part regardless, so the case passes even when
    # declaration-driven resolution is entirely disabled - proving nothing.
    (
        "rel Target ./-relative, Default-declared .dat",
        "word/doc.dat",
        f'<Default Extension="dat" ContentType="{WML}"/>',
        "./word/doc.dat",
    ),
    (
        "rel Target absolute, Default-declared .dat",
        "word/doc.dat",
        f'<Default Extension="dat" ContentType="{WML}"/>',
        "/word/doc.dat",
    ),
    (
        "rel Target with sub/.. traversal, Default .dat",
        "word/doc.dat",
        f'<Default Extension="dat" ContentType="{WML}"/>',
        "word/sub/../doc.dat",
    ),
    (
        "Override on a part with NO suffix",
        "word/document",
        f'<Override PartName="/word/document" ContentType="{WML}"/>',
        "word/document",
    ),
    (
        "conventional .xml part (control - must PASS)",
        "word/document.xml",
        f'<Override PartName="/word/document.xml" ContentType="{WML}"/>',
        "word/document.xml",
    ),
]


def main():
    print("OPC declaration-mechanism sweep")
    print("Each case: precondition -> CDR -> independent-parser exploitability\n")

    results = [check(label, build(part, ct, target)) for label, part, ct, target in CASES]

    passed = results.count(PASS)
    bypasses = results.count(BYPASS)
    skipped = results.count(SKIP)
    errors = results.count(ERROR)
    print(f"\n{len(results)} cases: {passed} pass, {bypasses} bypass, "
          f"{skipped} skipped, {errors} error")

    if bypasses:
        print("\nA bypass means an independent parser executes content CDR "
              "believed it had scrubbed. Add a pitfall entry and a regression test.")
        return 1
    # Every case must reach a verdict. A skipped or errored case proves nothing, and
    # counting it toward a green run is the exact failure this tool exists to prevent.
    if skipped or errors:
        print(f"\n{skipped + errors} case(s) reached no verdict. This is NOT a clean "
              "result - fix the harness or the code before trusting a green run.")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
