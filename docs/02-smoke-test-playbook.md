# Manual 02 — Smoke Test Playbook

Run this playbook after every `sam deploy`, including first deploys and all subsequent
changes. Each section tests one CDR path end-to-end. A single missed assertion means
the pipeline is not safe to carry live traffic.

Estimated time: 15–20 minutes.

---

## Setup

```bash
# Set stack name once — used throughout this playbook
STACK=cdr-lambda-staging

# Resolve bucket names from stack outputs/parameters
SOURCE_BUCKET=$(aws cloudformation describe-stacks \
  --stack-name $STACK \
  --query "Stacks[0].Parameters[?ParameterKey=='SourceBucketName'].ParameterValue" \
  --output text)

SANITISED_BUCKET=$(aws cloudformation describe-stacks \
  --stack-name $STACK \
  --query "Stacks[0].Parameters[?ParameterKey=='SanitisedBucketName'].ParameterValue" \
  --output text)

QUARANTINE_BUCKET=$(aws cloudformation describe-stacks \
  --stack-name $STACK \
  --query "Stacks[0].Parameters[?ParameterKey=='QuarantineBucketName'].ParameterValue" \
  --output text)

echo "Source:     $SOURCE_BUCKET"
echo "Sanitised:  $SANITISED_BUCKET"
echo "Quarantine: $QUARANTINE_BUCKET"
```

Open a second terminal and tail Lambda logs throughout the playbook:

```bash
aws logs tail /aws/lambda/cdr-lambda --follow --format short
```

---

## Test 1 — DOCX with VBA macro

### What this tests
The happy path: an Office file with a macro is sanitised, VBA binary is stripped,
output is valid DOCX, source is deleted.

### Create fixture

```python
# Run from repo root with venv active: python3 smoke_docx.py
import io, zipfile
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as z:
    z.writestr("[Content_Types].xml",
        '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/'
        'package/2006/content-types"><Default Extension="rels" ContentType='
        '"application/vnd.openxmlformats-package.relationships+xml"/></Types>')
    z.writestr("_rels/.rels",
        '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats'
        '.org/package/2006/relationships"/>')
    z.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0MACRO_PAYLOAD")
    z.writestr("word/document.xml",
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml'
        '/2006/main"><w:body><w:p><w:t>Hello</w:t></w:p></w:body></w:document>')
open("/tmp/smoke_test.docx", "wb").write(buf.getvalue())
print("Written: /tmp/smoke_test.docx")
```

### Upload and verify

```bash
aws s3 cp /tmp/smoke_test.docx s3://$SOURCE_BUCKET/smoke/smoke_test.docx

# Wait for Lambda (~5 s)
sleep 8

# 1. Sanitised output exists
aws s3 ls s3://$SANITISED_BUCKET/sanitised/smoke/smoke_test.docx
# Must print a file entry. If empty: Lambda did not run — check EventBridge rule.

# 2. S3 tags on sanitised output
aws s3api get-object-tagging \
  --bucket $SANITISED_BUCKET \
  --key sanitised/smoke/smoke_test.docx \
  --query 'TagSet'
```

Expected tags:
```
cdr-status    = sanitised
cdr-mode      = full
cdr-removals  = 1          (the vbaProject.bin)
cdr-original-ext = docx
cdr-zip-anomaly  = false
```

```bash
# 3. Source deleted from source bucket
aws s3 ls s3://$SOURCE_BUCKET/smoke/smoke_test.docx
# Must print nothing (exit 0 but no output means deleted — expected)

# 4. VBA binary absent from sanitised output
aws s3 cp s3://$SANITISED_BUCKET/sanitised/smoke/smoke_test.docx /tmp/smoke_clean.docx
python3 -c "
import zipfile, sys
with zipfile.ZipFile('/tmp/smoke_clean.docx') as z:
    names = z.namelist()
    vba = [n for n in names if 'vbaProject' in n.lower()]
    print('PASS: vbaProject.bin absent' if not vba else f'FAIL: found {vba}')
    print(f'  entries: {names}')
"
```

**Pass criteria:** `PASS: vbaProject.bin absent` printed, all four tags present.

---

## Test 2 — PDF with JavaScript

### What this tests
The PDF CDR path: `/OpenAction` JavaScript trigger removed.

### Create fixture

```python
# python3 smoke_pdf.py
import io, pikepdf
pdf = pikepdf.Pdf.new()
page = pdf.make_indirect(pikepdf.Dictionary(
    Type=pikepdf.Name("/Page"), MediaBox=pikepdf.Array([0,0,612,792])))
pdf.pages.append(pikepdf.Page(page))
pdf.Root["/OpenAction"] = pikepdf.Dictionary(
    S=pikepdf.Name("/JavaScript"),
    JS=pikepdf.String("app.alert('smoke test');"))
buf = io.BytesIO()
pdf.save(buf)
open("/tmp/smoke_test.pdf", "wb").write(buf.getvalue())
print("Written: /tmp/smoke_test.pdf")
```

```bash
aws s3 cp /tmp/smoke_test.pdf s3://$SOURCE_BUCKET/smoke/smoke_test.pdf
sleep 8

aws s3 ls s3://$SANITISED_BUCKET/sanitised/smoke/smoke_test.pdf

aws s3api get-object-tagging \
  --bucket $SANITISED_BUCKET \
  --key sanitised/smoke/smoke_test.pdf \
  --query 'TagSet'
```

```bash
# Verify /OpenAction is gone from the sanitised PDF
aws s3 cp s3://$SANITISED_BUCKET/sanitised/smoke/smoke_test.pdf /tmp/smoke_clean.pdf
python3 -c "
import io, pikepdf
with pikepdf.open('/tmp/smoke_clean.pdf') as pdf:
    has_oa = '/OpenAction' in pdf.Root
    print('FAIL: /OpenAction still present' if has_oa else 'PASS: /OpenAction removed')
"
```

**Pass criteria:** `PASS: /OpenAction removed` printed, `cdr-status=sanitised` tag.

---

## Test 3 — xlsb with sheet binary → converted to xlsx

### What this tests
The xlsb conversion path: `cdr_xlsb()` produces valid xlsx, source is deleted,
output extension is `.xlsx`.

### Create fixture

```python
# python3 smoke_xlsb.py
# Reuses the _make_xlsb() helper from the test suite
import sys
sys.path.insert(0, "src")
import os
os.environ.setdefault("SANITISED_BUCKET", "x")
import test_cdr
data = test_cdr._make_xlsb(rows=[[1.0, 2.0, 3.0], [4.0, 5.0, 6.0]])
open("/tmp/smoke_test.xlsb", "wb").write(data)
print(f"Written: /tmp/smoke_test.xlsb ({len(data)} bytes)")
```

```bash
aws s3 cp /tmp/smoke_test.xlsb s3://$SOURCE_BUCKET/smoke/smoke_test.xlsb
sleep 8

# Output key must be .xlsx, not .xlsb
aws s3 ls s3://$SANITISED_BUCKET/sanitised/smoke/smoke_test.xlsx
# Must print a file entry

aws s3api get-object-tagging \
  --bucket $SANITISED_BUCKET \
  --key sanitised/smoke/smoke_test.xlsx \
  --query 'TagSet'
```

```bash
# Verify output is a valid xlsx openable by openpyxl and cell values survived
aws s3 cp s3://$SANITISED_BUCKET/sanitised/smoke/smoke_test.xlsx /tmp/smoke_clean.xlsx
python3 -c "
import openpyxl
wb = openpyxl.load_workbook('/tmp/smoke_clean.xlsx')
ws = wb.active
v = ws.cell(1,1).value
print(f'PASS: cell A1 = {v}' if v == 1.0 else f'FAIL: cell A1 = {v!r}')
# Verify no formula elements survived (defence against formula injection)
import zipfile
with zipfile.ZipFile('/tmp/smoke_clean.xlsx') as z:
    for name in z.namelist():
        if name.endswith('.xml') and 'sheet' in name:
            content = z.read(name)
            if b'<f>' in content:
                print(f'FAIL: formula element <f> found in {name}')
            else:
                print(f'PASS: no <f> formula elements in {name}')
"
```

**Pass criteria:** `.xlsx` output exists, `cdr-status=sanitised`, cell value 1.0,
no `<f>` formula elements in sheet XML.

---

## Test 4 — GIF re-encode (comment block stripped)

### What this tests
The image CDR path for GIF: format preserved as GIF, comment extension block removed.

```python
# python3 smoke_gif.py
from PIL import Image
import io

img = Image.new("RGB", (32, 32), color=(255, 0, 0))
buf = io.BytesIO()
img.save(buf, format="GIF", comment=b"HIDDEN PAYLOAD IN COMMENT")
open("/tmp/smoke_test.gif", "wb").write(buf.getvalue())
print("Written: /tmp/smoke_test.gif")
```

```bash
aws s3 cp /tmp/smoke_test.gif s3://$SOURCE_BUCKET/smoke/smoke_test.gif
sleep 8

aws s3 ls s3://$SANITISED_BUCKET/sanitised/smoke/smoke_test.gif
# Must be .gif, not .png

aws s3api get-object-tagging \
  --bucket $SANITISED_BUCKET \
  --key sanitised/smoke/smoke_test.gif \
  --query 'TagSet'
```

```bash
# Verify output is GIF and comment block is absent
aws s3 cp s3://$SANITISED_BUCKET/sanitised/smoke/smoke_test.gif /tmp/smoke_clean.gif
python3 -c "
raw = open('/tmp/smoke_clean.gif', 'rb').read()
# GIF comment extension: 0x21 0xFE
has_comment = b'\x21\xFE' in raw
print('FAIL: comment extension still present' if has_comment else 'PASS: comment block absent')
# Confirm it is a valid GIF
print('PASS: GIF signature present' if raw[:6] in (b'GIF87a', b'GIF89a') else 'FAIL: not a GIF')
"
```

**Pass criteria:** `.gif` output, no `0x21 0xFE` comment block, `image/gif` content type
(check `cdr-status=sanitised` tag).

---

## Test 5 — Legacy .doc quarantined

### What this tests
Legacy OLE binary formats are quarantined without CDR and source is deleted.

```bash
# Create a minimal fake .doc (OLE magic bytes)
python3 -c "open('/tmp/smoke_test.doc','wb').write(b'\xd0\xcf\x11\xe0LEGACYDOC' + b'\x00'*512)"

aws s3 cp /tmp/smoke_test.doc s3://$SOURCE_BUCKET/smoke/smoke_test.doc
sleep 8

# Must NOT appear in sanitised bucket
aws s3 ls s3://$SANITISED_BUCKET/sanitised/smoke/smoke_test.doc
# Expected: empty output (file was not sanitised)

# Must appear in quarantine bucket (if enabled)
if [ -n "$QUARANTINE_BUCKET" ]; then
  aws s3 ls s3://$QUARANTINE_BUCKET/unsupported/smoke/smoke_test.doc
  # Expected: file entry present
fi

# Source must be deleted
aws s3 ls s3://$SOURCE_BUCKET/smoke/smoke_test.doc
# Expected: empty output
```

**Pass criteria:** File absent from sanitised bucket, present in quarantine under
`unsupported/` prefix, source deleted. Lambda logs should show
`unsupported legacy format`.

---

## Test 6 — Oversized file guard

### What this tests
Files above `CdrMaxFileBytes` (100 MB by default) are quarantined via `copy_object`
without downloading, and the source is NOT deleted.

```bash
# The EventBridge event carries the object size — we can simulate a large-size
# event without uploading a real 100 MB file.
# Instead, upload a real small file but inject the size into the test event
# by modifying the Lambda directly. The simplest production-safe test:
# upload a real file that is just over the limit.

# Generate a 101 MB file of random bytes
python3 -c "
import os
open('/tmp/smoke_oversized.bin','wb').write(os.urandom(101*1024*1024))
print('Written 101 MB')
"

aws s3 cp /tmp/smoke_oversized.bin s3://$SOURCE_BUCKET/smoke/smoke_oversized.bin
sleep 10

# Must NOT be in sanitised bucket
aws s3 ls s3://$SANITISED_BUCKET/sanitised/smoke/smoke_oversized.bin
# Expected: empty

# Must be in quarantine under oversized/ prefix
if [ -n "$QUARANTINE_BUCKET" ]; then
  aws s3 ls s3://$QUARANTINE_BUCKET/oversized/smoke/smoke_oversized.bin
fi

# Source must still exist (not deleted for oversized — no CDR was attempted)
# Note: handler() does NOT call _delete_source_safe for oversized files.
# Manually delete after confirming:
aws s3 rm s3://$SOURCE_BUCKET/smoke/smoke_oversized.bin
```

**Pass criteria:** Oversized file in quarantine under `oversized/`, absent from
sanitised bucket, Lambda logs show `File too large`.

---

## Test 7 — ZIP anomaly hard reject

### What this tests
A file with invalid ZIP magic bytes is rejected, quarantined, and source deleted.

```bash
# Upload a file with .docx extension but invalid ZIP magic bytes
python3 -c "open('/tmp/smoke_badzip.docx','wb').write(b'NOT_A_ZIP' + b'\x00'*256)"

aws s3 cp /tmp/smoke_badzip.docx s3://$SOURCE_BUCKET/smoke/smoke_badzip.docx
sleep 8

# Must NOT be in sanitised bucket
aws s3 ls s3://$SANITISED_BUCKET/sanitised/smoke/smoke_badzip.docx
# Expected: empty

# Must be in quarantine under rejected/ prefix
if [ -n "$QUARANTINE_BUCKET" ]; then
  aws s3 ls s3://$QUARANTINE_BUCKET/rejected/smoke/smoke_badzip.docx
fi

# Source must be deleted
aws s3 ls s3://$SOURCE_BUCKET/smoke/smoke_badzip.docx
# Expected: empty

# Lambda logs must show 'ZIP validation failed' and 'rejected'
aws logs filter-log-events \
  --log-group-name /aws/lambda/cdr-lambda \
  --filter-pattern "ZIP validation failed" \
  --query 'events[*].message' \
  --output text | tail -3
```

**Pass criteria:** File in quarantine under `rejected/`, absent from sanitised bucket,
source deleted, log line shows `ZIP validation failed`.

---

## CloudWatch alarms — confirm OK state

After all smoke tests pass, verify all five alarms are in `OK` state:

```bash
aws cloudwatch describe-alarms \
  --alarm-name-prefix cdr-lambda \
  --query 'MetricAlarms[].{Name:AlarmName,State:StateValue}' \
  --output table
```

Expected output — all `OK`:
```
------------------------------------------
| Name                        | State    |
|-----------------------------|----------|
| cdr-lambda-dlq-depth        | OK       |
| cdr-lambda-duration-p99     | OK       |
| cdr-lambda-errors           | OK       |
| cdr-lambda-passthrough      | OK       |
| cdr-lambda-throttles        | OK       |
------------------------------------------
```

If any alarm is in `ALARM` or `INSUFFICIENT_DATA` state:
- `ALARM` on `cdr-lambda-errors` — check Lambda logs for the failing invocation
- `INSUFFICIENT_DATA` — the alarm has not yet received a data point; run the
  smoke tests again to generate invocations, then re-check

---

## DLQ depth — must be zero

```bash
DLQ_URL=$(aws cloudformation describe-stack-resources \
  --stack-name $STACK \
  --query "StackResources[?LogicalResourceId=='CdrDlq'].PhysicalResourceId" \
  --output text)

aws sqs get-queue-attributes \
  --queue-url $DLQ_URL \
  --attribute-names ApproximateNumberOfMessages \
  --query 'Attributes.ApproximateNumberOfMessages'
# Expected: "0"
```

Any value > 0 means at least one file exhausted EventBridge retries. Inspect before
proceeding:

```bash
aws sqs receive-message --queue-url $DLQ_URL --max-number-of-messages 1
```

---

## Smoke test sign-off

Before marking the deployment ready for load testing or live traffic, confirm every
test passed:

- [ ] Test 1 — DOCX VBA stripped, source deleted, tags correct
- [ ] Test 2 — PDF `/OpenAction` removed
- [ ] Test 3 — xlsb converted to xlsx, no `<f>` formula elements
- [ ] Test 4 — GIF stays GIF, comment block absent
- [ ] Test 5 — Legacy `.doc` quarantined, not sanitised
- [ ] Test 6 — Oversized file quarantined via `copy_object`, not deleted
- [ ] Test 7 — Bad ZIP magic rejected, source deleted
- [ ] All five CloudWatch alarms in `OK` state
- [ ] DLQ depth = 0

**Next step:** `docs/deployment-runbook.md` §5 — load benchmark.
