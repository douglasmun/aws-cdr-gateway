# CDR Test Fixtures

Sample files with embedded active content for manual smoke testing and benchmarking
of the CDR Lambda pipeline. Each file contains real threats that CDR should fully disarm.

## Generate

```bash
cd <repo-root>
source bin/activate
python docs/fixtures/generate_fixtures.py
```

Requires the virtualenv with `requirements.txt` installed. Produces all 17 fixture
files in this directory. Re-run after any CDR change to regenerate fresh fixtures.

## Files

| File | Threats | Expected CDR outcome |
|---|---|---|
| `docx_vba_macro.docx` | `vbaProject.bin` · MACROBUTTON field · VBA rel | VBA entry stripped · field neutralised · rel removed |
| `docx_external_link.docx` | `externalLink` rel · `externalLinks/` entry | Rel stripped · entry dropped |
| `docx_dde_field.docx` | DDE field code in `document.xml` | Field code neutralised to `_CDR_REMOVED_` |
| `docx_autoopen_field.docx` | AUTOOPEN · AUTOEXIT · WEBSERVICE fields | All field codes neutralised |
| `docx_multithreat.docx` | VBA + ext link + macro CT + MACROBUTTON + DDE + AUTOOPEN + INCLUDETEXT | All threats stripped in a single pass |
| `xlsm_vba.xlsm` | `vbaProject.bin` · macro-enabled content type · VBA rel | VBA stripped · CT remapped · output renamed `.xlsx` |
| `xlsx_dde_formula.xlsx` | DDE formula · WEBSERVICE formula in sheet XML | Formula elements neutralised |
| `xlsb_sheet_binary.xlsb` | `sheet1.bin` BIFF12 binary sheet | Triggers `cdr_xlsb()` path · converted to clean `.xlsx` |
| `pptx_activex.pptx` | `activeX1.bin` · control rel | ActiveX entry dropped · rel removed |
| `pdf_openaction_js.pdf` | `/OpenAction` JavaScript | `/OpenAction` removed |
| `pdf_embedded_file.pdf` | `/EmbeddedFiles` attachment | `/Names./EmbeddedFiles` removed |
| `pdf_acroform_js.pdf` | AcroForm field `/AA` JavaScript (focus + blur) | JS actions stripped from all fields |
| `pdf_page_launch.pdf` | Page `/AA /O /Launch` · `/SubmitForm` annotation | Launch and SubmitForm actions stripped |
| `pdf_multithreat.pdf` | `/OpenAction` JS + `/EmbeddedFiles` + AcroForm JS + page `/AA /Launch` | All four threat vectors stripped |
| `gif_comment_block.gif` | GIF comment extension block (0x21 0xFE) | Re-encoded as GIF · comment block absent |
| `tiff_multiframe_exif.tiff` | 3-frame TIFF with GPS EXIF in every frame | Re-encoded · all frames preserved · EXIF stripped |
| `jpeg_with_exif.jpg` | JPEG with GPS + camera make/model + copyright EXIF | Re-encoded · EXIF stripped |

## Upload and verify

```bash
# Set your stack name once
STACK=cdr-lambda-staging

# Resolve bucket names from stack outputs
SOURCE_BUCKET=$(aws cloudformation describe-stacks \
  --stack-name $STACK \
  --query "Stacks[0].Parameters[?ParameterKey=='SourceBucketName'].ParameterValue" \
  --output text)

# Upload all fixtures
aws s3 cp docs/fixtures/ s3://$SOURCE_BUCKET/smoke/ \
  --recursive --exclude "*.py" --exclude "*.md"

# Tail Lambda logs in a separate terminal
aws logs tail /aws/lambda/cdr-lambda --follow --format short
```

After upload, check that each file is processed correctly using the assertions in
`docs/02-smoke-test-playbook.md`.

## Benchmark

Pass this directory to `docs/benchmark.py` to run a load test using realistic fixtures
instead of synthetic random files:

```bash
python docs/benchmark.py \
  --bucket $SOURCE_BUCKET \
  --files docs/fixtures/ \
  --concurrency 4 \
  --log-group /aws/lambda/cdr-lambda
```

The benchmark uploads all non-script files in this directory concurrently, waits for
Lambda invocations to complete, then reports p50/p99 Duration, peak memory, error
count, and throttle count with automatic tuning recommendations.
