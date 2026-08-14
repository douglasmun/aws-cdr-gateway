# Testing

> Extracted from CLAUDE.md. Authoritative testing reference; CLAUDE.md points here.

> **What a green suite does not prove.** Every assertion here is evaluated by **pikepdf,
> python-docx, openpyxl and Pillow**. The bug class this project keeps hitting (#49, #54, #55)
> *is* parser disagreement — a real consumer resolving a part differently than the test parser
> does — so the oracle shares a blind spot with the code under test. As of 2026-08-14 the PDF
> paths are independently confirmed against **mupdf, poppler and pdf.js**, the Office paths
> against **LibreOffice headless**, and the deployed pipeline against a **live AWS staging
> stack**. As of the same date the Office outputs have also been opened in **Word and Excel
> themselves** — 5 of 5 pass, including both confirmed live bypasses (#54, #55), which Word
> resolved through the `Override` and `Default Extension` mechanisms respectively and still
> executed nothing. That closes the gap the headless check could not: a headless render never
> *executes* a DDE field, so a clean conversion shows structural absence, not that an
> interactive viewer declines to prompt. The eight PDFs have likewise been opened in **Acrobat**
> — 8 of 8 pass. **PowerPoint closed last**, and needed a fixture built first: the corpus had no
> loadable `.pptx`, only an excluded package whose *input* no engine can load. The replacement
> carries a VBA project and an external `attachedTemplate` rel, and PowerPoint renders it with no
> macro warning and **no prompt to fetch the remote template** — a result no headless engine can
> produce, since it never attempts the fetch. The manual pass therefore stands at **14 of 14 with
> no engine unverified**. See `docs/viewer-validation/CHECKLIST.md`.

Tests (397 in `test_cdr.py` + 50 in `test_cdr_local.py` = **447 total**) construct malicious fixtures entirely in-memory — no fixture files on disk. S3/SNS calls are patched with `unittest.mock`. Required env vars are set automatically via `os.environ.setdefault`. `src/test_cdr.py` covers the CDR Lambda; `src/test_cdr_local.py` covers the pure `cdr_dispatch` core and the local FastAPI service (`app.py`), reusing the same in-memory fixtures. Run: `cd src && pytest test_cdr.py test_cdr_local.py -v`.

> **Run it bare — do not export AWS env vars around it.** `src/conftest.py` sets the
> credentials/region and `test_cdr.py` sets the bucket and topic names, both via
> `setdefault`, which *yields to anything already in the environment*. Exporting
> `SANITISED_BUCKET`/`QUARANTINE_BUCKET` therefore overrides the test defaults and fails
> the two tests asserting on the literal names `test-sanitised`/`test-quarantine`
> (`test_xlsb_output_is_valid_xlsx`, `test_oversized_uses_copy_object`) — an
> environmental failure that reads exactly like a code regression. Dummy AWS credentials
> are harmless but unnecessary; omitting them entirely also works, though botocore's
> credential lookup then stretches the suite from ~2 s to ~60 s.

**`test_cdr_local.py` of note:**
- `TestCdrDispatchRouting` — every `cdr_dispatch` branch (office/pdf/image sanitised, legacy/RTF/unknown unsupported, non-OOXML-zip rejected, oversize rejected, ext remap) and a `test_dispatch_does_no_io` that fails if the pure core makes any boto3 call
- `TestSanitiseEndpoint` — `/sanitise` returns 200 + clean bytes (vbaProject/OpenAction gone), 422 for RTF/unknown/non-OOXML-zip, 500 for a corrupt PDF; `/healthz` reports supported formats

**Test classes of note:**
- `TestSnsFailureDoesNotBlockSuccess` — SNS down → still sanitised + source deleted (fault isolation)
- `TestDeleteFailureDoesNotMaskSuccess` — delete throws → handler still returns sanitised result
- `TestNoSuchKeyDownload` — `NoSuchKey` → `source-missing` published, no quarantine created
- `TestZeroByteFile` — zero-byte upload handled without crash
- `TestMalformedEvent` — missing EventBridge fields raise structured error
- `TestAcroFormJSSweep` — JavaScript in AcroForm field `/AA` is stripped
- `TestXlsbCDR` — xlsb with sheet .bin is converted to clean xlsx; cell values preserved; VBA-only xlsb still goes through ZIP CDR path; `FORMULA_STRING` cached values starting with `=` are forced to plain text (formula injection blocked)
- `TestXlsbConversionPolicy` — handler routes xlsb→xlsx to sanitised bucket, deletes source, output is valid openpyxl-openable xlsx
- `TestOversizedCopyObject` — oversized file is quarantined via CopyObject (not b'' placeholder)
- `TestContentTypeRealOfficeTypes` — all 17 macro-enabled formats validated against real OPC part content types in both Override and Default entry forms
- `TestReadZipEntrySafe` — decompression limit enforced by chunked byte counter; boundary condition and falsified-`file_size` attack vector both covered
- `TestOtherOfficeFormats` — pptx, dotm, ppam CDR and extension-remap through handler
- `TestRemainingOfficeFormats` — dotx, xltx, xltm, xlam, potx, potm, ppsx VBA strip and extension remap
- `TestMultiThreatIntegration` — single fixture with simultaneous VBA + dangerous rels + macro content type + MACROBUTTON field; all threats removed in one pass, report captures all removals
- `TestStripXmlMacrosRegex` — `onClick`/`onAction` stripped for both quote styles; `AUTOOPEN`/`AUTOEXIT`/`AUTONEW`/`AUTOCLOSE` neutralised; `INCLUDE`/`INCLUDETEXT`/`INCLUDEPICTURE`/`LINK`/`WEBSERVICE`/`HYPERLINK` targets neutralised; XML entity-encoded field codes (`&#68;&#68;&#69;` = DDE, partial `&#77;ACROBUTTON`) neutralised in place; benign `&amp;` escapes preserved (`test_benign_xml_escape_preserved`); `automobile` not matched (word boundary check); field keywords in legitimate element/attribute markup are NOT corrupted (`test_field_keyword_in_markup_not_corrupted`, pitfall #40) and `<w:fldSimple w:instr="…">` field codes ARE neutralised (`test_fldsimple_instr_attribute_neutralised`)
- `TestTruncateRemoved` — `_truncate_removed` caps `removed` lists at 100 entries at both flat and nested report levels
- `TestRtfDeliberatelyFailClosed` — RTF is in `FAIL_CLOSED_EXTS` and not in `OFFICE_EXTS`; fails closed even if wrongly added to `OFFICE_EXTS` (never reaches `cdr_office()`). Pins RTF rejection as a deliberate decision (pitfall #38)

**When patching internal functions, patch `_publish_result_safe` (not `_publish_result`).**
