# Pre-Flight Checklist & Invariants

> Extracted from CLAUDE.md. Authoritative reference; CLAUDE.md points here.

## Pre-Flight Checklist for Every Code Change

Run this checklist before considering any change complete. Each item maps to a class of bug that has already been found in this codebase.

### Security invariants — verify nothing was weakened

- [ ] **`_read_zip_entry_safe` still present** — no bare `src.read(name)` calls in `cdr_office()`. The chunked counter is defence-in-depth against zip bombs even if `BadZipFile` would catch most cases.
- [ ] **ZIP hard-reject on all anomalies** — `_validate_zip_structure` returns `False` for non-standard compression, duplicate entries, magic byte failure, and method mismatch. There is no "log and proceed" path for structural anomalies.
- [ ] **xlsb worksheet `.bin` entries dispatch to `cdr_xlsb()`, resolved via the RELATIONSHIP** — the branch `elif ext == "xlsb" and name_canonical in xlsb_sheet_parts:` calls `return cdr_xlsb(data)`, where `xlsb_sheet_parts` comes from `_xlsb_worksheet_parts()` resolving every `_rels/*.rels` Target *before* the main loop. Do NOT revert to matching the hardcoded `xl/worksheets/sheet*.bin` name: OPC part names are arbitrary and a relocated sheet binary then skips conversion entirely, passing raw BIFF12 through (pitfall #49). Only parts a worksheet-type rel points at trigger conversion — non-worksheet `.bin` parts (e.g. `xl/workbook.bin`) stay on the ZIP path. The conversion uses `pyxlsb` to read cell values and `openpyxl` to write clean xlsx. No formula text or BIFF12 binary records pass through. `cdr_xlsb()` pre-reads all ZIP entries through `_read_zip_entry_safe` before handing to pyxlsb (decompression bomb guard). String cell values starting with `=` are prefixed with an apostrophe before `ws_out.append()` (formula injection guard).
- [ ] **S3 tag values are sanitised to S3's charset (NOT percent-encoded)** — `_enc_tag` replaces any char outside `[A-Za-z0-9 +\-._:/@]` (minus `&`/`=`) with `_` and caps length. Percent-encoding fails with `InvalidTag`; `&`/`=` are `Tagging` query separators. Malicious filenames must not inject extra tag pairs. See pitfall #35.
- [ ] **OPC part content types used in remap, not container types** — `MACRO_CONTENT_TYPE_REMAP` keys end in `.main+xml` for Override entries, `.12` for Default entries. Container-level MIME types (e.g. from `Content-Type` headers) are different strings and do not appear in `[Content_Types].xml`.
- [ ] **`onClick`/`onAction` regex handles both quote styles** — pattern is `(?:"[^"]*"|'[^']*')`, not `[^\2]` (which only matches the STX byte in a character class).
- [ ] **Auto-exec / keyword+arg field scrub runs only via `_scrub_field_code_carriers`** — never as a raw `re.subn` over the whole part. Scanning raw XML corrupts legitimate `styles.xml` into invalid XML (pitfall #40).
- [ ] **A part dropped by name also has its `.rels` entry dropped** — when adding a `STRIP_ZIP_ENTRIES` prefix, confirm any rel pointing at it is in `STRIP_REL_TYPES` (pitfall #39).
- [ ] **`STRIP_ZIP_ENTRIES` matching uses the canonicalised name, not the raw ZIP entry name** — `cdr_office` matches against `name_canonical = posixpath.normpath(name_lower).lstrip("/")`, so `./word/vbaProject.bin` / `word//vbaProject.bin` / leading-`/` variants can't dodge the prefix/suffix check (pitfall #43).
- [ ] **Any walk over attacker-controlled tree/graph structure is iterative (explicit stack), not recursive** — `_strip_pdf_outlines` (`/Next`/`/First`) and `_strip_acroform_fields` (`/Kids`) both use an explicit stack with an identity (`.objgen`) seen-set (blocks cycles) and `_MAX_WALK_NODES` (bounds a pathologically large acyclic tree). A recursive walk with a `depth > N` cutoff silently truncates a legitimately deep (non-cyclic) chain — the function returns success having left deeper nodes' actions un-stripped (pitfall #44). Never reintroduce recursion + depth-cutoff for a new PDF-object walk.
- [ ] **`pikepdf.Stream` also exposes `.items()`** — don't use `hasattr(x, "items")` alone to distinguish "a stream" from "a plain sub-dictionary of streams" (e.g. `/AP` appearance-state dicts); check `isinstance(x, pikepdf.Stream)` first (pitfall #43).
- [ ] **No regex substitution with a lazy/greedy body group spanning attacker-controlled text without a bounded/linear scan** — `_scrub_field_code_carriers` uses a manual linear scanner (`_scrub_instrtext_elements`), not a single `(open)(.*?)(close)` regex; the latter is O(n²) when many opens have no matching close (pitfall #44).
- [ ] **`cdr_image` fails closed on oversized images** — `Image.MAX_IMAGE_PIXELS` is set explicitly from `CDR_MAX_IMAGE_PIXELS` (not left at Pillow's default), and `DecompressionBombWarning` is escalated to an error via `warnings.catch_warnings()` inside `cdr_image` — don't rely on Pillow's own soft-warn/hard-error split, which lets images in the soft-warn band decode silently (pitfall #44).
- [ ] **`_sanitised_key` keeps the original extension in the basename when remapping** (`foo.docm` → `sanitised/foo.docm.docx`, not `sanitised/foo.docx`) — dropping it lets an unrelated already-clean upload collide on the same destination key (pitfall #45).
- [ ] **Any attacker-controlled string entering an AWS API's constrained field (SNS `Subject`, CloudWatch `Dimensions[].Value`, S3 tags, response headers) is sanitised to that field's charset/length/non-empty constraints before use** — `_sns_subject_safe`, `_emit_passthrough_metric`'s empty-extension placeholder, `_enc_tag`, and `_safe_ext_header` are the precedent patterns. An unsanitised value can make the whole API call raise, and because side-effect calls are fault-isolated by design, that exception is silently swallowed (pitfall #45).
- [ ] **`_ENCODED_FIELD_KEYWORDS_RE` (word-boundary), not a plain substring check, when testing decoded text against a keyword list** — `kw in text` false-positives on benign words containing a keyword as a substring (pitfall #45).
- [ ] **Any `_SAFE_EXT_RE`-style charset-allowlist regex used for header/log hygiene anchors with `\Z`, not `$`** — `$` also matches just before a trailing `\n` (pitfall #45).
- [ ] **A single `_DecompressionBudget` is threaded through the whole package extraction** — `cdr_office`'s Content_Types pre-pass and main loop, and `cdr_xlsb`'s pre-read loop, all pass the *same* budget object to `_read_zip_entry_safe`. A per-entry cap alone does not bound a package of many just-under-the-cap entries (pitfall #46).
- [ ] **`_validate_zip_structure` rejects unsafe entry names and canonical duplicates** — `..` segments, leading `/`, backslash and drive-letter forms; the duplicate seen-set is keyed on `posixpath.normpath(name.lower())`, not the raw name (pitfall #46).
- [ ] **XML parts are decoded via `_decode_xml_part` and re-encoded with the codec they arrived in** — never `decode("utf-8", errors="replace")`; a UTF-16 part decoded as UTF-8 matches no scrub regex, and `replace` corrupts clean latin-1 text (pitfall #46).
- [ ] **Every `ET.fromstring` call site on package bytes is preceded by `_reject_xml_doctype`** — `_strip_xml_macros`, `_strip_rels`, `_sanitise_content_types`, `_postscript_override_parts` (pitfall #46).
- [ ] **The XML scrub branch matches `.vml` as well as `.xml`** — VML drawings carry `onClick`/field-code payloads (pitfall #46).
- [ ] **Dropping a rel type also drops the payload part it pointed at** — the converse of pitfall #39; altChunk `.htm`/`.html`/`.mht` payloads are in `STRIP_ZIP_ENTRIES` (pitfall #46).
- [ ] **`cdr_image` collects animation frames in a single pass under `_MAX_TOTAL_IMAGE_PIXELS` / `_MAX_IMAGE_FRAMES`** — the per-frame `MAX_IMAGE_PIXELS` cap does not bound a many-frame animation (pitfall #46).
- [ ] **Every resource-cap trip raises `CdrReject`, not `ValueError`** — per-entry and aggregate decompression caps and the animation frame/pixel caps. A cap trip is deterministic: retrying re-reads the same bomb, burning the EventBridge retry budget and a reserved-concurrency slot each time (pitfall #46).
- [ ] **`CdrReject` maps to a `rejected` verdict, never the exception/retry path**, and `cdr_dispatch` refuses to emit empty output as "sanitised" (pitfall #46).
- [ ] **`cdr_image` re-encodes every frame for all multi-frame formats it supports (TIFF, GIF, WEBP), not just TIFF** — saving only the base `Image` object silently collapses an animated GIF/WEBP to its first frame (pitfall #45).

### Reliability invariants — verify the success path is protected

- [ ] **All boto3 clients are constructed with the shared `_BOTO_CONFIG`** — bounded connect/read timeouts and a capped standard retry mode; default botocore timeouts hold a reserved-concurrency slot for minutes during an S3/SNS brownout (pitfall #46).
- [ ] **`_delete_source_safe` never re-raises** — the try/except logs a warning and returns. An S3 delete failure must not cause EventBridge to retry a file that is already sanitised.
- [ ] **`_publish_result_safe` never re-raises** — same pattern. SNS unavailability must not block the success response.
- [ ] **All `_publish_result_safe` call sites go through `_truncate_removed`** — both flat and nested `removed` lists are capped before SNS publish. Check every call site when adding new result paths.
- [ ] **Oversized files use `copy_object`, not `put_object(Body=b'')`** — quarantine must preserve the full original content.
- [ ] **ZIP magic byte hard-reject deletes the source** — prevents EventBridge from re-triggering on the same corrupt file indefinitely.
- [ ] **Source is never deleted after a quarantine upload failure** — the reject/unsupported handler path only calls `_delete_source_safe` when `decision["delete_source"]` is true AND the quarantine upload (if attempted) actually succeeded; never destroy the only remaining copy (pitfall #43).

### Test invariants — verify coverage was not regressed

- [ ] **371 tests pass** (all passed) — `cd src && pytest test_cdr.py test_cdr_local.py -v` shows no failures.
- [ ] **No routing/disarm logic duplicated into a front-end** — `handler` and `app.py` both delegate to `cdr_dispatch`; a security decision must live in exactly one place (pitfall #41).
- [ ] **Every new CDR path has a test** — if you add a new strip rule, add a fixture that carries that threat and assert it is removed.
- [ ] **Every new try/except warn-and-continue block has a failure-path test** — prove the success path completes even when the wrapped operation throws.
- [ ] **No new `src.read(name)` calls** — always use `_read_zip_entry_safe(src, item)`.
- [ ] **New regex patterns are tested with both quote styles** — single-quoted and double-quoted XML attribute values.

### Infrastructure invariants — verify both IaC paths stay in step

- [ ] **Infra changes land in `src/template.yaml` AND `terraform/`** — the two paths provision the same stack, so a change to one is not a change to the deployment. New parameters, resources, IAM statements, alarms and env vars all need doing twice. (#62: four `CDR_MAX_*` caps and the resource-prefix work reached SAM only, and shipped that way for several PRs.)
- [ ] **A new `CDR_MAX_*` cap is settable from both paths** — a SAM `Parameter` plus a `terraform/` variable wired into the Lambda `environment` block, with matching defaults. CI's `terraform-validate` job enforces this parity against the names `lambda_function.py` reads; it covers **caps only**, so names/IAM/alarms still need checking by hand.
- [ ] **Defaults quoted in docs match the code** — retuning a cap in `lambda_function.py` without updating the docs leaves them confidently wrong (`CDR_MAX_TOTAL_BYTES` sat documented as 1 GiB long after being retuned to 512 MB, implying the decompression budget was *above* the 1024 MB `MemorySize` when the retune existed to put it under). `scripts/check_cap_defaults.py` (run by CI) now enforces this across the tracked docs. Two blind spots remain manual: lines naming **more than one cap** are skipped, since a number can't be attributed among several; and the gitignored CLAUDE/AGENTS/GEMINI.md are invisible to CI. `docs/claude/architecture.md`'s env-var table is still the place readers trust — fix it first.
- [ ] **Resource names stay parameterised** — never reintroduce a hardcoded `cdr-*` name. They are account-and-region-scoped, and a `cdr-*` deployment may already exist in the target account under another tool's management; absence from your state file does not mean unmanaged.

### Documentation invariants — verify docs stay accurate

- [ ] **CLAUDE.md test count matches actual** — update the `(N tests)` count after adding or removing tests. `scripts/check_test_count.py` (run by CI) enforces this for the *tracked* docs (`docs/claude/testing.md`, this file); CLAUDE.md / AGENTS.md / GEMINI.md are gitignored, so CI cannot see them — update those by hand.
- [ ] **ZIP anomaly handling described as hard-reject everywhere** — not "log and proceed". Check CLAUDE.md, AGENTS.md, GEMINI.md.
- [ ] **New pitfalls encoded** — if a bug required a non-obvious fix, add it to the pitfalls section so future contributors recognise the pattern immediately.

---

## Invariants — Never Change These

The following are correct and intentional. A reviewer who flags them as "problems" is wrong.

| Pattern | Why it must stay |
|---|---|
| `_read_zip_entry_safe` chunked counter | Defence-in-depth; CRC check is correctness-only and Python-version-dependent |
| `_delete_source_safe` / `_publish_result_safe` never re-raise | EventBridge retries any unhandled exception — side-effect failures must not re-CDR already-sanitised files |
| xlsb `.bin` dispatches to `cdr_xlsb()` | `pyxlsb` reads cell values only; `openpyxl` writes fresh xlsx — no BIFF12 records pass through; output renamed xlsb→xlsx; string cells starting with `=` prefixed with apostrophe to block formula injection |
| `s3.copy_object` for oversized quarantine | Preserves the original; `put_object(Body=b'')` destroys evidence |
| `MACRO_CONTENT_TYPE_REMAP` maps both `.main+xml` and `.12` forms | Real Office files write the part-level form; both forms exist in the wild |
| `sanitised/` prefix on output keys | Keeps source and destination separable; prevents EventBridge re-trigger if rules are misconfigured |
| Separate `CdrAlarmTopic` and `CdrResultTopic` | Application consumers on `CdrResultTopic` must not receive CloudWatch alarm JSON |
| Tag values URL-encoded in `_upload` | Prevents `&`/`=` injection from attacker-controlled filenames |
| MACROBUTTON replaced with `_CDR_REMOVED_`, not deleted | Preserves field begin/end marker balance in XML structure |
| Auto-exec / keyword+arg field scrub scoped to `<w:instrText>`/`<w:fldSimple w:instr>` carriers | Running it over the raw XML part false-positive-corrupts legitimate `styles.xml` into invalid XML (pitfall #40) |
| `customXml`/`customXmlProps` rel types in `STRIP_REL_TYPES` | Dropping the part without the rel leaves a dangling reference that breaks strict OPC consumers (pitfall #39) |
| Aggregate budget default kept **under** `MemorySize` | A budget above the container's memory ceiling cannot bind before the OOM it exists to prevent |
| Aggregate `_DecompressionBudget` shared across one package | A per-entry cap alone lets many just-under-cap entries expand without limit — the Lambda-timeout/retry-storm failure mode (pitfall #46) |
| `_decode_xml_part` BOM sniff + same-codec re-encode | UTF-16 parts evade every content scrub when force-decoded as UTF-8; `errors="replace"` corrupts clean non-UTF-8 text |
| `CdrReject` distinct from `ValueError` | A structural verdict is deterministic — retrying yields the same answer, so it must not take the EventBridge retry path |
| `_truncate_removed` checks both flat and nested shapes | Call sites pass both shapes; guarding only the nested path leaves the flat path unprotected |
