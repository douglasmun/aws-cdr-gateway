# CDR Gap Analysis — benchmarked against Didier Stevens' maldoc toolkit

Didier Stevens' analysis tools (`oledump.py`, `pdfid.py`, `pdf-parser.py`, `zipdump.py`,
`emldump.py`) are the canonical enumeration of *where active content hides* in documents.
This report maps each hiding technique those tools surface against what this CDR gateway
actually does, to find blind spots.

> **Scope and status.** This is a **point-in-time report**, written against one toolkit's
> enumeration. It is not a coverage guarantee and has not been re-run end-to-end since.
> Sections whose claims later proved incomplete carry inline `Superseded` notes; the
> closing section records what changed. See pitfall #51 for why that distinction matters.
> **Read the dated updates at the end before relying on any verdict here** — they record
> the bypasses found since (#54, #55) and the 2026-08-14 container-layer sweep, which
> covers an axis this report does not address at all.

**Method.** For each technique: is it caught? where in the code? and — for the
non-obvious cases — an *empirical* check (a crafted fixture run through the real
`cdr_*` function), not just a code read. Claims marked **[verified]** were reproduced in a
throwaway script this session.

**Framing.** A detection tool's job is to *find* everything; a CDR gateway's job is to
*neutralise or reject* everything. The gateway has two structural advantages over a naive
scanner that Stevens' tools are partly built to defeat:
1. **It parses, it doesn't string-scan.** `cdr_pdf` works on pikepdf's parsed object model;
   `cdr_office` rebuilds the ZIP entry-by-entry. Obfuscation that defeats grep (hex-encoded
   PDF names, objects buried in object streams) is irrelevant once the structure is parsed.
2. **It fails closed.** Anything unparseable or unrecognised is rejected, not passed
   through — so "can hide from a parser" becomes "gets quarantined", not "gets through clean".

---

## 1. `oledump.py` — OLE2 / Compound File Binary (legacy Office, `vbaProject.bin`)

`oledump` decompresses VBA, carves OLE streams, de-obfuscates macro URLs, brute-forces XOR.

| Technique | CDR disposition | Where |
|---|---|---|
| VBA macros in legacy `.doc/.xls/.ppt` (OLE2 container) | **N/A — rejected.** Legacy OLE formats are quarantined + source deleted, never CDR'd | `LEGACY_EXTS`, handler legacy branch |
| `vbaProject.bin` inside an OOXML package | **Dropped wholesale** (the part bytes + its relationship) | `STRIP_ZIP_ENTRIES`, `STRIP_REL_TYPES` (both vbaProject rel namespaces) |
| Obfuscated/encoded VBA, XOR'd payloads, stomped p-code | **Moot** — the gateway never parses VBA; it deletes the whole binary part. There is nothing to de-obfuscate because nothing survives | — |

**Verdict: no gap.** `oledump`'s entire problem domain (analysing VBA you've chosen to
keep) doesn't exist here — the gateway's answer to "malicious VBA" is "delete the binary,
or reject the container". This is *stronger* than analysis: there is no macro left to be
clever about. The one thing to keep airtight is that **every** macro-bearing part and its
rel are on the strip lists (CLAUDE.md pitfalls #31, #39 cover the part-and-rel rule).

---

## 2. `pdfid.py` / `pdf-parser.py` — PDF

`pdfid` flags: `/JS`, `/JavaScript`, `/OpenAction`, `/AA`, `/Launch`, `/EmbeddedFile`,
`/RichMedia`, `/AcroForm`, `/XFA`, `/ObjStm`, `/JBIG2Decode`, and hex-name obfuscation
(`/J#61vaScript`). `pdf-parser` decompresses streams and resolves indirect objects.

| Technique pdfid flags | CDR disposition | Evidence |
|---|---|---|
| `/OpenAction`, `/AA`, `/JS`, `/JavaScript` at catalog | deleted | `cdr_pdf` catalog loop |
| `/Names → /JavaScript`, `/EmbeddedFiles`, `/AlternatePresentations` | deleted | `cdr_pdf` `/Names` branch |
| `/AcroForm` → `/XFA`, `/CO`, `/AA` + field/widget `/A`/`/AA`/`/JS` | deleted (recursive field sweep) | `_strip_acroform_fields`, AcroForm branch |
| Page annotation actions (`/A`/`/AA`), incl. `/Launch`/`/GoToE`/`/Rendition`/`/SetOCGState` | **all** annotation actions deleted unconditionally (allowlist-free) | `_strip_pdf_page` |
| `/FileAttachment` annotations (`/FS`+`/EF`) — embed bypass | file spec scrubbed | `_strip_pdf_page` |
| `/RichMedia`, `/Screen`, `/3D`, `/Movie`, `/Sound` | content dropped, subtype neutralised | `_strip_pdf_page` |
| Outline (bookmark) actions | walked + deleted (cycle-guarded) | `_strip_pdf_outlines` |
| `/EmbeddedFile` at catalog | dropped via `/Names` | `cdr_pdf` |
| **`/ObjStm` — JS hidden inside a compressed object stream** | **[verified] neutralised.** A JS object packed into an `/ObjStm` is still removed: pikepdf resolves objects through the stream, the strip deletes the reference, and `pdf.save()` re-serialises without the orphan. `app.alert` payload absent from output | crafted ObjStm PDF → `cdr_pdf` |
| **Hex-name obfuscation `/S /J#61vaScript`** | **[verified] neutralised.** pikepdf normalises the name on parse, so the action is recognised and `/OpenAction` is removed; payload absent | crafted obfuscated-name PDF |
| **Encrypted PDF (empty/standard user password)** | **[verified] disarmed.** pikepdf opens transparently; strip runs normally | crafted encrypted PDF |
| **Encrypted PDF (unknown password)** | **[verified] fail-closed.** raises `PasswordError` → handler quarantines to `error/`, re-raises; never passed through | crafted pw-protected PDF |
| Appended/polyglot bytes after `%%EOF`, incremental-update layers | dropped — `pdf.save()` re-serialises a single clean revision | `cdr_pdf` save |

### PDF gaps — resolved

- **`/JBIG2Decode` and `/JPXDecode` — FIXED.** pdfid flags JBIG2 for its decoder-RCE history
  (CVE-2009-0658; the FORCEDENTRY CVE-2021-30860 family). The CDR now detects these
  decoder-RCE-prone image filters on *any* stream (page/form XObjects, soft masks, appearance
  streams) and **neutralises** the stream — replaces its bytes with a 1×1 inert image and
  drops the filter — so the crafted payload never reaches a viewer's JBIG2/JPX decoder, while
  the PDF stays valid. Detect-and-neutralise (not reject) avoids false-positives on legitimate
  scanned documents that use JBIG2. `_neutralise_pdf_risky_image_filters`,
  `_RISKY_IMAGE_FILTERS`. **[verified]** — `TestStevensGapRegressions::test_jbig2_image_filter_neutralised`,
  `test_jpx_image_filter_neutralised`, and a clean-PDF no-op test.
- **Inline-image JBIG2/JPX — FIXED (found by adversarial audit of the first fix).** A risky
  filter can also ride an *inline image* (`BI … /F /JBIG2Decode … ID … EI`) inside a
  page/XObject content stream. That lives in operator tokens, not a stream object, so the
  object sweep above never saw it — and it **survives `pdf.save()`** (re-encoded but intact,
  verified by decoding the saved content stream). Fix: scan content streams via
  `pikepdf.parse_content_stream` and **hard-reject** any PDF with an inline image using a
  risky filter (`_reject_inline_risky_images`). Inline JBIG2/JPX is spec-violating and
  vanishingly rare, so fail-closed rejection is correct and won't false-positive (a
  benign-inline-image test confirms no over-reject). **[verified]** —
  `test_inline_image_jbig2_rejected`, `test_inline_image_benign_filter_not_rejected`.

  > **Superseded — this section overstated its own coverage until 2026-08-13 (PR #88).**
  > "Scan every content stream" described the intent, not the code. The implementation
  > enumerated *known containers*: page content streams, `/XObject` entries one level below
  > the page **gated on `/Subtype == /Form`**, and `/AP` appearance streams. Six containers
  > were never reached — a form XObject nested inside another, a form XObject with no
  > `/Subtype` (an attacker-written discriminator), Type3 `/CharProcs` glyph procedures,
  > tiling `/Pattern` streams, and ExtGState `/SMask /G` groups — each confirmed to carry an
  > inline `/JBIG2Decode` payload into the sanitised bucket. Worse, a blanket
  > `except Exception: continue` around the operand loop swallowed the sweep's **own**
  > rejection, so even the containers it did reach failed open. Both are fixed: the sweep now
  > walks `_walk_pdf_nodes` and checks every reachable stream, with the `try` scoped to
  > operator extraction only. See pitfall #53; pinned by `TestInlineRiskyImageContainers`.
- **Fail-open swallow — FIXED (audit).** The first cut caught all per-object exceptions and
  only `debug`-logged them, so a stream *identified as risky* that failed to mutate would
  silently survive in a "sanitised" file (worst outcome for a CDR control; inconsistent with
  the handler's fail-closed quarantine). Now a failure after a stream is identified as risky
  (or an unparsable `/Filter`) **re-raises** → the handler quarantines the whole PDF.
  **[verified]** — `test_malformed_filter_fails_closed`.
- **`/XFA`** is only stripped inside the `/AcroForm` branch. XFA lives in AcroForm, so this
  is correct — confirmed it is the only place XFA can appear. No gap.
- **Parser-strength cases now have regression tests.** ObjStm-hidden JS, hex-obfuscated
  action names, encrypted-empty-password disarm, and unknown-password fail-closed are pinned
  by `TestStevensGapRegressions` so a future pikepdf change can't silently regress them.

**Verdict: no open PDF residuals _within pdfid's enumeration_.** Every technique pdfid
enumerates is neutralised — including the parser-defeating ones (ObjStm, name obfuscation)
and the decoder-RCE filters (JBIG2/JPX) — and all are now regression-tested.

> **How this verdict has aged — read before trusting it.** It was accurate against pdfid's
> enumeration and is *still* scoped to exactly that. It is not a statement about the PDF
> attack surface, and treating it as one is what hid the next round of gaps. Auditing the
> same code against a different taxonomy (jonaslejon/malicious-pdf) found three more live
> vectors pdfid does not enumerate — catalog `/Threads`, `/FontMatrix` JS injection
> (CVE-2024-4367), and a UNC stream `/F` external ref with no action object (PR #85,
> pitfall #51) — and adversarial audits of *those* fixes found four more classes of bug in
> the fixes themselves: an attacker-controlled `/Subtype` gate, `bool` passing an `int`
> check, `pdf.objects` missing every direct (inline) object (#87, pitfall #52), and the
> container-enumeration/swallowed-rejection pair above (#88, pitfall #53). None of these
> contradict the verdict; all of them sat outside its scope. **Re-audit against a fresh
> taxonomy rather than re-reading this line.**

> **Scope warning.** This verdict is bounded by what pdfid looks for. It is *not* a
> statement that the PDF path has no gaps. A later pass against the
> [jonaslejon/malicious-pdf](https://github.com/jonaslejon/malicious-pdf) taxonomy found
> three live vectors that pdfid does not enumerate and this document therefore missed:
> catalog `/Threads`, `/FontMatrix` JS injection (CVE-2024-4367), and UNC paths in stream
> `/F` external file specs. All three are now fixed and pinned by
> `TestMaliciousPdfTaxonomyGaps`. Treat a clean bill of health here as "clean against this
> one toolkit", and re-audit against a new taxonomy rather than reading it as coverage.

---

## 3. `zipdump.py` — ZIP / OOXML container

`zipdump` surfaces ZIP-level tricks: extra entries not referenced by the package,
local-vs-central directory mismatches, nested/embedded ZIPs, non-standard compression,
data appended after the central directory, duplicate names.

| ZIP trick | CDR disposition | Where |
|---|---|---|
| Non-standard compression method (not stored/deflate) | **hard reject** | `_validate_zip_structure` |
| Local-header vs central-directory method mismatch | **hard reject** (reads raw local header bytes) | `_validate_zip_structure` |
| Duplicate entry names (parser-divergence trick) | **hard reject** | `_validate_zip_structure` |
| Arbitrary archive renamed `.docx` (no `[Content_Types].xml`) | **hard reject** | `_validate_zip_structure` |
| Bad magic bytes | **hard reject** | `_validate_zip_structure` |
| Hidden/extra parts not referenced by any `.rels` | **dropped on rebuild** — `cdr_office` only re-emits known-safe parts; dangerous prefixes/suffixes are stripped regardless of references | `STRIP_ZIP_ENTRIES`, rebuild loop |
| Decompression bomb (small entry, huge inflate) | **bounded** — chunked counter, never trusts `file_size` | `_read_zip_entry_safe` |
| Embedded OLE/package objects (`embeddings/*.bin`) | dropped (part + rel) | `STRIP_ZIP_ENTRIES`, `STRIP_REL_TYPES` |
| PostScript/EPS smuggled as `media/*.png` via Override | dropped (two independent mechanisms) | `_postscript_override_parts` + suffix rule |

### ZIP gaps / things to confirm

- **Data appended after the central directory / before the local header (ZIP polyglots).**
  `_validate_zip_structure` checks magic at offset 0 and uses Python's `zipfile`, which reads
  from the central directory. Bytes *appended after* the archive, or a prepended polyglot,
  are not explicitly inspected. However: `cdr_office` **rebuilds** the archive entry-by-entry
  into a fresh ZIP, so appended/prepended junk is **not carried into the output** — the
  output contains only the re-emitted entries. **Confirmed empirically 2026-08-14** (see the
  container-layer sweep below): appended-after-EOCD, 4096 bytes prepended, an entry present
  in the local headers but omitted from the central directory, NUL-truncatable and
  trailing-space entry names, and backslash separators were all probed against the real
  `cdr_office`; none reached the output. The rebuild is indeed the mitigation.
- **Nested ZIP inside an OOXML part** (e.g. a `.zip` stored as an embedded object). Embedded
  objects under `embeddings/` are dropped; a nested ZIP stored under an *unknown* part name
  would be re-emitted as opaque bytes. It cannot execute on its own (it's just a file inside
  the doc), but it's content the gateway didn't inspect. Mirrors the deferred
  "unknown-part-family allowlist" note in CLAUDE.md pitfall #40. **Severity: low** (inert
  unless a consumer extracts and opens it).

**Verdict: strong on structural attacks** (all hard-rejected), and the rebuild-not-rewrite
design neutralises most hiding. Residuals are low-severity (nested/opaque content) and
mostly already noted as deferred decisions.

---

## 4. `emldump.py` — MIME / MHTML / ActiveMime wrapping

`emldump` handles MIME containers (`.eml`, `.mht`) that wrap OLE/ActiveMime payloads — the
CVE-2014-6352 / "ActiveMime" style smuggling, and Word's MHTML import.

| Technique | CDR disposition | Where |
|---|---|---|
| `<w:altChunk>` importing external HTML/MHTML/RTF | **neutralised** — `aFChunk`/`afChunk` rel dropped (both spellings) **and** the `<w:altChunk>` element renamed so it can't fire even if a rel survives | `STRIP_REL_TYPES`, `_neutralise_altchunk` (both `<w:altChunk/>` and paired forms) |
| Standalone `.eml`/`.mht`/`.mhtml` upload | **fail-closed** — not a handled extension → `unsupported-format`, quarantined + deleted | unknown-extension gate |
| ActiveMime/OLE smuggled via altChunk | covered by the altChunk neutralisation above (the import vector is killed before the payload matters) | — |

**Verdict: no gap.** The two routes emldump cares about — MHTML-as-a-file and
MHTML-imported-via-altChunk — are respectively fail-closed and explicitly neutralised
(belt-and-suspenders: rel *and* element).

---

## Summary scorecard

| Area | Coverage | Residual |
|---|---|---|
| OLE2 / VBA (`oledump`) | ✅ reject container / drop part | none |
| PDF active content (`pdfid`/`pdf-parser`) | ✅ all enumerated vectors neutralised, incl. ObjStm + name-obfuscation + JBIG2/JPX decoder filters **[verified, regression-tested]** | none open *within pdfid's enumeration* — see the scope warning above; `/Threads`, `/FontMatrix`, and UNC stream `/F` were found later via a different taxonomy |
| ZIP/OOXML structure (`zipdump`) | ✅ all structural anomalies hard-rejected; rebuild-not-rewrite | nested/opaque content inside unknown parts (low, deferred); ZIP-polyglot append — confirm rebuild drops it |
| MHTML/ActiveMime (`emldump`) | ✅ altChunk neutralised + standalone fail-closed | none |

---

## Recommended work — status

1. ✅ **DONE — regression-test the parser-strength PDF cases.** `TestStevensGapRegressions`
   covers JS-in-`/ObjStm`, hex-obfuscated action name, encrypted-empty-password disarm, and
   unknown-password fail-closed.
2. ✅ **DONE — JBIG2 decided & implemented.** Decision: **detect-and-neutralise** (not reject)
   `/JBIG2Decode` and `/JPXDecode` image streams — see `_neutralise_pdf_risky_image_filters`.
   Reject would false-positive on legitimate scanned PDFs; neutralise keeps the document valid
   while denying the decoder a crafted payload.
3. ✅ **DONE — ZIP-polyglot regression fixture.** `test_zip_polyglot_appended_bytes_dropped`
   pins that appended-after-EOCD bytes do not survive the `cdr_office` rebuild.
4. **(Deferred, unchanged)** unknown-part-family allowlist — already analysed in CLAUDE.md
   pitfall #40; revisit only with a real Office corpus to bound false positives.

The design (parse-don't-scan, rebuild-don't-rewrite, fail-closed) held up well against the
full Stevens technique set; the one real residual (JBIG2/JPX decoder filters) is now closed,
and the parser-strength behaviours are regression-protected.

**Update (2026-08-13).** The *design* verdict still holds — every gap found since sat in an
implementation that had drifted from the design, never in the design itself. But the
implementation was not as complete as this report implied. Four subsequent PRs (#85–#89)
closed ten further vectors across three pitfalls (#51–#53), plus one in the Office path
(#54): `cdr_office` dispatched its XML macro scrub on **filename suffix**, so a document
part stored as `word/document.bin` and declared wordprocessingml via an OPC `Override`
skipped the scrub entirely — python-docx opened the *sanitised* file and still saw a live
`DDEAUTO … cmd.exe` field code. The recurring shape across all of them is a sweep trusting
something the attacker writes (a `/Subtype`, a filename suffix) or enumerating containers
instead of walking the graph.

**Update (2026-08-14) — the container layer, swept as a taxonomy in its own right.** Every
audit up to this point (this report, jonaslejon/malicious-pdf, ClamAV, DocBleach) targets
document *content*. The **package/container layer** — which bytes constitute the document at
all — had never been swept deliberately; #54 surfaced from it only incidentally. Sweeping it
produced one live bypass and one clean bill of health, and the contrast between them is the
useful result.

*OOXML/OPC container — one live bypass (#55, PR #91).* OPC declares content types through
**two** elements, both authoritative: `Override` binds one exact PartName, `Default` binds
every part with a given extension. Pitfall #54 closed the `Override` half and left `Default`
entirely unguarded. A package with **no `Override` at all** — just
`<Default Extension="dat" ContentType="…wordprocessingml.document.main+xml"/>` plus an
`officeDocument` relationship pointing at `word/doc.dat` — skipped the XML macro scrub, and
python-docx opened the *sanitised* output and still saw a live `DDEAUTO … cmd.exe` payload.
Five variants bypassed. Fixed by resolving both elements through one shared
`_declared_parts()`, so the PostScript and XML halves can no longer drift.

*PDF container — no bypass found; structurally immune.* Probed with the payload as a
reachable `/OpenAction` JavaScript action: incremental updates repointing `/Root` at a
payload catalog, a stale payload catalog left in the file, **hybrid-reference `/XRefStm`**
files where a classic-xref reader and an xref-stream reader resolve the same object number
to different offsets, two `%PDF-` headers in either order, ObjStm/xref-stream containers,
linearised files, and encrypted files. All cleaned. The reason is `cdr_pdf`'s closing
`pdf.save()`: it rebuilds from the reachable object graph and emits **one revision**
(verified — single `startxref`, single `%%EOF`). Every attack in this class works by leaving
*two* candidate documents in one file and steering which the reader picks; a rebuild that
emits one document destroys the primitive by construction. Two incidental confirmations:
encryption is **stripped** rather than propagated (sanitised output is never an opaque blob
to downstream scanners), a password-protected PDF raises `PasswordError` and is quarantined
to `error/` rather than passed through, and the documented "header within the first 1024
bytes" rule matches the code exactly (≤1024 accepted and cleaned, beyond → `CdrReject`).

**The generalisable finding is the contrast, not either verdict.** `cdr_pdf` rebuilds the
*document*; `cdr_image` rebuilds *pixels*; both are immune to their whole container bug
class. `cdr_office` rebuilds the ZIP **entry-by-entry, preserving part bytes**, which is
deliberate (rebuild-don't-rewrite, so nothing untouched is mangled) but leaves the package
layer attacker-influenced — which is why declaration bugs like #54 and #55 are reachable
there and nowhere else. **When auditing a new subsystem, ask what its rebuild strategy
reconstructs; that predicts which bug classes can exist at all.** No code or tests were added
for the PDF sweep: there is no defect, and pinning behaviour supplied by a third-party
rebuild would test QPDF rather than this codebase.

*Cross-engine confirmation (2026-08-14).* The sweep's verdicts were re-run against mupdf,
poppler and pdf.js — three engines independent of pikepdf/QPDF. All agree: the inputs carry
live JavaScript, the sanitised outputs carry none. Details and the retraction of the
"classic-only reader" framing are under **Known limits** below.

**Known limits of every claim in this document.** Verification here is against **pikepdf,
python-docx, openpyxl and Pillow** — not Acrobat or Word. That is strong evidence a real
consumer behaves the same way, and it is what confirmed the #54 and #55 bypasses were live
rather than inert, but it is not proof. Divergence between those parsers and the shipping
viewers would not be caught by anything in this report or the test suite.

This limit **no longer applies to the PDF verdicts**, which were cross-checked on 2026-08-14
against three engines sharing no code with pikepdf/QPDF: **mupdf 1.28.2**, **poppler**
(`pdfinfo`/`pdftotext`) and **pdf.js 4** — the last being what ships in Firefox. All eight
sanitised PDFs in `docs/viewer-validation/` are clean in all three (no JavaScript, no
`/OpenAction`, no attachments), and a positive control confirms the probes detect the payloads
in 7 of the 8 corresponding inputs, so the clean result is a real signal rather than a broken
probe. The eighth, `pdf_lejon_multithreat`, carries `/GoToR` as its only vector — present in
the input, absent from the output — and scored zero only because the mupdf grep pattern
omitted that key.

**The "classic-only reader" concern is retired, and it was misstated.** The incremental-update
fixture puts the JavaScript in the **newer** revision (`/Root 5 0 R`); the older catalog is
clean. A reader honouring the latest `startxref` — i.e. any modern parser — is therefore the
one that reaches the payload, not a legacy one. All four engines resolve the input to the
payload catalog and the sanitised output to the clean catalog; none follows an alternate
branch. There is no evidence a reader exists that resolves these files differently, and the
verdict continues to rest on the directly-verified fact that the rebuild emits one revision.

The limit stands **in full for the Office paths**, which is where it matters most: both
confirmed live bypasses (#54, #55) were OPC declaration bugs, and no equivalent
independent-engine check has been run against Word, Excel or PowerPoint. See
`docs/viewer-validation/CHECKLIST.md` for the manual pass that would close it.

---

## References

- oledump.py — <https://blog.didierstevens.com/2014/12/17/introducing-oledump-py/>
- PDF tools (pdfid, pdf-parser) — <https://blog.didierstevens.com/programs/pdf-tools/>
- Didier Stevens' blog (zipdump, emldump, maldoc series) — <https://blog.didierstevens.com/>
