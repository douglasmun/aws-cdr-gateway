# Viewer-validation corpus

**Why this exists.** Every CDR verdict in this repo is confirmed against **pikepdf, python-docx, openpyxl and Pillow** — never against Acrobat or Word. That matters more than it sounds: the bug class we keep finding (pitfalls #49, #54, #55) *is* parser disagreement — a real consumer resolving a part differently than the test parser does. Verifying only against Python parsers means the test oracle shares a blind spot with the thing being tested.

This corpus closes that gap the only way it can be closed: **a human opens the sanitised files in the real viewers.**

Everything here has already been checked with the Python parsers and is payload-free by that measure. What is unverified — and what you are being asked to check — is whether the **real viewers agree**.

**Status, 2026-08-14: the manual pass is COMPLETE — 13 of 13 PASS.** All five Office outputs were opened in **Word and Excel** and all eight PDFs in **Acrobat**. No repair prompt, no macro warning, no remote-data or DDE prompt, no JavaScript alert, no attachment, no network-location prompt, no password prompt, and nothing launched — in the real viewers, not just the Python parsers. Details in the Word, Excel and Acrobat sections below.

**One file is now waiting on you: `pptm_vba_realistic.pptx`.** PowerPoint was the last unverified engine, and it could not be checked at all because the corpus had no loadable `.pptx` — `pptx_activex` is an excluded empty-`_rels` fixture whose *input* no engine can open. A genuine presentation carrying a VBA project and a remote-template link has now been built for it (Priority 2b below), so the gap is a viewer check rather than a missing fixture.

## How to run it

1. Open each file in `sanitised/` with the **real** application (not Preview, not Quick Look, not Google Docs — those are different parsers again and would just move the blind spot).
2. For each, check the two questions in the table: **does it open cleanly** (fidelity) and **is the threat inert** (security).
3. Record the result in the Result column. Anything in the **Red flags** section below is a finding — stop and report it.

`originals/` holds the corresponding malicious inputs, for reference only. **Do not open those in a viewer** — several carry live payloads; that is the point of them.

## What counts as a pass

| | Pass | Fail |
|---|---|---|
| **Fidelity** | Opens with no repair/recovery prompt; text, tables and images render | "Word found unreadable content", blank document, missing content |
| **Security** | No macro warning, no "update links"/"remote data" prompt, no JavaScript alert, no attachment pane entry, nothing launches | Any prompt offering to fetch remote data or run code |

A **repair prompt is a fidelity failure, not a security failure** — worth reporting either way, but they mean different things.

## The files

### Priority 1 — the two bypasses fixed this week

These are the reason the corpus exists. Both were **live bypasses**: python-docx opened the sanitised output and still saw an executable `DDEAUTO` field. Fixed in PR #91 (#55) and PR #89 (#54).

| File | What to check | Result |
|---|---|---|
| `p55_realistic.docx` | **Highest-value file here.** A real python-docx document (heading, styled runs, 2×2 table) whose main part was relocated to `word/doc.dat` and declared solely by `<Default Extension="dat">`. Word must render heading, bold run, and table, with **no DDE/remote-data prompt**. | **PASS — Word, 2026-08-14.** Full fidelity: Title style, all four paragraphs, bold run, 2×2 table with all cells. No repair prompt. **No remote-data prompt and nothing launched.** The `DDEAUTO _CDR_REMOVED_ "/c calc.exe"` line rendered as **plain prose**, not a resolved field — pitfall #13 residue behaving exactly as designed. |
| `p55_default_dat.docx` | Minimal version of the same #55 vector — declared by `Default Extension`, no `Override` at all. | **PASS — Word, 2026-08-14.** Opens cleanly, no repair prompt, both paragraphs render. **No remote-data prompt and nothing launched.** Word resolved the `Default`-declared part (it displayed the content) yet executed nothing; both the self-describing prose and the `_CDR_REMOVED_` residue rendered as plain text. |
| `p54_override_bin.docx` | Pitfall #54: document part named `.bin`, declared XML via an `Override`. | **PASS — Word, 2026-08-14.** Opens cleanly, no repair prompt, both paragraphs render. **No remote-data prompt and nothing launched.** Word rendered the part despite its `.bin` name — so it honoured the `Override` rather than the suffix — and still executed nothing. |

> **Expected residue — not a finding.** The scrubbed field reads `DDEAUTO _CDR_REMOVED_ "/c calc.exe"`. The *executable path* is replaced; the inert string `calc.exe` survives inside the quoted argument (pitfall #13). Word has no DDE target to resolve, so nothing launches. **Seeing `calc.exe` in the XML is expected; being *prompted* to update remote data is not.**

> **Visible fixture prose — also not a finding.** `p55_default_dat.docx` and `p54_override_bin.docx` render the sentence *"…carried a DDEAUTO field code before sanitisation."* as ordinary body text. That is the fixture describing itself, not a live field — it is prose in a `<w:t>` run, not a `w:instrText`/`w:fldSimple` carrier, so there is nothing for Word to execute. Worth knowing because a naive check for the string `DDEAUTO` matches it: a scripted pre-check of this corpus reported both files as live bypasses for exactly this reason before the match was inspected in context. **The signal is a prompt, never the presence of a word.**

### Priority 2 — Office fidelity

| File | What to check | Result |
|---|---|---|
| `macro-sample.docx` | Input was `.docm`; output is `.docx` by `EXT_REMAP`. Must open cleanly, and **Alt+F8 should list no macros**. | **PASS — Word, 2026-08-14.** Heading 1 styled, all four paragraphs render, no repair prompt. **Alt+F8 lists no macros** — the `.docm`'s `vbaProject.bin` is gone and Word has nothing to offer. |
| `xlsm_vba_realistic.xlsx` | Input `.xlsm` → output `.xlsx`. Cell values and formulas intact; no macros. **Expect a slow open** — `sheet1.xml` is ~29 MB of size-cap padding inside a 3 MB file. A pause is not a hang. | **PASS — Excel, 2026-08-14.** Opens with no repair prompt; header styling and all ten columns render. `I2` shows `=G2*H2` in the formula bar, so formulas survive as formulas rather than frozen values. `Summary` opens and its cross-sheet `SUMIF` resolves — no `#REF!`. **Alt+F8 lists no macros.** Corroborated structurally: both worksheet parts are byte-identical to the input, and `xl/vbaProject.bin` is the only ZIP entry CDR removed. |

### Priority 2b — PowerPoint (added 2026-08-14)

Built to close the last engine gap. The repo's `pptx_activex` fixture could not do it: its `_rels/.rels` is empty, so **no engine can load the input** and PowerPoint rejecting it would say nothing about CDR. `pptm_vba_realistic.pptx` is a genuine presentation — real `officeDocument` relationship, slide master, layout, theme and actual slide text — carrying a **VBA project** and an **external `attachedTemplate`** rel.

| File | What to check | Result |
|---|---|---|
| `pptm_vba_realistic.pptx` | Input was `.pptm`; output is `.pptx` by `EXT_REMAP`. **Both text boxes must render.** No macro warning (Developer → Macros lists none), and **no prompt to fetch a remote template**. | |

Verified before asking: CDR reports removing the `vbaProject` content type, the macro-enabled `main+xml` content type, the `vbaProject` and `attachedTemplate` rels, and `ppt/vbaProject.bin`. **6 threat indicators in the input, 0 in the output, slide text preserved**, and both input and output load in LibreOffice. The generator asserts each of those, so a regression fails the build rather than quietly emitting a useless fixture.

> **A probe bug worth not repeating.** The first version of that check scanned the **raw ZIP bytes** and reported every marker absent — from the *input* as well. The entries are deflated, so a byte grep finds nothing and the file reads perfectly clean. Decompress the parts before scanning. This is the same shape as the `pdf_lejon_multithreat.pdf` blind spot below: **the probe, not the file, was clean.**

### Priority 3 — PDF, in Acrobat

> Several files here are ~3 MB because the source fixtures carry a deliberate padding stream (they double as size-cap tests). The padding is inert filler, not content — ignore the file sizes.

> **A blank page is not automatically a fidelity failure here.** Most of these are *synthetic* fixtures: built to carry one payload in the PDF structure, with no page content ever authored. Their `/Contents` is absent in the **input** too, so a blank render means nothing was there to begin with, not that CDR ate it. The way to tell the difference is always the same — **compare against the input**, never against an assumption about what a document "should" look like.
>
> Measured across all eight (total page-content-stream bytes, input → output, 2026-08-14), so it does not need re-deriving file by file:
>
> | File | In → Out | Meaning |
> |---|---|---|
> | `pdf_javascript_realistic.pdf` | 55,422 → 55,422 | **the real fidelity test** — a genuine 24-page document, preserved byte for byte. A blank or truncated render *here* is a finding |
> | `pdfc_incremental_update.pdf` | 51 → 51 | content preserved |
> | the other six | 0 → 0 | **blank by design** — no content in the input either |
>
> So for six of eight, a blank white page is the expected outcome and only the security question is live.

| File | What to check | Result |
|---|---|---|
| `pdf_openaction_js.pdf` | Opens with **no JavaScript alert**. **A blank white page is the correct result** — see note below; do not read it as over-stripping. | **PASS — Acrobat, 2026-08-14.** Opens, blank white page, **no JavaScript alert**. The `/OpenAction` JS that Acrobat would have run on open is gone. Blank is expected: the input has no `/Contents` either (verified), so there was never any page content to lose. |
| `pdf_acroform_js.pdf` | Blank page expected. No JS on open/focus/calculate. `/AcroForm` is *present* by design — field geometry is kept, actions stripped. | **PASS — Acrobat, 2026-08-14.** Opens blank, no JavaScript alert. The 4 `/JS` tokens in the input are gone while `/AcroForm` survives with no `/XFA`. |
| `pdf_embedded_file.pdf` | Blank page expected. **No attachment offered.** | **PASS — Acrobat, 2026-08-14.** Opens blank, nothing offered. Structurally confirmed: `/Names/EmbeddedFiles` is gone and `/Filespec`+`/EmbeddedFile` tokens drop 3→0, so the pane has nothing to list. |
| `pdf_multithreat.pdf` | Blank page expected. Several vectors stripped at once — no alert, no attachment. | **PASS — Acrobat, 2026-08-14.** Opens blank, no alert, nothing offered. `/OpenAction` and `/Names/EmbeddedFiles` gone, 4 `/JS` and 3 `/Filespec`/`/EmbeddedFile` tokens → 0; `/AcroForm` retained by design. |
| `pdf_lejon_multithreat.pdf` | Blank page expected. malicious-pdf taxonomy sample — `/Threads`, a `GoToR` UNC link, a poisoned `/FontMatrix` and two external-stream `/F` refs. **No prompt to open a network location.** | **PASS — Acrobat, 2026-08-14.** Opens blank, no network-location prompt. 8 vector tokens in the input → 1 benign structure out; the `GoToR` UNC target and both `attacker.invalid` external-stream refs are gone, and `/FontMatrix` is six clean numbers. |
| `pdf_javascript_realistic.pdf` | **The fidelity stress case** — a genuine 24-page document, and the one file here where a blank render would be a finding. All pages render, no script. | **PASS — Acrobat, 2026-08-14.** Renders as a real document: "Quarterly Business Review" heading plus body text per page, pages sequential. **No JavaScript alert.** Byte-level confirmation: 24 pages in → 24 out, all 24 headings and all 55,422 content-stream bytes preserved exactly, while the 9 `/JS` tokens drop to 0 and `/OpenAction` + `/AA` are gone. `/Names` survives as an **empty** dictionary — the `/JavaScript` name tree holding the `app.alert` payload is gone, and an empty `/Names` gives Acrobat nothing to enumerate. |

### Priority 4 — PDF container layer (the 2026-08-14 sweep)

These probe the claim that `pdf.save()` collapses multi-revision containers into one document. The sweep found no bypass **against pikepdf**; Acrobat is the independent check.

| File | What to check | Result |
|---|---|---|
| `pdfc_incremental_update.pdf` | Input had two revisions, the newer pointing at a JavaScript catalog. Output must show **no JS alert** — confirms the rebuild collapsed them. | **PASS — Acrobat, 2026-08-14.** Renders (near-blank, 51 bytes of content preserved exactly), **no JavaScript alert**. Acrobat resolves one document, so `pdf.save()` did collapse the revisions rather than leaving the newer JS catalog reachable — the specific claim this file exists to test. |
| `pdfc_encrypted_input.pdf` | Input was **encrypted**; output should open with **no password prompt** (encryption is stripped by design) and no JS alert. | **PASS — Acrobat, 2026-08-14.** Opens straight to a blank page — **no password prompt**, no JavaScript alert. Encryption stripped as designed and the `/OpenAction` JS gone with it. |

### What pikepdf already says about these eight — and why that is not the answer

Re-checked 2026-08-14, before the Acrobat pass, so you know what a disagreement would look like. By pikepdf all eight are clean: **no `/OpenAction`, no catalog `/AA`, no `/Names/JavaScript`, no `/Names/EmbeddedFiles`, no page `/AA`, no annotation actions, zero `/JS` tokens, zero `/Filespec` or `/EmbeddedFile` tokens, and none still encrypted.** `/AcroForm` survives in `pdf_acroform_js.pdf` and `pdf_multithreat.pdf` by design — field geometry is kept, actions stripped — and neither retains `/XFA`.

`pdf_lejon_multithreat.pdf` was verified separately because its vectors are different in kind: **8 vector tokens in the input, 1 benign structure out.** `/Threads`, the `/Type /Thread` object, the `GoToR` UNC link, both `attacker.invalid` external-stream `/F` refs and the `CDR_TEST_MULTI_PWNED` marker are all gone. `/FontMatrix` remains — it is a legitimate Type3 font key — but now holds six numbers, the injected `(0);globalThis…//` string having been stripped from element 5 with the structure intact. The link annotation keeps its `/Rect` and loses its `/A`.

**This is the oracle with the known blind spot, so it settles nothing on its own.** It is recorded here for one reason: if Acrobat prompts on any of these, the disagreement is the finding, and knowing pikepdf saw nothing is what makes it diagnosable.

> **A probe gap found while writing this, worth repeating.** The first sweep reported all eight clean *and* the positive control fired on only 7 of 8 — `in_pdf_lejon_multithreat.pdf` showed nothing even as a malicious input. The probe was looking for `/JS`, `/OpenAction` and `/Filespec`; that fixture carries none of them. Its threats are `/Threads`, `GoToR`, `/FontMatrix` and external `/F` refs, so the probe was blind to the entire file and its silence read exactly like a clean result. **A positive control that fires on most inputs is not a passing control** — the one row that stays quiet is the one to chase, because it means the probe and the fixture disagree about what the threat even is.

## Red flags — report immediately

- Any **"update links" / "remote data" / DDE prompt** in Word → a #54/#55-class bypass is live in the real viewer.
- Any **macro warning**, or macros listed under Alt+F8.
- Any **JavaScript alert** in Acrobat, or an entry in the attachments pane.
- A **password prompt** on `pdfc_encrypted_input.pdf` (encryption should have been stripped).
- Anything that **launches a process**.

## Already checked for you — LibreOffice, 2026-08-14

Before you spend time in Word, a second *independent* Office engine has been run over the corpus: **LibreOffice 26.2.5.2**, headless, converting each sanitised file and inspecting the rendered text. This is not python-docx, so it is a genuine cross-implementation check.

| File | LibreOffice result |
|---|---|
| `p55_realistic.docx` | Opens. Heading, bold run, **2×2 table** and closing line all render. |
| `p55_default_dat.docx` | Opens. Field rendered as literal text. |
| `p54_override_bin.docx` | Opens. Field rendered as literal text. |
| `macro-sample.docx` | Opens. All five paragraphs intact. |
| `xlsm_vba_realistic.xlsx` | Opens as a spreadsheet (converts to CSV). |

**No rendered output contains `cmd.exe` or `system32`** — the DDE target is structurally gone, and LibreOffice prints the neutralised field as text rather than resolving it. Every field carrier in every output is `_CDR_REMOVED_`, with zero live `DDEAUTO`/`DDE` carriers in `w:instrText` or `w:fldSimple`.

**What this does not settle, and why you are still needed.** A headless conversion never executes a DDE field, so a clean render proves the payload is *structurally* absent — not that an interactive viewer would decline to prompt. Word deciding whether to offer "update links" is exactly the behaviour no automated check here can reach. That question, and Word's own fidelity, is what the manual pass is for.

## Known exclusions

Six repo fixtures are **excluded by the generator** — not omitted by hand, so a rebuild will not quietly reintroduce them:

`docx_dde_field`, `docx_autoopen_field`, `docx_multithreat`, `docx_vba_macro`, `xlsx_dde_formula`, `pptx_activex`.

All six are synthetic packages with an **empty `_rels/.rels`** — no `officeDocument` relationship, so nothing points from the package root to the document, workbook or presentation. python-docx cannot open the `.docx` ones and LibreOffice cannot load the `.xlsx`/`.pptx` ones. The decisive part: **the inputs fail identically**, so a viewer rejecting them tells you nothing about CDR. They remain valid unit-test fixtures; they are just not viewer-validation material.

The last two were added on 2026-08-14. They had survived the first cut because python-docx only covers `.docx`, so the `.xlsx`/`.pptx` packages were never opened by any parser until LibreOffice was brought in — a reminder that an exclusion criterion needs applying across *every* type it logically covers, not just the one the available parser happened to check.

**Excluding `pptx_activex` left PowerPoint with no coverage at all**, which is a gap rather than a resolution. `pptm_vba_realistic` (Priority 2b) was built to fill it: same threat classes, in a package a viewer will actually open. Excluding an unloadable fixture is correct; leaving the format unrepresented afterwards is not.

## Word — complete, 2026-08-14

All four `.docx` files were opened in **Word itself**, the parser whose disagreement with python-docx defined pitfalls #54 and #55. **4 of 4 PASS**, fidelity and security.

The decisive results are the two live-bypass mechanisms. In `p54_override_bin.docx` Word rendered a part named `.bin`, so it resolved it through the `Override` rather than the file suffix; in `p55_default_dat.docx` and `p55_realistic.docx` Word resolved a part declared solely by `<Default Extension="dat">`. In every case Word reached the part **and executed nothing** — no remote-data prompt, no repair prompt. That is the specific question a headless LibreOffice render could not answer, and it now has an answer for Word.

`macro-sample.docx` adds the macro check: **Alt+F8 lists no macros**, so the `.docm`'s `vbaProject.bin` is genuinely absent rather than merely unreferenced.

Word's verdicts therefore corroborate the Python-parser verdicts rather than contradicting them.

## Excel — complete, 2026-08-14

`xlsm_vba_realistic.xlsx` opened in **Excel itself**: no repair prompt, formulas intact as formulas (`I2` = `=G2*H2`), the `Summary` sheet's cross-sheet `SUMIF` resolving, and **no macros under Alt+F8**.

This file tests the opposite risk from the Word set, and it is worth being explicit about which claim it settles. The Word files asked whether a *real* viewer executes a part the Python parser thought was scrubbed. Here CDR removed exactly one ZIP entry — `xl/vbaProject.bin` — and rewrote nothing: both worksheet parts are byte-identical to the input. So the security claim was nearly settled by the entry list alone, and the open risk was **over-stripping** — Excel rejecting the rebuilt package, or recalculating on open and finding the cross-sheet reference broken. Neither happened. Excel therefore confirms fidelity; it does not add an independent security data point the way Word did.

**Office is complete: 5 of 5 PASS.**

## Acrobat — complete, 2026-08-14

All eight PDFs opened in **Acrobat**. **8 of 8 PASS**: no JavaScript alert anywhere, no attachment offered, no network-location prompt, no password prompt.

Three results carry more weight than the absence of an alert:

- **`pdfc_encrypted_input.pdf` opened with no password prompt.** Encryption is genuinely stripped, not re-applied — which also means the sanitised output is inspectable by downstream tooling rather than opaque.
- **`pdfc_incremental_update.pdf` resolved as a single document.** This is the actual confirmation that `pdf.save()` collapses a multi-revision container rather than leaving the newer JavaScript catalog reachable. It had only ever been checked against pikepdf, and it is precisely the container-layer claim a second parser could have contradicted.
- **`pdf_javascript_realistic.pdf` kept every byte of its 24 pages** while losing all 9 `/JS` tokens. Full fidelity and full disarmament in the same file, in the viewer the format is named for.

Two checks were settled structurally rather than by eye, because a blank page cannot show whether an attachment pane is populated: `/Names/EmbeddedFiles` is absent from both `pdf_embedded_file.pdf` and `pdf_multithreat.pdf`, with `/Filespec`+`/EmbeddedFile` token counts falling to zero, so Acrobat has nothing to enumerate. Where a payload container survives at all it survives **empty** — `pdf_javascript_realistic.pdf` keeps `/Names` as an empty dictionary, and the two `/AcroForm` files keep field geometry with no `/XFA` and no actions. That is the intended shape: structure preserved, behaviour removed.

## Interpreting the outcome

- **All pass** → the Python-parser verdicts throughout `docs/cdr-gap-analysis-stevens.md` and the pitfalls doc are corroborated by the shipping viewers, and the stated limit in those docs can be narrowed.
- **Any security failure** → a real bypass that the entire test suite is currently blind to. That is a new pitfall and a code fix.
- **Any fidelity failure** → CDR is over-stripping or corrupting the rebuild; the file still needs a fix, but it is a usability defect rather than a security one.

Regenerate with `docs/viewer-validation/build_corpus.py`.
