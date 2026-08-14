# Viewer-validation corpus

**Why this exists.** Every CDR verdict in this repo is confirmed against **pikepdf, python-docx, openpyxl and Pillow** — never against Acrobat or Word. That matters more than it sounds: the bug class we keep finding (pitfalls #49, #54, #55) *is* parser disagreement — a real consumer resolving a part differently than the test parser does. Verifying only against Python parsers means the test oracle shares a blind spot with the thing being tested.

This corpus closes that gap the only way it can be closed: **a human opens the sanitised files in the real viewers.**

Everything here has already been checked with the Python parsers and is payload-free by that measure. What is unverified — and what you are being asked to check — is whether the **real viewers agree**.

**Status, 2026-08-14: the Office half is done.** All five `.docx`/`.xlsx` files have been opened in Word and Excel themselves — 5 of 5 PASS, including both live-bypass mechanisms from pitfalls #54 and #55. See the Word and Excel sections below. **The eight PDFs remain unchecked in Acrobat**, and that is what is still being asked for.

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

### Priority 3 — PDF, in Acrobat

> Several files here are ~3 MB because the source fixtures carry a deliberate padding stream (they double as size-cap tests). The padding is inert filler, not content — ignore the file sizes.

| File | What to check | Result |
|---|---|---|
| `pdf_openaction_js.pdf` | Opens with **no JavaScript alert**; page renders. | |
| `pdf_acroform_js.pdf` | Form fields render; no JS on focus/calculate. `/AcroForm` is *present* by design — field geometry is kept, actions stripped. | |
| `pdf_embedded_file.pdf` | **Attachments pane must be empty.** | |
| `pdf_multithreat.pdf` | Several vectors stripped at once; page still renders. | |
| `pdf_lejon_multithreat.pdf` | malicious-pdf taxonomy sample — `/Threads`, a `GoToR` UNC link, a poisoned `/FontMatrix` and two external-stream `/F` refs. Page renders; **no prompt to open a network location**. | |
| `pdf_javascript_realistic.pdf` | 24-page realistic document — the fidelity stress case. Renders fully, no script. | |

### Priority 4 — PDF container layer (the 2026-08-14 sweep)

These probe the claim that `pdf.save()` collapses multi-revision containers into one document. The sweep found no bypass **against pikepdf**; Acrobat is the independent check.

| File | What to check | Result |
|---|---|---|
| `pdfc_incremental_update.pdf` | Input had two revisions, the newer pointing at a JavaScript catalog. Output must show **no JS alert** — confirms the rebuild collapsed them. | |
| `pdfc_encrypted_input.pdf` | Input was **encrypted**; output should open with **no password prompt** (encryption is stripped by design) and no JS alert. | |

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

## Word — complete, 2026-08-14

All four `.docx` files were opened in **Word itself**, the parser whose disagreement with python-docx defined pitfalls #54 and #55. **4 of 4 PASS**, fidelity and security.

The decisive results are the two live-bypass mechanisms. In `p54_override_bin.docx` Word rendered a part named `.bin`, so it resolved it through the `Override` rather than the file suffix; in `p55_default_dat.docx` and `p55_realistic.docx` Word resolved a part declared solely by `<Default Extension="dat">`. In every case Word reached the part **and executed nothing** — no remote-data prompt, no repair prompt. That is the specific question a headless LibreOffice render could not answer, and it now has an answer for Word.

`macro-sample.docx` adds the macro check: **Alt+F8 lists no macros**, so the `.docm`'s `vbaProject.bin` is genuinely absent rather than merely unreferenced.

Word's verdicts therefore corroborate the Python-parser verdicts rather than contradicting them.

## Excel — complete, 2026-08-14

`xlsm_vba_realistic.xlsx` opened in **Excel itself**: no repair prompt, formulas intact as formulas (`I2` = `=G2*H2`), the `Summary` sheet's cross-sheet `SUMIF` resolving, and **no macros under Alt+F8**.

This file tests the opposite risk from the Word set, and it is worth being explicit about which claim it settles. The Word files asked whether a *real* viewer executes a part the Python parser thought was scrubbed. Here CDR removed exactly one ZIP entry — `xl/vbaProject.bin` — and rewrote nothing: both worksheet parts are byte-identical to the input. So the security claim was nearly settled by the entry list alone, and the open risk was **over-stripping** — Excel rejecting the rebuilt package, or recalculating on open and finding the cross-sheet reference broken. Neither happened. Excel therefore confirms fidelity; it does not add an independent security data point the way Word did.

**Office is now complete: 5 of 5 PASS.** PowerPoint has no corpus file (`pptx_activex` is an excluded dead fixture, see below), so the remaining gap is **Acrobat** — the eight PDF files in Priorities 3 and 4.

## Interpreting the outcome

- **All pass** → the Python-parser verdicts throughout `docs/cdr-gap-analysis-stevens.md` and the pitfalls doc are corroborated by the shipping viewers, and the stated limit in those docs can be narrowed.
- **Any security failure** → a real bypass that the entire test suite is currently blind to. That is a new pitfall and a code fix.
- **Any fidelity failure** → CDR is over-stripping or corrupting the rebuild; the file still needs a fix, but it is a usability defect rather than a security one.

Regenerate with `docs/viewer-validation/build_corpus.py`.
