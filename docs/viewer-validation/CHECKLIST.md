# Viewer-validation corpus

**Why this exists.** Every CDR verdict in this repo is confirmed against **pikepdf, python-docx, openpyxl and Pillow** — never against Acrobat or Word. That matters more than it sounds: the bug class we keep finding (pitfalls #49, #54, #55) *is* parser disagreement — a real consumer resolving a part differently than the test parser does. Verifying only against Python parsers means the test oracle shares a blind spot with the thing being tested.

This corpus closes that gap the only way it can be closed: **a human opens the sanitised files in the real viewers.**

Everything here has already been checked with the Python parsers and is payload-free by that measure. What is unverified — and what you are being asked to check — is whether **Word, Excel, PowerPoint and Acrobat agree**.

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
| `p55_realistic.docx` | **Highest-value file here.** A real python-docx document (heading, styled runs, 2×2 table) whose main part was relocated to `word/doc.dat` and declared solely by `<Default Extension="dat">`. Word must render heading, bold run, and table, with **no DDE/remote-data prompt**. | |
| `p55_default_dat.docx` | Minimal version of the same #55 vector — declared by `Default Extension`, no `Override` at all. | |
| `p54_override_bin.docx` | Pitfall #54: document part named `.bin`, declared XML via an `Override`. | |

> **Expected residue — not a finding.** The scrubbed field reads `DDEAUTO _CDR_REMOVED_ "/c calc.exe"`. The *executable path* is replaced; the inert string `calc.exe` survives inside the quoted argument (pitfall #13). Word has no DDE target to resolve, so nothing launches. **Seeing `calc.exe` in the XML is expected; being *prompted* to update remote data is not.**

> **Visible fixture prose — also not a finding.** `p55_default_dat.docx` and `p54_override_bin.docx` render the sentence *"…carried a DDEAUTO field code before sanitisation."* as ordinary body text. That is the fixture describing itself, not a live field — it is prose in a `<w:t>` run, not a `w:instrText`/`w:fldSimple` carrier, so there is nothing for Word to execute. Worth knowing because a naive check for the string `DDEAUTO` matches it: a scripted pre-check of this corpus reported both files as live bypasses for exactly this reason before the match was inspected in context. **The signal is a prompt, never the presence of a word.**

### Priority 2 — Office fidelity

| File | What to check | Result |
|---|---|---|
| `macro-sample.docx` | Input was `.docm`; output is `.docx` by `EXT_REMAP`. Must open cleanly, and **Alt+F8 should list no macros**. | |
| `xlsm_vba_realistic.xlsx` | Input `.xlsm` → output `.xlsx`. Cell values and formulas intact; no macros. **Expect a slow open** — `sheet1.xml` is ~29 MB of size-cap padding inside a 3 MB file. A pause is not a hang. | |
| `xlsx_dde_formula.xlsx` | DDE formula neutralised; **other cell values must be intact**. | |
| `pptx_activex.pptx` | ActiveX control removed; slides must still render. | |

### Priority 3 — PDF, in Acrobat

> Several files here are ~3 MB because the source fixtures carry a deliberate padding stream (they double as size-cap tests). The padding is inert filler, not content — ignore the file sizes.

| File | What to check | Result |
|---|---|---|
| `pdf_openaction_js.pdf` | Opens with **no JavaScript alert**; page renders. | |
| `pdf_acroform_js.pdf` | Form fields render; no JS on focus/calculate. `/AcroForm` is *present* by design — field geometry is kept, actions stripped. | |
| `pdf_embedded_file.pdf` | **Attachments pane must be empty.** | |
| `pdf_multithreat.pdf` | Several vectors stripped at once; page still renders. | |
| `pdf_lejon_multithreat.pdf` | malicious-pdf taxonomy sample. | |
| `pdf_javascript_realistic.pdf` | 24-page realistic document — the fidelity stress case. Renders fully, no script. | |

### Priority 4 — PDF container layer (the 2026-08-14 sweep)

These probe the claim that `pdf.save()` collapses multi-revision containers into one document. The sweep found no bypass **against pikepdf**; Acrobat is the independent check.

| File | What to check | Result |
|---|---|---|
| `pdfc_incremental_update.pdf` | Input had two revisions, the newer pointing at a JavaScript catalog. Output must show **no JS alert** — confirms the rebuild collapsed them. | |
| `pdfc_encrypted_input.pdf` | Input was **encrypted**; output should open with **no password prompt** (encryption is stripped by design) and no JS alert. | |

## Red flags — report immediately

- Any **"update links" / "remote data" / DDE prompt** in Word → a #54/#55-class bypass is live in the real viewer.
- Any **macro warning**, or macros listed under Alt+F8.
- Any **JavaScript alert** in Acrobat, or an entry in the attachments pane.
- A **password prompt** on `pdfc_encrypted_input.pdf` (encryption should have been stripped).
- Anything that **launches a process**.

## Known exclusions

Four repo fixtures (`docx_dde_field`, `docx_autoopen_field`, `docx_multithreat`, `docx_vba_macro`) are **deliberately excluded by the generator** — not omitted by hand, so a rebuild will not quietly reintroduce them. They are synthetic packages with no `officeDocument` relationship — python-docx cannot open the *inputs* either, so Word would reject them for a reason unrelated to CDR and produce a false alarm. They remain valid as unit-test fixtures; they are just not viewer-validation material. `p55_realistic.docx` was built specifically to cover what they cannot.

## Interpreting the outcome

- **All pass** → the Python-parser verdicts throughout `docs/cdr-gap-analysis-stevens.md` and the pitfalls doc are corroborated by the shipping viewers, and the stated limit in those docs can be narrowed.
- **Any security failure** → a real bypass that the entire test suite is currently blind to. That is a new pitfall and a code fix.
- **Any fidelity failure** → CDR is over-stripping or corrupting the rebuild; the file still needs a fix, but it is a usability defect rather than a security one.

Regenerate with `docs/viewer-validation/build_corpus.py`.
