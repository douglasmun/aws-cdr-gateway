# aws-cdr-gateway vs. DocBleach

A point-in-time comparison of this project's CDR coverage against
[DocBleach](https://github.com/docbleach/DocBleach), conducted as part of a gap audit.

**As of:** 2026-06-21.
**DocBleach state:** archived (read-only since 2020-11-09), Java/Apache POI + PDFBox.
**aws-cdr-gateway state:** Python AWS Lambda, ZIP-level OOXML surgery (no Office library
re-serialisation).

This document records *why* certain DocBleach behaviours were adopted, improved on, or
deliberately not copied — so the rationale survives for future contributors. It is a
snapshot, not a living spec; verify against the code (`src/lambda_function.py`) before
relying on any specific claim.

DocBleach ships four modules: **office** (OLE2 + OOXML), **pdf**, **rtf**, and **zip**
(nested-archive recursion). The comparison below is grouped by format.

---

## Summary

| Area | DocBleach | aws-cdr-gateway |
|---|---|---|
| OOXML approach | Re-serialises via Apache POI (can mutate untouched parts) | ZIP-level surgery; untouched parts preserved byte-for-byte |
| Embedded OLE payload | Strips the **relationship** only — `…/embeddings/*.bin` bytes survive | Drops the relationship **and** the part bytes |
| Hyperlinks | **Whitelisted — passed through untouched** | Rewritten inert (defeats UNC NTLM theft / phishing) |
| DDE | Regex on `DDEAUTO` / `ddeService` attributes | Full field-code scrub incl. entity-encoded, ReDoS-bounded |
| PostScript/EPS | Content-type blacklist (declaration only) | Declaration **and** part bytes, two independent mechanisms |
| PDF actions | Allowlist of named action slots | Deletes **all** `/A` / `/AA` unconditionally |
| Unknown extensions | Passed through (best-effort) | **Fail closed** → quarantine, never labelled sanitised |
| Decompression bomb | `byte[1024]` loop, no cap (`@TODO: check real file size?`) | Chunked counter, `_MAX_ENTRY_BYTES`, untrusting of `file_size` |
| xlsb | Not handled | `cdr_xlsb()` value-extraction → clean xlsx |
| Images | Not handled | Pillow re-encode (EXIF/ICC/XMP stripped, all TIFF frames) |
| RTF | `\obj` → `\0bj` byte substitution | **Rejected by design** (fail closed) |
| Nested ZIP-of-documents | Recurses and bleaches each entry | Hard-rejected (no `[Content_Types].xml`) |
| Legacy OLE2 (`doc`/`xls`/`ppt`) | Bleaches in place (POI rewrite) | Quarantined + deleted (no CDR attempted) |

---

## Where this project is ahead

These are areas where aws-cdr-gateway provides stronger guarantees than DocBleach.

### OOXML: surgery vs. re-serialisation
DocBleach opens the package with Apache POI and writes it back out, which can add,
reorder, or mutate parts CDR never intended to touch. aws-cdr-gateway rebuilds the ZIP
entry-by-entry and never re-serialises through an Office library, so anything not
explicitly stripped is preserved byte-for-byte. Smaller blast radius, fewer surprises.

### Embedded OLE objects — strip the part, not just the reference
DocBleach's `OOXMLBleach` replaces blacklisted **relationships** with a dummy, but the
embedded payload bytes under `word|xl|ppt/embeddings/*.bin` remain extractable from the
output. aws-cdr-gateway drops both the relationship and the part bytes (see
`STRIP_ZIP_ENTRIES`). This is the recurring "denylist that strips the reference but leaves
the payload" failure mode — see `CLAUDE.md` pitfall #31.

### Hyperlinks — neutralised, not whitelisted
DocBleach explicitly whitelists the hyperlink relationship type ("Hyperlinks should be
safe enough, right?"), passing it through untouched. That leaves UNC paths
(`\\host\share` → NTLM credential theft) and arbitrary phishing/SSRF URLs intact.
aws-cdr-gateway rewrites external hyperlink rel `Target`s to inert while keeping the rel
so `r:id` references don't dangle (pitfall #32).

### DDE / field codes
DocBleach regexes for `DDEAUTO` and the `ddeService`/`ddeTopic` attributes. aws-cdr-gateway
scrubs a much wider field-code surface (`MACROBUTTON`, `DDE`, `EXEC`, `INCLUDE*`, `LINK`,
`WEBSERVICE`, `RTD`, `CALL`, `REGISTER`, auto-exec macros), including **entity-encoded**
variants (`&#68;&#68;&#69;` = DDE), with all neutralisation patterns ReDoS-bounded
(pitfalls #21, #29).

### PDF annotation actions — delete all, don't allowlist
DocBleach matches a named set of action slots (`/C`, `/O`, `/Bl`, …). aws-cdr-gateway
deletes **every** `/A` and `/AA` unconditionally, catching `/GoToE`, `/Rendition`,
`/SetOCGState`, etc. that an action allowlist misses (pitfall #31).

### Fail-closed dispatch
DocBleach is best-effort: unrecognised content is passed through. aws-cdr-gateway's core
promise is that everything in `SANITISED_BUCKET` was disarmed, so any unknown extension is
quarantined and never labelled sanitised (pitfall #28).

### Decompression-bomb defence
DocBleach's `ArchiveBleach` reads entries with an unbounded `byte[1024]` loop and a literal
`@TODO: check real file size?`. aws-cdr-gateway reads in chunks with a running byte counter
that does **not** trust the attacker-controlled central-directory `file_size`, bounded by
`_MAX_ENTRY_BYTES` (pitfalls #2, #20).

### Formats DocBleach doesn't handle
- **xlsb** → `cdr_xlsb()` extracts cell values via `pyxlsb` and re-serialises clean xlsx
  with `openpyxl`; no BIFF12 records survive (pitfall #10).
- **Images** → Pillow re-encode to a pixel-only copy, stripping EXIF/ICC/XMP and GIF
  comment blocks, preserving all TIFF frames.

---

## Behaviours adopted from DocBleach (and hardened)

### PostScript / EPS content-type blacklist
DocBleach blacklists `application/postscript` "to prevent 0days." EPS is a Turing-complete
interpreter language and a historic RCE surface (the GhostScript `-dSAFER` bypass family).
aws-cdr-gateway adopted this idea and **hardened it past the original** after an
adversarial audit:

- The declaration is dropped via `_is_postscript_ct()`, which normalises case, whitespace,
  and RFC-2045 parameters (`;charset=…`) — closing a content-type evasion.
- The part bytes are dropped by **two** independent mechanisms: `.eps`/`.ps` suffix in
  `STRIP_ZIP_ENTRIES`, **and** a content-type-driven pre-pass (`_postscript_override_parts`)
  that drops any part an `Override` declares PostScript *regardless of filename* — closing a
  bypass where an EPS payload is stored as e.g. `word/media/image1.png`.

See `CLAUDE.md` pitfall #37.

---

## Gaps considered and deliberately NOT closed

DocBleach handles two input types this project intentionally does not. Both are **fail-closed**
here (quarantined, never sanitised), so the difference is throughput/coverage, not safety —
and in both cases fail-closed is the more secure posture.

### RTF — rejected by design
DocBleach sanitises RTF by replacing `\obj` with `\0bj` (a single byte substitution betting
an RTF parser will skip the now-unknown tag). aws-cdr-gateway does **not** give RTF a
handler. RTF's danger is **parser divergence**: embedded/linked OLE, remote-template
references, and control words a forgiving consumer acts on — structure, not cleanly-excisable
content. A reconstruction pass can only defend the grammar *it* parses; the attacker targets
the grammar the *consumer* (Word) parses. History bears this out: CVE-2017-0199 (remote OLE
template), CVE-2017-11882 / CVE-2018-0802 (Equation Editor), CVE-2023-21716 (font-table heap
corruption). RTF is therefore in `FAIL_CLOSED_EXTS`, checked before ZIP validation and the
unknown-extension gate so the rejection is order-independent. DocBleach's `\obj`→`\0bj`
substitution is exactly the denylist trap to avoid. See `CLAUDE.md` pitfall #38.

If RTF throughput is ever required, the answer is render-to-safe-format out-of-band
(e.g. RTF→PDF→CDR), not in-pipeline reconstruction.

### Nested-archive recursion
DocBleach's `ArchiveBleach` recurses into a plain ZIP and bleaches each entry.
aws-cdr-gateway hard-rejects a ZIP that lacks `[Content_Types].xml` (i.e. a non-OOXML
archive renamed `.docx`, or an arbitrary ZIP), rather than recursing. Recursion adds real
attack surface (recursion bombs, cumulative-size blowup) and would loosen a load-bearing
invariant (pitfall #34). Not closed without a concrete need.

### Unknown OOXML part-family allowlist
DocBleach deletes any OOXML part whose top-level MIME family isn't
`application|image|audio|video` (a coarse allowlist). A fine-grained equivalent would harden
the denylist posture further, but the false-positive surface is wide (SmartArt, ink, embedded
fonts, custom XML, theme variants, future Office part types) and a miss rejects/corrupts a
legitimate business document — a production incident in a CDR gateway, not a security event.
Deferred pending a real-world Office corpus to validate against. See `CLAUDE.md` pitfall #37
(deferred note).

---

## Notes on DocBleach behaviours intentionally not mirrored

- **Password brute-forcing (PDF):** DocBleach tries 8 common passwords to open protected
  PDFs. aws-cdr-gateway routes protected files to quarantine instead — intentional.
- **Dummy-file injection:** DocBleach injects a `/bleach/bleach` part so Office doesn't crash
  on a dangling relationship. aws-cdr-gateway avoids the problem by rewriting rels inert
  rather than deleting them, so no dummy is needed.
- **Legacy OLE2 (`doc`/`xls`/`ppt`):** DocBleach bleaches these in place via POI.
  aws-cdr-gateway quarantines and deletes them — no in-place rewrite of a legacy binary
  format is attempted.
