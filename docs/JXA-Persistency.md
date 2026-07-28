# Threat Coverage — JXA-Persistency (macOS remote-template → VBA → osascript → LaunchAgent)

Analysis of the [`forefy/JXA-Persistency`](https://github.com/forefy/JXA-Persistency)
red-team technique against this CDR gateway. The technique is a macOS-endpoint
compromise chain that *begins* with a booby-trapped `.docx` — exactly the input class this
gateway disarms. This doc maps each link of the chain to what the gateway does, and states
plainly where the gateway's responsibility ends.

**Method.** Same as `cdr-gap-analysis-stevens.md`: for each stage, is it caught? where in
the code? Claims are grounded in `src/lambda_function.py` line references and the existing
regression tests, not a hand-wave.

**Framing.** A CDR gateway is a *document* control, not an endpoint agent. It can only act
on the first link of this chain — the malicious Office file. But that link is load-bearing:
sever it and every downstream stage (VBA, `osascript`, sandbox escape, persistence, C2)
is starved of its trigger. The gateway does exactly that.

---

## The attack chain (as published)

| # | Stage | Layer |
|---|---|---|
| 1 | `.docx` carries a **remote template** reference (`attachedTemplate` rel → attacker's `http://` server) | **Document** |
| 2 | Word fetches the remote template on open; the template delivers **VBA** | Document → Office runtime |
| 3 | VBA runs **`osascript` / JXA** | Office runtime |
| 4 | Word sandbox is bypassed for paths starting `~$` (Microsoft regexed it out so Word can write its own temp files) | macOS / Office sandbox |
| 5 | macOS auto-unzips zips dropped in `~/Library`; a `LaunchAgents/*.plist` inside grants persistence → C2 | macOS / EDR |

The gateway owns **stage 1**. Stages 4–5 are Microsoft- and Apple-layer issues — which is
Forefy's actual point to EDR vendors (stop trusting the signed Word binary to write login
items as it pleases). This document is scoped to stage 1 and its immediate document-layer
fallbacks.

---

## Stage 1 — remote template reference: **severed**

The remote-template feature (`CVE-2017-0199` family) works by placing a relationship of
type `…/relationships/attachedTemplate` in `word/_rels/settings.xml.rels`, whose `Target`
is the attacker's `http(s)://` (or UNC) server. On open, Word resolves that relationship
and pulls the template — which is where the VBA rides in.

| Element | CDR disposition | Where |
|---|---|---|
| `attachedTemplate` relationship | **Deleted wholesale** — the `<Relationship>` node is removed from the `.rels` part; Word is left with no URL to fetch | `STRIP_REL_TYPES` → `_strip_rels` removes the node via `STRIP_REL_LOCALNAMES` |
| `subDocument` relationship (sibling delivery vector) | Deleted | `STRIP_REL_TYPES` |
| `frame` relationship (frameset sub-document delivery) | Deleted | `STRIP_REL_TYPES` |

`_strip_rels` rebuilds the `.rels` XML *without* the stripped relationships and re-serialises
it back into the reconstructed ZIP. There is no `attachedTemplate` node in the output
package, so **stage 2 never fires** — Word has nothing to fetch, the remote template is
never retrieved, the VBA never arrives, `osascript` never runs, no `~/Library` zip is
dropped, no LaunchAgent is written, no C2 callback.

**Regression-pinned** by `test_strip_rel_types_includes_template_injection`, which asserts
`attachedTemplate`, `subDocument`, and `frame` are all in `STRIP_REL_TYPES`, and by an
end-to-end case that builds a `.docx` carrying an `attachedTemplate` rel to an attacker
URL and asserts the sanitised output contains no such relationship. Note the audit-report
string is lowercased (`type=attachedtemplate`) — match case-insensitively when asserting
against it.

**Verdict: no gap at the entry point.** The chain is severed at its root cause.

---

## Fallback stages — defence in depth

Even if the attacker abandons the remote-template delivery and tries to embed the payload
directly, the gateway cuts each alternative:

| Alternative delivery | CDR disposition | Where |
|---|---|---|
| **VBA embedded directly** (`.docm`) instead of remote | `word/vbaProject.bin` dropped; macro-enabled content type remapped to plain; file renamed to clean `.docx` extension | `STRIP_ZIP_ENTRIES`, `MACRO_CONTENT_TYPE_REMAP` |
| **Legacy OLE `.doc`** carrying the macro | Quarantined + source deleted — no CDR attempted, never labelled sanitised | `LEGACY_EXTS`, handler legacy branch |
| **`altChunk`** HTML/MHTML/RTF import (bypasses the macro scrub) | Element renamed so Word won't import it; the `aFChunk` relationship is also in the strip set | `_strip_xml_macros` altChunk pass |
| **UNC / `http` hyperlink target** (NTLM theft / phishing, the passive cousin) | Target rewritten to `https://_CDR_REMOVED_/`, rel kept so `r:id` doesn't dangle | `_strip_rels` external-hyperlink branch |
| **Field-code delivery** (`INCLUDE`, `WEBSERVICE`, `HYPERLINK`, `DDEAUTO`) fetching a remote payload | Scrubbed inside field carriers only | `_scrub_field_code_carriers` |

Structural anomalies fail closed: a ZIP that is not a valid OOXML package (e.g. an arbitrary
archive renamed `.docx`) is hard-rejected, not CDR'd — so a payload can't smuggle itself
past by breaking the container.

---

## Scope boundary — what this gateway does **not** claim

This is a document-transit control. It only sees the `.docx` **if the file passes through
the pipeline** — uploaded to the source S3 bucket, or `POST`ed to the local `/sanitise`
service. Any `.docx` a macOS user receives by email/download and opens directly, never
routed through the gateway, is outside its reach. The gateway is a chokepoint you route
untrusted files *through*, not an agent on the endpoint.

It also does **not** address the macOS/Office-layer links of the chain:

- **Stage 4 — the `~$` Word-sandbox regex hole.** That is a Microsoft Office bug; no
  document-layer transform touches it.
- **Stage 5 — `~/Library` zip auto-extract → `LaunchAgents` persistence.** That is a macOS
  behaviour + an EDR-trust problem — precisely what Forefy is urging EDR vendors to stop
  rubber-stamping for the signed Word binary.

Those are different layers than a CDR gate. **The claim is bounded and true: any `.docx`
that transits this gateway comes out with no relationship pointing at an attacker's template
server, so this specific chain cannot start.**

---

## References

- forefy/JXA-Persistency — <https://github.com/forefy/JXA-Persistency>
- CVE-2017-0199 (Office remote-template / HTA code execution) — the canonical remote-template abuse this stage exploits
- `cdr-gap-analysis-stevens.md` — sibling threat-coverage analysis (parse-don't-scan, fail-closed design)
