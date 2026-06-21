# Security Policy

`aws-cdr-gateway` is a **Content Disarm & Reconstruction (CDR)** gate: its security
guarantee is that anything routed to the sanitised bucket has had active/executable content
removed. The most serious class of issue is therefore a **CDR bypass** — active content
surviving into the sanitised output, or content that was never disarmed being labelled
`sanitised`.

We take these reports seriously and appreciate responsible disclosure.

## Reporting a vulnerability

**Please do not open a public issue or discussion for a security vulnerability.**

Report it privately through either channel:

1. **GitHub private advisory (preferred):** the repository's **Security** tab →
   **Report a vulnerability**. This opens a private advisory visible only to maintainers.
2. **Email:** `douglasmun@yahoo.com` with `[aws-cdr-gateway security]` in the subject.

You should receive an acknowledgement within **5 business days**. We aim to confirm the
issue and agree on a disclosure timeline within **30 days**.

## What to include

You do **not** need to attach a working exploit or live malware to make a report
actionable. Describe the **vector**:

- File type and the handler path it exercises (Office/OOXML, PDF, image, xlsb, …).
- The carrier — embedded object, relationship type, `[Content_Types].xml` declaration,
  field code, PDF action, annotation, etc.
- What survives into the sanitised output, or what is wrongly labelled `sanitised`.
- A minimal structural description or generator snippet is ideal. If you must share a
  sample, note that in the report and we'll arrange a private channel — **do not** attach
  live malware to a public-facing message.

## Scope

In scope:

- CDR bypass — active content surviving disarmament (macros, OLE/embedded objects, DDE /
  field codes, PDF JavaScript/actions, PostScript/EPS, external/remote references, etc.).
- Content that was not disarmed being routed to the sanitised bucket (a fail-open in the
  dispatch).
- Resource-exhaustion / denial of service reachable from an uploaded file (decompression
  bombs, ReDoS, OOM).
- Injection via attacker-controlled metadata (e.g. object-tag injection from a filename).

Out of scope:

- Issues requiring control of the AWS account, IAM roles, or the deployment environment.
- The deliberate, documented fail-closed behaviours — e.g. RTF and legacy OLE2
  (`doc`/`xls`/`ppt`) are **quarantined by design**, not sanitised. A report that these
  formats "aren't sanitised" is expected behaviour, not a vulnerability. See
  `docs/comparison-docbleach.md` and the "Common Pitfalls" notes for the rationale.
- Findings against a **fork or modified deployment** that has weakened a documented
  security invariant.

## Supported versions

This project is distributed as source to deploy yourself; there is no released binary or
version stream. Fixes land on `main`. Please test against the current `main` before
reporting.

## Disclosure

We follow coordinated disclosure: we'll work with you on a fix and a public advisory, and
credit you (unless you prefer to remain anonymous). Please give us reasonable time to ship a
fix before any public write-up.
