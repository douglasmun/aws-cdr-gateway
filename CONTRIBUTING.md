# Contributing

Thanks for your interest in improving the CDR pipeline. This is security-sensitive code —
it is the gate that decides whether an uploaded file is safe — so contributions are held to
a high bar for testing and review. Please read this before opening a PR.

## Ground rules

- **Every behaviour change needs a test.** If you add or change what CDR strips, add a
  fixture that carries that threat and assert it is removed (or that a benign file
  survives). PRs without tests for new behaviour will be asked to add them.
- **Never weaken a security guard to make a test pass.** If a test fails, fix the code or
  the test's expectation — do not relax the guard.
- **The only operation allowed to fail the handler is the upload to `SANITISED_BUCKET`.**
  Side effects (SNS publish, source delete, metric emission, quarantine upload) are
  wrapped in try/except *warn-and-continue* so a side-effect failure never turns a
  successful CDR into an EventBridge retry of an already-sanitised file. Keep it that way.
- **Fail closed.** Anything the pipeline cannot prove safe (unknown extension, structural
  ZIP anomaly, a format it can't disarm) must be quarantined or rejected — never uploaded
  to the sanitised bucket.

## Development setup

The Lambda runtime is **Python 3.12** (see `src/template.yaml`).

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r src/requirements.txt pytest

# Run the full test suite
cd src && pytest test_cdr.py -v

# Run one class or test
pytest test_cdr.py::TestOfficeCDR -v
pytest test_cdr.py::TestOfficeCDR::test_vba_macro_removed -v

# Lint (byte-compile)
python -m py_compile lambda_function.py
```

Tests construct malicious fixtures **entirely in memory**; S3/SNS are mocked with
`unittest.mock`, and required env vars are set automatically. **No AWS credentials are
needed to run the tests.**

## Project layout

| Path | What it is |
|---|---|
| `src/lambda_function.py` | The CDR Lambda — all Office/PDF/image handling |
| `src/test_cdr.py` | Test suite (malicious fixtures built in memory) |
| `src/template.yaml` | AWS SAM infrastructure |
| `terraform/` | OpenTofu/Terraform port of the SAM template |
| `scripts/build.sh` | Builds the Lambda zip with Linux wheels (for the Terraform path) |
| `docs/` | Architecture, deployment runbook, security/IAM review, operations |

## Engineering conventions (read before touching CDR code)

These are non-obvious and have each prevented a real bug. Keep them.

- **Decompression-bomb defence.** ZIP entries are read through `_read_zip_entry_safe`, a
  chunked byte counter that **never trusts `item.file_size`** (the central-directory size
  is attacker-controlled). Do not replace it with a single `read()` or a `file_size` check.
- **ZIP anomalies are hard rejects.** Bad magic, non-standard compression, duplicate
  entries, local/central method mismatch, or a missing `[Content_Types].xml` → quarantine +
  delete source. There is no "log and proceed" path.
- **CDR drops/neutralises in place; it never re-serialises through an Office library.**
  Anything not explicitly touched is preserved byte-for-byte.
- **Regexes that scan attacker-controlled XML must be ReDoS-safe.** No
  `(?:A|B)* REQUIRED (?:A|B)*` shapes; bound every unanchored `[^x]+` quantifier. Add a
  timing regression test (a long adversarial input must complete in well under a second).
- **Entity-encoded threats are neutralised without decoding the whole part.** Word/Excel
  entity-decode before evaluating field codes, so e.g. `&#68;&#68;&#69;` ("DDE") must be
  caught — but decoding the whole part and re-emitting it corrupts benign escapes like
  `&amp;`. Match encoded runs in place instead.
- **S3 object-tag values are sanitised to S3's allowed character set** (not URL-encoded —
  S3 rejects `%`). Reason/error strings on the quarantine path are attacker-influenced;
  a wrong tag value silently fails the quarantine write.
- **S3 tag values are sanitised so an attacker-controlled filename can't inject tag pairs.**

## Pull request checklist

- [ ] `pytest test_cdr.py -v` passes locally
- [ ] New/changed CDR behaviour has a test (threat fixture + assertion)
- [ ] New try/except *warn-and-continue* paths have a failure-path test
- [ ] New regexes are tested for both correctness and (if they scan untrusted input) ReDoS
- [ ] `python -m py_compile lambda_function.py` is clean
- [ ] Docs updated if behaviour or infrastructure changed

CI runs the test suite and a Linux package build on every push/PR; both must be green.

## Reporting a security issue

If you believe you've found a way to bypass CDR (active content surviving into the
sanitised output), please **do not open a public issue**. See [`SECURITY.md`](SECURITY.md)
for how to report privately (GitHub Security tab → *Report a vulnerability*, or email).

## License

By contributing you agree your contributions are licensed under the repository's
[MIT License](LICENSE).
