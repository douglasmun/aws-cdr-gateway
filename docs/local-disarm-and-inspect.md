# Local disarm & inspect (no server, no AWS)

Disarm or inspect a single file on your machine using the **same** shared
`cdr_dispatch` core the AWS Lambda and the FastAPI service use. `cdr_dispatch`
is pure and I/O-free, so a local run produces byte-identical results to
production — it's not an approximation.

Two helper scripts live in `tools/`:

| Script | What it does | Modifies file? |
|---|---|---|
| `tools/disarm.py` | Disarms any supported format (PDF, Office incl. macro variants, images, xlsb). Writes `<name>.cdr.<ext>` next to the original. | No — writes a new file |
| `tools/pdf_inspect.py` | PDF-only, read-only. Lists active-content vectors (OpenAction, AA, JavaScript, AcroForm/XFA, embedded files, auto-run annotations, JBIG2/JPX filters, metadata). | No |

## One-time setup

There is no repo venv. Create a scratch one with the CDR deps:

```bash
python3 -m venv /tmp/cdrvenv
/tmp/cdrvenv/bin/pip install -r src/requirements.txt
```

If you want it to survive a reboot, use `~/.cdrvenv` instead of `/tmp/cdrvenv`
everywhere below.

## Usage

Run from the repo root (`cd` into the repo so the scripts find `src/`):

```bash
# Inspect a PDF (read-only) — what active content is in there?
/tmp/cdrvenv/bin/python tools/pdf_inspect.py ~/Downloads/foo.pdf

# Disarm any supported file — writes foo.cdr.pdf next to the original
/tmp/cdrvenv/bin/python tools/disarm.py ~/Downloads/foo.pdf
```

`disarm.py` prints the verdict (`sanitised` / `rejected` / `unsupported-format`)
and the removal report, and on `sanitised` writes the clean copy using the
engine's remapped extension (a `.docm` comes out `.cdr.docx`, an `.xlsb` comes
out `.cdr.xlsx`).

## One-line shell alias

Add to `~/.zshrc` (adjust the repo path if yours differs):

```bash
alias cdr='(cd ~/Develop/aws-cdr-gateway && /tmp/cdrvenv/bin/python tools/disarm.py "$(pwd -P)/$1" 2>/dev/null || /tmp/cdrvenv/bin/python tools/disarm.py)'
```

That subshell-`cd` form is fiddly with arguments. A shell **function** is
cleaner and lets you pass a path from anywhere — prefer this:

```bash
# Disarm from any directory: `cdr foo.pdf`  or  `cdr ~/Downloads/foo.pdf`
cdr() { ( cd ~/Develop/aws-cdr-gateway && /tmp/cdrvenv/bin/python tools/disarm.py "$(realpath "$1")" ); }

# Inspect a PDF from anywhere: `cdrx foo.pdf`
cdrx() { ( cd ~/Develop/aws-cdr-gateway && /tmp/cdrvenv/bin/python tools/pdf_inspect.py "$(realpath "$1")" ); }
```

Reload with `source ~/.zshrc`, then:

```bash
cdr  ~/Downloads/foo.pdf      # disarm  -> foo.cdr.pdf
cdrx ~/Downloads/foo.pdf      # inspect (read-only)
```

## Gotchas (already handled in the scripts)

- **boto3 client at import** — `lambda_function.py` builds an S3 client at module
  load. The scripts set dummy `AWS_*` env vars so it constructs; the disarm core
  never makes a call.
- **Never name an inspect script `inspect.py`** — it shadows the stdlib module
  and pikepdf fails to import with a confusing circular-import error.
