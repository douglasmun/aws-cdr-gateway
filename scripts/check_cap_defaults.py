#!/usr/bin/env python3
"""Fail if a doc quotes a stale default for a CDR_MAX_* cap.

Retuning a cap in lambda_function.py silently invalidates every doc quoting its old
default. That happened: CDR_MAX_TOTAL_BYTES stayed documented as 1 GiB in two files long
after being retuned to 512 MB, in the direction that mattered — a reader would believe the
aggregate decompression budget sat *above* the Lambda's 1024 MB MemorySize when the whole
point of the retune was putting it under.

Docs mention caps constantly in prose, beside port numbers, chunk sizes, memory ceilings and
measured figures. Guessing which nearby number is a default claim produces false positives,
so this matches only the explicit shapes docs actually use to *state* a default:

    (default 104857600 = 100 MB)            docs/claude/architecture.md
    | `CDR_MAX_FILE_BYTES` | `104857600` …  docs/local-cdr.md, docs/deploy-container.md
    | `CDR_MAX_FILE_BYTES` | no | 100 MB |  README.md
    default `CDR_MAX_TOTAL_BYTES` = 512 MB  docs/claude/pitfalls.md
    (default 200 MB)                        prose form

Anything else on the line is ignored. Byte and human-unit forms are both accepted, so
"536870912" and "512 MB" each satisfy CDR_MAX_TOTAL_BYTES.

Run: python scripts/check_cap_defaults.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SOURCE = REPO / "src" / "lambda_function.py"

# Tracked docs that quote user-facing defaults. The gitignored agent docs
# (CLAUDE/AGENTS/GEMINI.md) are invisible to CI and are updated by hand.
DOCS = [
    "README.md",
    "docs/claude/architecture.md",
    "docs/claude/pitfalls.md",
    "docs/claude/checklist-and-invariants.md",
    "docs/local-cdr.md",
    "docs/deploy-container.md",
    "docs/cdr_pipeline_summary.md",
]

UNIT_MULTIPLIERS = {"KB": 1024, "MB": 1024**2, "GB": 1024**3, "GIB": 1024**3}
NUM = r"(\d[\d,_]*)\s*(KB|MB|GB|GiB|MP)?"

# Each pattern captures (number, unit) and is anchored to an explicit default statement.
DEFAULT_PATTERNS = [
    # (default 104857600 = 100 MB)  /  (default 20000)  /  (default 40,000,000 ≈ 40 MP)
    re.compile(rf"\(default\s+{NUM}", re.IGNORECASE),
    # default `CDR_MAX_TOTAL_BYTES` = 512 MB
    re.compile(rf"default\s+`?CDR_MAX_[A-Z_]+`?\s*=\s*{NUM}", re.IGNORECASE),
    # Markdown table cell immediately after the cap name: | `CDR_MAX_FILE_BYTES` | `104857600` (100 MB) |
    re.compile(rf"\|\s*`CDR_MAX_[A-Z_]+`\s*\|\s*`?{NUM}`?"),
    # README shape: | `CDR_MAX_FILE_BYTES` | no | 100 MB |
    re.compile(rf"\|\s*`CDR_MAX_[A-Z_]+`\s*\|\s*(?:no|yes)\s*\|\s*{NUM}", re.IGNORECASE),
]

CAP_RE = re.compile(r"\bCDR_MAX_[A-Z_]+\b")
# Lines describing a past value rather than asserting the current one.
SKIP_MARKERS = ("was documented as", "sat documented", "after being retuned")


def real_defaults() -> dict[str, int]:
    """Parse the CDR_MAX_* defaults out of lambda_function.py.

    Handles both shapes the module uses: str(512 * 1024 * 1024) and a bare "20000".
    """
    text = SOURCE.read_text(encoding="utf-8")
    pattern = re.compile(
        r'os\.environ\.get\(\s*"(CDR_MAX_[A-Z_]+)"\s*,\s*(str\(\s*)?("?[^)"]+?"?)\s*\)?\s*\)'
    )
    out: dict[str, int] = {}
    for name, _wrapped, expr in pattern.findall(text):
        cleaned = expr.strip().strip('"').replace("_", "")
        if not cleaned:
            continue
        try:
            value = eval(cleaned, {"__builtins__": {}}, {})  # noqa: S307 - fixed repo input
        except Exception:
            continue
        if isinstance(value, int):
            out[name] = value
    return out


def stated_values(line: str) -> set[int]:
    """Numbers the line explicitly states as a default, normalised to the cap's own unit."""
    values: set[int] = set()
    for pattern in DEFAULT_PATTERNS:
        for raw, unit in pattern.findall(line):
            try:
                n = int(raw.replace(",", "").replace("_", ""))
            except ValueError:
                continue
            # MP is a display unit for an already-decimal pixel count; the doc writes both
            # "40000000" and "40 MP", so accept the bare number and the scaled form.
            if unit and unit.upper() == "MP":
                values.update({n, n * 1_000_000})
            elif unit:
                values.add(n * UNIT_MULTIPLIERS[unit.upper()])
            else:
                values.add(n)
    return values


def main() -> int:
    defaults = real_defaults()
    expected_caps = set(CAP_RE.findall(SOURCE.read_text(encoding="utf-8")))
    missing = expected_caps - set(defaults)
    if missing:
        print(
            f"ERROR failed to parse defaults for {sorted(missing)} from {SOURCE.name} — "
            "the parser is out of step with the code, not the docs.",
            file=sys.stderr,
        )
        return 1

    print(f"Defaults in {SOURCE.relative_to(REPO)}:")
    for name, value in sorted(defaults.items()):
        print(f"  {name} = {value}")
    print()

    problems: list[str] = []
    checked = 0

    for rel in DOCS:
        path = REPO / rel
        if not path.exists():
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            caps = set(CAP_RE.findall(line))
            if len(caps) != 1 or any(m in line for m in SKIP_MARKERS):
                continue
            cap = caps.pop()
            if cap not in defaults:
                continue
            stated = stated_values(line)
            if not stated:
                continue
            checked += 1
            if defaults[cap] not in stated:
                problems.append(
                    f"{rel}:{lineno}: {cap} stated as {sorted(stated)}, "
                    f"real default is {defaults[cap]}\n    {line.strip()[:150]}"
                )

    if problems:
        print("Stale cap defaults in docs:\n", file=sys.stderr)
        for p in problems:
            print(f"  {p}\n", file=sys.stderr)
        print("Update the doc to match lambda_function.py.", file=sys.stderr)
        return 1

    print(f"{checked} stated cap defaults across {len(DOCS)} docs all match the code.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
