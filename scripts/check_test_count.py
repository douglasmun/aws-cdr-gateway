#!/usr/bin/env python3
"""Verify the documented test counts match what pytest actually collects.

The suite size is quoted in several docs, and the counts drift silently as tests
are added. CI runs this so a stale number fails the build instead of misleading
the next contributor. Only tracked docs are checked; CLAUDE.md / AGENTS.md /
GEMINI.md are gitignored and must be updated by hand (this script prints them as
a reminder when a mismatch is found).
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
SUITES = ("test_cdr.py", "test_cdr_local.py")


def collected(*paths: str) -> int:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", *paths, "--collect-only", "-q"],
        cwd=SRC, capture_output=True, text=True,
    )
    m = re.search(r"^(\d+) tests? collected", proc.stdout, re.MULTILINE)
    if not m:
        sys.exit(f"could not parse collection output for {paths}:\n{proc.stdout[-2000:]}")
    return int(m.group(1))


def main() -> int:
    lambda_n = collected(SUITES[0])
    local_n = collected(SUITES[1])
    total = collected(*SUITES)
    if lambda_n + local_n != total:
        return fail(f"per-suite counts {lambda_n}+{local_n} != combined {total}")

    print(f"collected: {lambda_n} Lambda + {local_n} local = {total} total")

    errors = []
    for rel, patterns in {
        "docs/claude/testing.md": [
            (rf"\({lambda_n} in `test_cdr\.py` \+ {local_n} in `test_cdr_local\.py` = \*\*{total} total\*\*\)",
             f"({lambda_n} in `test_cdr.py` + {local_n} in `test_cdr_local.py` = **{total} total**)"),
        ],
        "docs/claude/checklist-and-invariants.md": [
            (rf"\*\*{total} tests pass\*\*", f"**{total} tests pass**"),
        ],
        # The contributor quickstart. Was unguarded and drifted to "227 tests: 178 + 49"
        # — off by 84 — while CI stayed green; it is the first doc a contributor reads.
        "README.md": [
            (rf"# Run the full test suite \({total} tests: {lambda_n} CDR Lambda \+ {local_n} local variant\)",
             f"# Run the full test suite ({total} tests: {lambda_n} CDR Lambda + {local_n} local variant)"),
        ],
    }.items():
        text = (ROOT / rel).read_text()
        for pattern, expected in patterns:
            if not re.search(pattern, text):
                errors.append(f"{rel}: expected to find {expected!r}")

    if errors:
        return fail("\n".join(errors))

    print("documented counts match.")
    return 0


def fail(msg: str) -> int:
    print(f"::error::test count mismatch\n{msg}", file=sys.stderr)
    print(
        "\nUpdate the tracked docs above, and the gitignored CLAUDE.md / AGENTS.md /"
        "\nGEMINI.md by hand (CI cannot see those).",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
