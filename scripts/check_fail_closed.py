#!/usr/bin/env python3
"""Guard: every fail-closed rejection in the CDR core must be pinned by a test that
fails when the rejection is removed.

Pitfall #59 was a resource cap that `return`ed instead of raising: it read as bounding
the work, but meant "ship whatever was inspected so far" — and because the sweep still
completed, nothing in a 447-test suite noticed. The suite passed just as green with the
hole open as with it closed.

That is the failure mode this script exists to prevent recurring. It does not read the
code and it does not trust a docstring that claims FAIL CLOSED (pitfall #53 is exactly a
docstring that made that claim while the code did not). It mutates each `raise CdrReject`
into a silent `pass` and re-runs the suite: if the tests still pass, that rejection is
decorative — nothing proves it fires, and a future refactor can delete it silently.

Deliberately mutation-based rather than a grep for `return` inside a loop: the direction
a bound *should* take is a judgement call (`_SNS_REMOVED_BYTE_BUDGET` correctly truncates,
because it caps a report about an already-sanitised file and must never reject one), so a
syntactic rule would produce false positives on the one cap that is right to truncate.
What is not a judgement call is whether a rejection that exists is actually load-bearing.

Run from the repo root:  python scripts/check_fail_closed.py
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src" / "lambda_function.py"
TESTS = "test_cdr.py"

# boto3 builds its clients at import time, so a region and dummy credentials are needed.
# SANITISED_BUCKET/QUARANTINE_BUCKET are deliberately NOT set: the test module defaults
# them with os.environ.setdefault, which *yields* to the environment, so exporting them
# breaks the tests asserting the literal test-sanitised/test-quarantine names. Setting
# them here cost five spurious failures before the baseline check caught it.
TEST_ENV = {
    **os.environ,
    "AWS_DEFAULT_REGION": "us-east-1",
    "AWS_ACCESS_KEY_ID": "x",
    "AWS_SECRET_ACCESS_KEY": "x",
    "AWS_EC2_METADATA_DISABLED": "true",
}
for _leaky in ("SANITISED_BUCKET", "QUARANTINE_BUCKET"):
    TEST_ENV.pop(_leaky, None)


def find_python() -> str:
    """The venv interpreter, which has pikepdf/Pillow. A bare `python3` collects nothing
    and the resulting empty run looks like a pass — the #57 failure mode."""
    for candidate in (REPO / ".venv/bin/python", Path("/tmp/cdrvenv/bin/python")):
        if candidate.exists():
            return str(candidate)
    return sys.executable


def raise_sites(lines: list[str]) -> list[int]:
    return [i for i, line in enumerate(lines) if re.search(r"\braise CdrReject\b", line)]


def mutate(lines: list[str], index: int) -> list[str]:
    """Replace the raise statement at `index` (and any continuation lines) with `pass`."""
    mutated = lines[:]
    indent = len(mutated[index]) - len(mutated[index].lstrip())
    end = index
    # A multi-line raise runs until parentheses balance.
    depth = mutated[index].count("(") - mutated[index].count(")")
    while depth > 0 and end + 1 < len(mutated):
        end += 1
        depth += mutated[end].count("(") - mutated[end].count(")")
    mutated[index:end + 1] = [" " * indent + "pass"]
    return mutated


def main() -> int:
    python = find_python()
    original = SRC.read_text()
    lines = original.split("\n")
    sites = raise_sites(lines)

    if not sites:
        print("::error::no `raise CdrReject` sites found — has the guard moved?")
        return 1

    # Baseline: the suite must be green before mutants mean anything. Without this a
    # broken checkout reports every mutant as "caught" and the guard passes vacuously.
    baseline = subprocess.run(
        [python, "-m", "pytest", TESTS, "-q", "--no-header"],
        cwd=SRC.parent, capture_output=True, text=True, env=TEST_ENV,
    )
    if baseline.returncode != 0:
        print("::error::baseline suite is not green; fix that before running this guard")
        print(baseline.stdout[-2000:])
        return 1

    backup = Path(tempfile.mkdtemp()) / "lambda_function.py.bak"
    shutil.copy(SRC, backup)
    survivors: list[str] = []
    try:
        for site in sites:
            SRC.write_text("\n".join(mutate(lines, site)))
            result = subprocess.run(
                [python, "-m", "pytest", TESTS, "-q", "-x", "--no-header"],
                cwd=SRC.parent, capture_output=True, text=True, env=TEST_ENV,
            )
            label = f"{SRC.name}:{site + 1}: {lines[site].strip()[:60]}"
            if result.returncode == 0:
                survivors.append(label)
                print(f"  SURVIVED  {label}")
            else:
                print(f"  caught    {label}")
    finally:
        shutil.copy(backup, SRC)
        assert SRC.read_text() == original, "failed to restore lambda_function.py"

    print()
    if survivors:
        print(f"::error::{len(survivors)} fail-closed rejection(s) not pinned by any test")
        for label in survivors:
            print(f"  {label}")
        print("\nEach rejection above can be deleted without the suite noticing, so nothing")
        print("proves it fires. Add a test that asserts CdrReject for that input (see")
        print("test_walk_cap_rejects_rather_than_truncating for the pattern).")
        return 1

    print(f"all {len(sites)} fail-closed rejections are pinned by a failing test")
    return 0


if __name__ == "__main__":
    sys.exit(main())
