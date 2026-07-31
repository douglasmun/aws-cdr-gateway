#!/usr/bin/env python3
"""Verify the hash-pinned Lambda dependency set matches src/requirements.txt.

Two files pin the same dependencies for different consumers:

  src/requirements.txt          — what the tests, the container and local dev install
  scripts/lambda-requirements.txt — what scripts/build.sh actually ships to Lambda,
                                    hash-pinned for --require-hashes

Dependabot only watches /src, so a CVE bump lands in src/requirements.txt and the
deployed artifact silently keeps the old version. That is exactly how pikepdf and
Pillow drifted two releases behind the tested versions. CI runs this so the gap
fails the build instead of shipping quietly.

boto3 is intentionally exempt (the Lambda runtime provides it). Transitive pins
that appear only in the hash-pinned file are left alone — they have no counterpart
to compare against.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "src" / "requirements.txt"
PINNED = ROOT / "scripts" / "lambda-requirements.txt"

# Provided by the Lambda python3.12 runtime, deliberately absent from the package.
EXEMPT = {"boto3"}


def parse(path: Path) -> dict[str, str]:
    """Map normalised package name -> pinned version for every `name==version` line."""
    found: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)==([^\s;]+)", line)
        if m:
            name = m.group(1).lower().replace("_", "-")
            found[name] = m.group(2)
    return found


def main() -> None:
    source = parse(SOURCE)
    pinned = parse(PINNED)

    problems: list[str] = []
    for name, want in sorted(source.items()):
        if name in EXEMPT:
            continue
        got = pinned.get(name)
        if got is None:
            problems.append(
                f"  {name}: pinned in src/requirements.txt ({want}) but MISSING from "
                f"scripts/lambda-requirements.txt — it will not ship to Lambda"
            )
        elif got != want:
            problems.append(
                f"  {name}: src/requirements.txt has {want}, "
                f"scripts/lambda-requirements.txt ships {got}"
            )

    # A hash-pinned entry with no --hash defeats the point of --require-hashes.
    for line in PINNED.read_text().splitlines():
        stripped = line.split("#", 1)[0].strip()
        if re.match(r"^[A-Za-z0-9_.\-]+==", stripped) and "--hash=sha256:" not in stripped:
            problems.append(f"  unhashed pin in scripts/lambda-requirements.txt: {stripped}")

    if problems:
        print("Lambda dependency pins are out of sync:", file=sys.stderr)
        print("\n".join(problems), file=sys.stderr)
        print(
            "\nThe deployed Lambda is built from scripts/lambda-requirements.txt, so a "
            "version that only moved in src/requirements.txt is NOT deployed.\n"
            "Regenerate the hash-pinned set:\n"
            "  python3 scripts/regen_lambda_requirements.py",
            file=sys.stderr,
        )
        sys.exit(1)

    shared = sorted(set(source) - EXEMPT)
    for name in shared:
        print(f"  {name}=={source[name]}")
    print(f"{len(shared)} shared pins agree across both dependency files.")


if __name__ == "__main__":
    main()
