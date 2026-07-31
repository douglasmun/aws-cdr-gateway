#!/usr/bin/env python3
"""Regenerate scripts/lambda-requirements.txt from src/requirements.txt.

Resolves the Lambda target platform's wheels (x86_64 / cp312 / manylinux_2_28) and
writes each package's sha256 so scripts/build.sh can install with --require-hashes.
Versions come from src/requirements.txt, so bumping a dependency is a one-file edit
followed by running this script.

Requires network access (it asks pip to resolve against PyPI). Run after any version
bump in src/requirements.txt; scripts/check_lambda_requirements.py fails CI otherwise.

  python3 scripts/regen_lambda_requirements.py
"""
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "src" / "requirements.txt"
PINNED = ROOT / "scripts" / "lambda-requirements.txt"

# Provided by the Lambda python3.12 runtime — must not be added to the package.
EXEMPT = {"boto3"}

PLATFORM = "manylinux_2_28_x86_64"
PYTHON_VERSION = "312"


def wanted() -> list[str]:
    specs: list[str] = []
    for line in SOURCE.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9_.\-]+)==([^\s;]+)", line)
        if m and m.group(1).lower().replace("_", "-") not in EXEMPT:
            specs.append(f"{m.group(1)}=={m.group(2)}")
    return specs


def resolve(specs: list[str]) -> list[tuple[str, str, str]]:
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "report.json"
        proc = subprocess.run(
            [
                sys.executable, "-m", "pip", "install", "--dry-run", "--quiet",
                "--platform", PLATFORM,
                "--python-version", PYTHON_VERSION,
                "--implementation", "cp",
                "--only-binary=:all:",
                "--target", str(Path(tmp) / "target"),
                "--report", str(report),
                *specs,
            ],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            sys.exit(f"pip resolution failed:\n{proc.stderr[-3000:]}")
        data = json.loads(report.read_text())

    out: list[tuple[str, str, str]] = []
    for item in data["install"]:
        meta = item["metadata"]
        digest = item["download_info"]["archive_info"]["hashes"].get("sha256")
        if not digest:
            sys.exit(f"no sha256 for {meta['name']} — refusing to write an unhashed pin")
        out.append((meta["name"], meta["version"], digest))
    return out


def main() -> None:
    resolved = resolve(wanted())

    header, seen_pin = [], False
    for line in PINNED.read_text().splitlines():
        if re.match(r"^[A-Za-z0-9_.\-]+==", line.strip()):
            seen_pin = True
            break
        header.append(line)
    if not seen_pin:
        sys.exit(f"no existing pins found in {PINNED} — refusing to rewrite blindly")

    while header and not header[-1].strip():
        header.pop()

    body = "\n".join(f"{n}=={v} --hash=sha256:{h}" for n, v, h in resolved)
    PINNED.write_text("\n".join(header) + "\n\n" + body + "\n")

    print(f"wrote {len(resolved)} hash-pinned entries to {PINNED.relative_to(ROOT)}:")
    for n, v, _ in resolved:
        print(f"  {n}=={v}")


if __name__ == "__main__":
    main()
