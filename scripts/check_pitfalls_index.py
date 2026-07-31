#!/usr/bin/env python3
"""Verify the pitfalls.md subsystem index covers every entry, with working anchors.

docs/claude/pitfalls.md opens with an "Index by subsystem" grouping all entries so a
reader can find the handful relevant to the code they are about to touch. An index that
silently misses newly-appended entries is worse than none — it reads as complete.

Also enforces the numbering contract: `pitfall #N` is cited ~90 times across the code,
the tests and the other docs, so numbers must stay contiguous, unique and never reordered.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "claude" / "pitfalls.md"
INDEX_HEADING = "## Index by subsystem"


def gh_slug(heading: str) -> str:
    """GitHub's anchor slug: lowercase, drop backticks and punctuation, spaces -> '-'."""
    s = heading.strip().lower().replace("`", "")
    s = re.sub(r"[^\w\s\-]", "", s, flags=re.UNICODE)
    return re.sub(r"\s+", "-", s.strip())


def main() -> None:
    text = DOC.read_text()
    problems: list[str] = []

    if INDEX_HEADING not in text:
        sys.exit(f"{DOC.relative_to(ROOT)} is missing its '{INDEX_HEADING}' section")

    index_part, _, body_part = text.partition("\n---\n")

    headings = re.findall(r"^### (\d+)\.\s+(.*)$", text, re.M)
    numbers = [int(n) for n, _ in headings]

    expected = list(range(1, len(numbers) + 1))
    if numbers != expected:
        dupes = sorted({n for n in numbers if numbers.count(n) > 1})
        problems.append(
            f"  entry numbers are not contiguous 1..{len(numbers)} in document order"
            + (f" (duplicates: {dupes})" if dupes else "")
            + "\n    Numbers are permanent identifiers — append new entries, never renumber."
        )

    # Every entry must be linked from the index exactly once.
    linked = re.findall(r"\]\(#([^)]+)\)", index_part)
    slug_to_num = {gh_slug(f"{n}. {title}"): int(n) for n, title in headings}

    for slug in linked:
        if slug not in slug_to_num:
            problems.append(f"  index link points at a non-existent anchor: #{slug}")

    covered = [slug_to_num[s] for s in linked if s in slug_to_num]
    missing = sorted(set(numbers) - set(covered))
    if missing:
        problems.append(
            f"  entries missing from the index: {missing}\n"
            "    Add each to the matching group under '## Index by subsystem'."
        )
    twice = sorted({n for n in covered if covered.count(n) > 1})
    if twice:
        problems.append(f"  entries listed more than once in the index: {twice}")

    if problems:
        print(f"{DOC.relative_to(ROOT)} index is out of sync:", file=sys.stderr)
        print("\n".join(problems), file=sys.stderr)
        sys.exit(1)

    groups = re.findall(r"^\*\*(.+?)\*\*$", index_part, re.M)
    print(
        f"pitfalls.md: {len(numbers)} entries, all indexed across {len(groups)} groups; "
        "anchors resolve and numbering is contiguous."
    )


if __name__ == "__main__":
    main()
