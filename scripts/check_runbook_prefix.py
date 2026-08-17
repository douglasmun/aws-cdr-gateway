#!/usr/bin/env python3
"""Fail if a runbook CLI command hardcodes a `cdr-`-prefixed resource name.

Lambda, SNS topic, DLQ, IAM role/policy, EventBridge rule and alarm names all derive
from `ResourcePrefix` / `var.resource_prefix`. The runbook tells operators NOT to deploy
at the `cdr` default (a live askkaifbot service already owns those names in
ap-southeast-1), then exports `PREFIX` in section 1 for every command to use. A command
that hardcodes `cdr-<suffix>` therefore inspects a resource the reader does not have —
they see `ResourceNotFoundException`, or worse, somebody else's production resource.

That shipped twice: `aws events list-targets-by-rule --rule cdr-s3-object-created` and
`aws events describe-rule --name cdr-s3-object-created`, while Terraform actually names
the rule `${var.resource_prefix}-s3-object-created`. An operator following the runbook's
own advice to use a non-default prefix would misdiagnose a deployment or an incident.

WHAT IS CHECKED, AND WHY THE SCOPE IS NARROW

Only `cdr-<suffix>` where <suffix> is a suffix the IaC actually derives from the prefix
(read from src/template.yaml and terraform/main.tf at runtime — never hand-listed here,
see pitfall #61), and only where the name is being *passed to a command*:

    --rule cdr-s3-object-created                     an argument value
    --function-name cdr-lambda                       an argument value
    --dimensions Name=FunctionName,Value=cdr-lambda  a Key=Value argument
    --alarm-names cdr-lambda-errors cdr-lambda-p99   later items in a multi-value argument
    /aws/lambda/cdr-lambda                           a log-group path

The `Value=` and multi-value forms are not decoration: CloudWatch commands here pass the
function name as `Name=FunctionName,Value=…`, and a first cut of this guard matched only a
name sitting immediately after `--opt`, so an injected `Value=cdr-lambda` passed clean. The
guard's own negative control caught that (#57) — hence matching the whole argument run.

Prose, table cells and parameter-value examples are deliberately NOT flagged. The runbook
must be able to say "do not leave ResourcePrefix at the `cdr` default" and show
`cdr-staging-source-<alias>` as a suggested value; flagging those would make the guard
unusable and it would be silenced rather than fixed.

THE EXEMPTION, AND WHY IT MUST EXIST

Section 8's `AWS::EarlyValidation::ResourceExistenceCheck` entry is about investigating a
*pre-existing* `cdr-lambda` the reader did NOT deploy — the real askkaifbot function. There
`cdr-lambda` is correct and `$PREFIX-lambda` would be wrong. A syntactic rule cannot tell
that apart from a genuine bug, so the doc declares it inline:

    <!-- prefix-literal-ok: investigating the foreign cdr-lambda, not the reader's stack -->

The marker must carry a reason and is counted in the summary, so a growing pile of them is
visible rather than silently normal. It must sit OUTSIDE the fence, immediately before the
```bash line — an HTML comment inside a fenced block is not a comment, it renders literally
and breaks copy-paste (and lands mid-command if the command is line-continued). Placed
there it covers the whole block; placed before an ordinary line it covers that line only.

Run: python scripts/check_runbook_prefix.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RUNBOOK = REPO / "docs" / "deployment-runbook.md"
TEMPLATE = REPO / "src" / "template.yaml"
TERRAFORM = REPO / "terraform" / "main.tf"

EXEMPT_MARKER = "prefix-literal-ok:"

# Everything after an option up to the next option / end of line is that option's value
# run: `--rule cdr-x`, `--function-name=cdr-x`, `Name=FunctionName,Value=cdr-x`, and
# multi-value forms like `--alarm-names cdr-a cdr-b`. Names are then picked out of the run.
ARG_RUN = re.compile(r"--[a-z][a-z-]*(?:[ =])((?:(?!\s--)[^\n])*)")
NAME_IN_RUN = re.compile(r"(?<![\w./-])(cdr-[a-z0-9-]+)")
LOG_GROUP = re.compile(r"/aws/lambda/(cdr-[a-z0-9-]+)")


def prefix_suffixes() -> set[str]:
    """Suffixes the IaC derives from the resource prefix, read from the IaC itself.

    Hand-listing these is the mistake pitfall #61 records: the #60 cap audit enumerated
    from memory, missed `_MAX_WALK_NODES`, and shipped a fail-open. Deriving the list
    means a resource added to either IaC file is covered without touching this script.
    """
    suffixes: set[str] = set()
    for path, pattern in (
        (TEMPLATE, r"\$\{ResourcePrefix\}-([a-z0-9-]+)"),
        (TERRAFORM, r"\$\{var\.resource_prefix\}-([a-z0-9-]+)"),
    ):
        if not path.exists():
            sys.exit(f"missing {path.relative_to(REPO)} — cannot derive prefixed names")
        suffixes.update(re.findall(pattern, path.read_text(encoding="utf-8")))
    if not suffixes:
        sys.exit("derived zero prefixed resource names — the IaC patterns must have changed")
    return suffixes


def main() -> int:
    if not RUNBOOK.exists():
        sys.exit(f"missing {RUNBOOK.relative_to(REPO)}")

    suffixes = prefix_suffixes()
    lines = RUNBOOK.read_text(encoding="utf-8").splitlines()

    problems: list[str] = []
    exempted: list[str] = []
    exempt_armed = False       # marker seen, not yet consumed
    exempt_reason = ""
    exempt_block = False       # marker armed a fenced block; holds until the fence closes
    in_fence = False

    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()

        if EXEMPT_MARKER in line:
            if in_fence:
                problems.append(
                    f"{RUNBOOK.name}:{lineno}: {EXEMPT_MARKER} inside a fenced block — an "
                    "HTML comment there renders literally and can split a line-continued "
                    "command. Move it above the opening ``` line."
                )
                continue
            exempt_armed = True
            exempt_reason = line.split(EXEMPT_MARKER, 1)[1].strip()
            if exempt_reason.endswith("-->"):
                exempt_reason = exempt_reason[:-3].strip()
            if not exempt_reason:
                problems.append(
                    f"{RUNBOOK.name}:{lineno}: {EXEMPT_MARKER} with no reason given"
                )
            continue

        if stripped.startswith("```"):
            if in_fence:
                in_fence, exempt_block = False, False
            else:
                in_fence = True
                exempt_block = exempt_armed
            exempt_armed = False
            continue

        if not stripped:
            continue

        candidates = [
            name for run in ARG_RUN.findall(line) for name in NAME_IN_RUN.findall(run)
        ] + LOG_GROUP.findall(line)
        hits = {n for n in candidates if n[len("cdr-"):] in suffixes}

        if hits and (exempt_block or exempt_armed):
            exempted.append(f"line {lineno} ({', '.join(sorted(hits))}): {exempt_reason}")
        elif hits:
            for name in sorted(hits):
                problems.append(
                    f"{RUNBOOK.name}:{lineno}: command hardcodes `{name}`; "
                    f"use `$PREFIX-{name[len('cdr-'):]}`\n    {line.strip()[:120]}"
                )
        if not in_fence:
            exempt_armed = False

    if problems:
        print("::error::runbook command hardcodes a prefix-derived resource name")
        print("\nHardcoded resource names in runbook commands:\n", file=sys.stderr)
        for p in problems:
            print(f"  {p}\n", file=sys.stderr)
        print(
            "These names derive from ResourcePrefix, and the runbook tells operators not\n"
            "to deploy at the `cdr` default — so the command inspects a resource the\n"
            "reader does not have. Use $PREFIX, or, if the literal is deliberate (e.g.\n"
            f"investigating a foreign resource), mark it:\n"
            f"    <!-- {EXEMPT_MARKER} why this literal is correct -->",
            file=sys.stderr,
        )
        return 1

    print(
        f"{RUNBOOK.name}: no command hardcodes a prefix-derived name "
        f"({len(suffixes)} suffixes derived from the IaC, "
        f"{len(exempted)} deliberate literal(s) exempted)."
    )
    for e in exempted:
        print(f"  exempt: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
