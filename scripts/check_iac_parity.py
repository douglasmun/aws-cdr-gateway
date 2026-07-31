#!/usr/bin/env python3
"""Check src/template.yaml and terraform/ provision the same stack.

The two IaC paths are meant to be ports of one another, but nothing forced them to stay
that way: four `CDR_MAX_*` caps and fourteen resource names reached SAM only and shipped
that way for several PRs (#62, #63). CI's terraform-validate job closed the gap for the
caps; this closes it for the other three axes that actually change behaviour when they
drift:

  * resource names   — the `${prefix}-*` suffixes. A name in one path only means the
                       Terraform deployment is missing a resource, or two stacks collide.
  * IAM              — the (action, resource-shape) pairs the Lambda role grants. A
                       permission present in SAM but absent from Terraform is a runtime
                       AccessDenied that only shows up on the Terraform path.
  * CloudWatch alarms — name, metric, namespace, threshold and comparison operator. A
                       missing alarm is silent by construction: nothing fires.
  * bucket settings  — encryption at rest, versioning, all four public-access-block flags
                       and the source bucket's EventBridge notification. Each fails open
                       when dropped: unencrypted objects, no way to recover overwritten
                       quarantine evidence, a bucket that can be made public, or a
                       pipeline that silently never triggers.
  * TLS-only policies — the DenyInsecureTransport statement on every bucket. This axis is
                       checked as an absolute, not just for parity: dropping it from both
                       paths keeps them consistent but still fails, because a bucket
                       accepting plaintext HTTP is a defect regardless of agreement.

Deliberately structural, not a diff. The two languages express the same intent very
differently (SAM `Policies` with managed-policy templates vs a Terraform
`aws_iam_policy_document`), so each side is parsed into a comparable shape and the shapes
are compared. SAM's managed policy templates are expanded to the actions they really
grant — otherwise `S3WritePolicy` reads as zero permissions.

Not covered (still manual): the EventBridge *pattern* contents (source/detail-type/reason
filters) and Lambda tuning knobs like memory, timeout and reserved concurrency — those are
tunable per environment, so a difference is not necessarily drift. Compare them by eye at
review time.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SAM = ROOT / "src" / "template.yaml"
TF = ROOT / "terraform" / "main.tf"

# SAM policy templates expand to action sets that never appear literally in the template.
# Only the ones this stack uses are modelled; an unknown template is an error, not a skip,
# so adding one without teaching this script fails the build rather than silently passing.
SAM_POLICY_TEMPLATES = {
    "S3WritePolicy": {"s3:PutObject", "s3:PutObjectAcl", "s3:PutObjectVersionAcl"},
    "SNSPublishMessagePolicy": {"sns:Publish"},
}

# Resources SAM creates implicitly but Terraform must name explicitly. SAM generates the
# execution role, its inline policy and the EventBridge rule from `Policies:` and the
# `EventBridgeRule` event, so there is no `${ResourcePrefix}-...` string to compare against.
# Their absence from the SAM side is structural, not drift.
TF_ONLY_NAMES = {
    "lambda-role",     # SAM: implicit AWS::IAM::Role
    "lambda-policy",   # SAM: implicit inline policy from Policies:
    "s3-object-created",  # SAM: implicit AWS::Events::Rule from the S3Upload event
}

# Actions one path grants that the other legitimately does not.
SAM_ONLY_ACTIONS = {
    # S3WritePolicy is a broad managed template: it grants ACL actions this code never
    # calls (_upload uses PutObject + PutObjectTagging). Terraform's hand-written policy
    # is deliberately tighter. Tracked as SAM being over-broad, not Terraform missing.
    "s3:PutObjectAcl",
    "s3:PutObjectVersionAcl",
}
TF_ONLY_ACTIONS = {
    # SAM's `Tracing: Active` makes SAM attach the X-Ray write policy automatically;
    # Terraform has to spell the actions out. Same effective permission.
    "xray:PutTraceSegments",
    "xray:PutTelemetryRecords",
}

# Bucket placeholders differ by language (${SourceBucketName} vs ${var.source_bucket_name}).
# Normalise both to a role name so the ARNs compare.
BUCKET_ROLES = {
    "sourcebucketname": "SOURCE",
    "source_bucket_name": "SOURCE",
    "sanitisedbucketname": "SANITISED",
    "sanitised_bucket_name": "SANITISED",
    "quarantinebucketname": "QUARANTINE",
    "quarantine_bucket_name": "QUARANTINE",
}


def normalise_arn(arn: str) -> str:
    """Reduce an ARN to a comparable shape: bucket role + whether it is object-level."""
    arn = arn.strip().strip('"')
    if arn == "*":
        return "*"

    def sub(m):
        inner = m.group(1).strip().lower()
        inner = inner.replace("var.", "").split(".")[0]
        return BUCKET_ROLES.get(inner, inner.upper())

    # ${SourceBucketName} (SAM !Sub) and ${var.source_bucket_name} (TF interpolation)
    arn = re.sub(r"\$\{([^}]+)\}", sub, arn)
    # Terraform resource references: aws_sqs_queue.dlq.arn / aws_sns_topic.result.arn
    arn = re.sub(r"aws_sqs_queue\.dlq\.arn", "DLQ", arn)
    arn = re.sub(r"aws_sns_topic\.result\.arn", "RESULT_TOPIC", arn)
    return arn


def sam_resource_names(text: str) -> set[str]:
    """Every `${ResourcePrefix}-suffix` string in the SAM template."""
    return set(re.findall(r"\$\{ResourcePrefix\}-([a-z0-9-]+)", text))


def tf_resource_names(text: str) -> set[str]:
    """Every `${var.resource_prefix}-suffix` string in the Terraform config."""
    return set(re.findall(r"\$\{var\.resource_prefix\}-([a-z0-9-]+)", text))


def sam_iam(text: str) -> set[tuple[str, str]]:
    """(action, arn-shape) pairs granted by the SAM function's Policies block."""
    grants: set[tuple[str, str]] = set()

    policies = _slice_block(text, "      Policies:")
    if policies is None:
        sys.exit("could not locate the Policies block in src/template.yaml")

    for name, actions in SAM_POLICY_TEMPLATES.items():
        for _ in re.finditer(rf"\b{name}:", policies):
            for action in actions:
                # Managed templates are bucket/topic-scoped; the resource shape is implied
                # by the template rather than written out, so compare on action alone.
                grants.add((action, "<managed-template>"))

    for stmt in re.split(r"-\s+Effect:\s*Allow", policies)[1:]:
        actions = _yaml_scalar_or_list(stmt, "Action")
        resources = _yaml_scalar_or_list(stmt, "Resource")
        for a in actions:
            for r in resources:
                grants.add((a, normalise_arn(r)))
    return grants


def _slice_block(text: str, header: str) -> str | None:
    """Return the indented block following `header` (ends at the next same-or-less indent)."""
    start = text.find(header)
    if start == -1:
        return None
    indent = len(header) - len(header.lstrip())
    lines = text[start:].splitlines()
    out = [lines[0]]
    for line in lines[1:]:
        if line.strip() and (len(line) - len(line.lstrip())) <= indent:
            break
        out.append(line)
    return "\n".join(out)


def _yaml_scalar_or_list(block: str, key: str) -> list[str]:
    """Read `Key: value`, or `Key:` followed by a `- item` list.

    Collects EVERY occurrence of the key in the block, and reads a list until the
    indentation drops back to the key's own level. An earlier version returned only the
    first item of a multi-item list, which silently hid `s3:DeleteObject` and
    `s3:PutObjectTagging` and made this guard report drift that did not exist.
    """
    items: list[str] = []
    lines = block.splitlines()
    for i, line in enumerate(lines):
        m = re.match(rf"(\s*)-?\s*{key}:\s*(.*)", line)
        if not m:
            continue
        indent = len(m.group(1))
        inline = m.group(2).strip()
        if inline and not inline.startswith("#"):
            items.append(inline)
            continue
        for nxt in lines[i + 1:]:
            if not nxt.strip():
                continue
            nxt_indent = len(nxt) - len(nxt.lstrip())
            s = nxt.strip()
            if s.startswith("- ") and nxt_indent > indent:
                items.append(s[2:].strip())
            else:
                break
    return items


def tf_iam(text: str) -> set[tuple[str, str]]:
    """(action, arn-shape) pairs from the aws_iam_policy_document statements."""
    doc = _brace_block(text, 'data "aws_iam_policy_document" "lambda"')
    if doc is None:
        sys.exit("could not locate the aws_iam_policy_document in terraform/main.tf")

    grants: set[tuple[str, str]] = set()
    for m in re.finditer(r"actions\s*=\s*\[(.*?)\]", doc, re.S):
        actions = re.findall(r'"([^"]+)"', m.group(1))
        rest = doc[m.end():]
        rm = re.search(r"resources\s*=\s*\[(.*?)\]", rest, re.S)
        if not rm:
            continue
        resources = re.findall(r'"?([^",\[\]\s]+)"?', rm.group(1))
        for a in actions:
            for r in resources:
                grants.add((a, normalise_arn(r)))
    return grants


def _brace_block(text: str, header: str) -> str | None:
    """Return the `{...}` body following a header line, brace-balanced."""
    start = text.find(header)
    if start == -1:
        return None
    i = text.find("{", start)
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[i:j + 1]
    return None


def sam_buckets(text: str) -> dict[str, dict]:
    """Per-bucket settings from the SAM template.

    SAM nests everything inside one AWS::S3::Bucket resource; Terraform splits the same
    settings across four resource types. Both sides are reduced to this shape so they
    compare: {encryption, versioning, public_access_block(4 flags), eventbridge}.
    """
    buckets: dict[str, dict] = {}
    for block in re.split(r"\n  (?=\w+:\n    Type: AWS::S3::Bucket\n)", text):
        if not re.search(r"Type: AWS::S3::Bucket\n", block):
            continue
        name = re.search(r"BucketName:\s*!Ref\s+(\w+)", block)
        if not name:
            continue
        role = BUCKET_ROLES.get(name.group(1).lower())
        if role is None:
            continue
        pab = _slice_block(block, "      PublicAccessBlockConfiguration:") or ""
        buckets[role] = {
            "encryption": _one(block, r"SSEAlgorithm:\s*(\S+)"),
            "versioning": _one(block, r"VersioningConfiguration:\s*\n\s*Status:\s*(\S+)"),
            "block_public_acls": _one(pab, r"BlockPublicAcls:\s*(\S+)"),
            "block_public_policy": _one(pab, r"BlockPublicPolicy:\s*(\S+)"),
            "ignore_public_acls": _one(pab, r"IgnorePublicAcls:\s*(\S+)"),
            "restrict_public_buckets": _one(pab, r"RestrictPublicBuckets:\s*(\S+)"),
            "eventbridge": str("EventBridgeEnabled: true" in block).lower(),
        }
    return buckets


# Terraform bucket resource label ("source"/"sanitised"/"quarantine") -> shared role key.
TF_BUCKET_LABELS = {"source": "SOURCE", "sanitised": "SANITISED", "quarantine": "QUARANTINE"}


def tf_buckets(text: str) -> dict[str, dict]:
    """Per-bucket settings, gathered from the split-out Terraform resources."""
    buckets: dict[str, dict] = {
        role: {
            "encryption": None,
            "versioning": None,
            "block_public_acls": None,
            "block_public_policy": None,
            "ignore_public_acls": None,
            "restrict_public_buckets": None,
            "eventbridge": "false",
        }
        for label, role in TF_BUCKET_LABELS.items()
        if re.search(rf'resource\s+"aws_s3_bucket"\s+"{label}"', text)
    }

    for label, role in TF_BUCKET_LABELS.items():
        if role not in buckets:
            continue
        enc = _brace_block(
            text, f'resource "aws_s3_bucket_server_side_encryption_configuration" "{label}"')
        if enc:
            buckets[role]["encryption"] = _one(enc, r'sse_algorithm\s*=\s*"([^"]+)"')

        ver = _brace_block(text, f'resource "aws_s3_bucket_versioning" "{label}"')
        if ver:
            buckets[role]["versioning"] = _one(ver, r'status\s*=\s*"([^"]+)"')

        pab = _brace_block(text, f'resource "aws_s3_bucket_public_access_block" "{label}"')
        if pab:
            for flag in ("block_public_acls", "block_public_policy",
                         "ignore_public_acls", "restrict_public_buckets"):
                buckets[role][flag] = _one(pab, rf"{flag}\s*=\s*(\S+)")

        notif = _brace_block(text, f'resource "aws_s3_bucket_notification" "{label}"')
        if notif and re.search(r"eventbridge\s*=\s*true", notif):
            buckets[role]["eventbridge"] = "true"
    return buckets


def sam_tls_buckets(text: str) -> set[str]:
    """Which buckets get a DenyInsecureTransport policy in SAM."""
    found = set()
    for block in re.split(r"\n  (?=\w+:\n    Type: AWS::S3::BucketPolicy\n)", text):
        if "Type: AWS::S3::BucketPolicy\n" not in block:
            continue
        if "DenyInsecureTransport" not in block or 'Effect: Deny' not in block:
            continue
        if not re.search(r'"aws:SecureTransport":\s*"false"', block):
            continue
        m = re.search(r"Bucket:\s*!Ref\s+(\w+)", block)
        if m:
            # !Ref points at the bucket *resource* (SourceBucket), not the parameter.
            found.add(m.group(1).replace("Bucket", "").upper())
    return found


def tf_tls_buckets(text: str) -> set[str]:
    """Which buckets get a DenyInsecureTransport policy in Terraform."""
    found = set()
    stmt = _brace_block(text, "  tls_only_statement = {") or ""
    shared_ok = (
        "DenyInsecureTransport" in stmt
        and '"Deny"' in stmt
        and re.search(r'"aws:SecureTransport"\s*=\s*"false"', stmt)
    )
    for m in re.finditer(r'resource\s+"aws_s3_bucket_policy"\s+"(\w+)_tls"', text):
        label = m.group(1)
        block = _brace_block(text, m.group(0)) or ""
        # The Deny/Sid/Condition live in the shared local merged into each policy.
        inline_ok = (
            "DenyInsecureTransport" in block
            and re.search(r'"aws:SecureTransport"\s*=\s*"false"', block)
        )
        if (shared_ok and "tls_only_statement" in block) or inline_ok:
            role = TF_BUCKET_LABELS.get(label)
            if role:
                found.add(role)
    return found


def sam_alarms(text: str) -> dict[str, dict]:
    alarms = {}
    for block in re.split(r"\n  (?=\w+:\n    Type: AWS::CloudWatch::Alarm)", text):
        if "Type: AWS::CloudWatch::Alarm" not in block:
            continue
        name = re.search(r"AlarmName:.*?\$\{ResourcePrefix\}-([a-z0-9-]+)", block)
        if not name:
            continue
        alarms[name.group(1)] = {
            "metric": _one(block, r"MetricName:\s*(\S+)"),
            "namespace": _one(block, r"Namespace:\s*(\S+)"),
            "threshold": _one(block, r"Threshold:\s*(\S+)"),
            "comparison": _one(block, r"ComparisonOperator:\s*(\S+)"),
        }
    return alarms


def tf_alarms(text: str) -> dict[str, dict]:
    alarms = {}
    for m in re.finditer(r'resource\s+"aws_cloudwatch_metric_alarm"\s+"(\w+)"', text):
        block = _brace_block(text, m.group(0))
        if block is None:
            continue
        name = re.search(r"alarm_name\s*=\s*\"\$\{var\.resource_prefix\}-([a-z0-9-]+)", block)
        if not name:
            continue
        alarms[name.group(1)] = {
            "metric": _one(block, r'metric_name\s*=\s*"([^"]+)"'),
            "namespace": _one(block, r'namespace\s*=\s*"([^"]+)"'),
            "threshold": _one(block, r"threshold\s*=\s*(\S+)"),
            "comparison": _one(block, r'comparison_operator\s*=\s*"([^"]+)"'),
        }
    return alarms


def _one(block: str, pattern: str) -> str | None:
    m = re.search(pattern, block)
    return m.group(1).strip().strip('"') if m else None


def main() -> None:
    sam_text = SAM.read_text()
    tf_text = TF.read_text()
    problems: list[str] = []

    # Guard the parsers themselves: a regex that silently matches nothing would make
    # every comparison below trivially pass.
    sam_names, tf_names = sam_resource_names(sam_text), tf_resource_names(tf_text)
    sam_perms, tf_perms = sam_iam(sam_text), tf_iam(tf_text)
    sam_al, tf_al = sam_alarms(sam_text), tf_alarms(tf_text)
    sam_bk, tf_bk = sam_buckets(sam_text), tf_buckets(tf_text)
    sam_tls, tf_tls = sam_tls_buckets(sam_text), tf_tls_buckets(tf_text)
    # TLS policies are exempt from the both-sides-non-empty rule: a policy whose Deny or
    # SecureTransport condition has been broken legitimately parses as absent, and that is
    # real drift to report below rather than a parser fault to bail on. The bucket
    # resources themselves still anchor this axis against a silently-dead parser.
    for label, a, b in (
        ("resource names", sam_names, tf_names),
        ("IAM grants", sam_perms, tf_perms),
        ("alarms", sam_al, tf_al),
        ("buckets", sam_bk, tf_bk),
    ):
        if not a or not b:
            sys.exit(
                f"parser found no {label} on one side "
                f"(SAM={len(a)}, Terraform={len(b)}) — the parser is broken, not the IaC"
            )

    for missing in sorted(sam_names - tf_names):
        problems.append(f"  name '{{prefix}}-{missing}' is in SAM but not terraform/")
    for missing in sorted(tf_names - sam_names - TF_ONLY_NAMES):
        problems.append(f"  name '{{prefix}}-{missing}' is in terraform/ but not SAM")

    # Compare IAM on actions. Resource shapes differ legitimately (SAM managed templates
    # imply their scope), so an action granted by one path and not the other is the signal.
    sam_actions = {a for a, _ in sam_perms}
    tf_actions = {a for a, _ in tf_perms}
    for missing in sorted(sam_actions - tf_actions - SAM_ONLY_ACTIONS):
        problems.append(f"  IAM action '{missing}' granted in SAM but not terraform/")
    for missing in sorted(tf_actions - sam_actions - TF_ONLY_ACTIONS):
        problems.append(f"  IAM action '{missing}' granted in terraform/ but not SAM")

    # An allowance that stops being needed should be deleted, not left to rot.
    for stale in sorted(SAM_ONLY_ACTIONS - (sam_actions - tf_actions)):
        problems.append(f"  SAM_ONLY_ACTIONS lists '{stale}', but it is no longer SAM-only — remove it")
    for stale in sorted(TF_ONLY_ACTIONS - (tf_actions - sam_actions)):
        problems.append(f"  TF_ONLY_ACTIONS lists '{stale}', but it is no longer Terraform-only — remove it")
    for stale in sorted(TF_ONLY_NAMES - (tf_names - sam_names)):
        problems.append(f"  TF_ONLY_NAMES lists '{stale}', but it is no longer Terraform-only — remove it")

    for missing in sorted(set(sam_al) - set(tf_al)):
        problems.append(f"  alarm '{{prefix}}-{missing}' is in SAM but not terraform/")
    for missing in sorted(set(tf_al) - set(sam_al)):
        problems.append(f"  alarm '{{prefix}}-{missing}' is in terraform/ but not SAM")

    for name in sorted(set(sam_al) & set(tf_al)):
        for field in ("metric", "namespace", "threshold", "comparison"):
            s, t = sam_al[name][field], tf_al[name][field]
            if s is None or t is None:
                problems.append(f"  alarm '{name}': could not parse {field} (SAM={s!r}, TF={t!r})")
            elif _norm_num(s) != _norm_num(t):
                problems.append(f"  alarm '{name}' {field} differs: SAM={s!r}, terraform={t!r}")

    # Bucket-level settings. Each of these is a security control that fails open when
    # dropped: no encryption at rest, no versioning to recover overwritten evidence, or a
    # bucket that can be made public.
    for missing in sorted(set(sam_bk) - set(tf_bk)):
        problems.append(f"  {missing} bucket is provisioned in SAM but not terraform/")
    for missing in sorted(set(tf_bk) - set(sam_bk)):
        problems.append(f"  {missing} bucket is provisioned in terraform/ but not SAM")

    for role in sorted(set(sam_bk) & set(tf_bk)):
        for field in sorted(sam_bk[role]):
            s, t = sam_bk[role][field], tf_bk[role][field]
            if s is None or t is None:
                problems.append(
                    f"  {role} bucket: could not parse {field} (SAM={s!r}, terraform={t!r})")
            elif str(s).lower() != str(t).lower():
                problems.append(
                    f"  {role} bucket {field} differs: SAM={s!r}, terraform={t!r}")

    # TLS-only bucket policies. A bucket missing DenyInsecureTransport silently accepts
    # plaintext HTTP — no error, just an unencrypted transfer of a file under analysis.
    for missing in sorted(sam_tls - tf_tls):
        problems.append(
            f"  {missing} bucket has a TLS-only policy in SAM but not terraform/")
    for missing in sorted(tf_tls - sam_tls):
        problems.append(
            f"  {missing} bucket has a TLS-only policy in terraform/ but not SAM")
    for role in sorted(set(sam_bk) & set(tf_bk)):
        if role not in sam_tls:
            problems.append(f"  {role} bucket has no TLS-only policy in SAM")
        if role not in tf_tls:
            problems.append(f"  {role} bucket has no TLS-only policy in terraform/")

    if problems:
        print("src/template.yaml and terraform/ have drifted:", file=sys.stderr)
        print("\n".join(problems), file=sys.stderr)
        print(
            "\nBoth paths provision the same stack — a change to one is not a change to "
            "the deployment.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(
        f"IaC parity: {len(sam_names)} resource names, {len(sam_actions)} IAM actions, "
        f"{len(sam_al)} alarms, {len(sam_bk)} buckets (encryption/versioning/"
        f"public-access-block/EventBridge) and {len(sam_tls)} TLS-only policies match "
        "across src/template.yaml and terraform/."
    )


def _norm_num(v: str) -> str:
    """250000 and 250000.0 are the same threshold."""
    try:
        return str(float(v))
    except (TypeError, ValueError):
        return v


if __name__ == "__main__":
    main()
