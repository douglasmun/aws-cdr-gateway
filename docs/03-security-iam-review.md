# Manual 03 — Security and IAM Review

Run this review after every deploy (`sam deploy` or `tofu apply`) and before allowing
external traffic to reach the source bucket. Each check has a pass/fail command. Annotate
any deviation in your change management system before proceeding.

Estimated time: 20–30 minutes.

> **IaC paths:** the commands below that look up resources via CloudFormation
> (`describe-stack-resources` / `describe-stacks`) assume the **SAM** deploy. For the
> **OpenTofu/Terraform** deploy, get the same values from outputs instead — e.g.
> `ROLE_NAME=cdr-lambda-role`, `RESULT_TOPIC_ARN=$(cd terraform && tofu output -raw result_topic_arn)`,
> `ALARM_TOPIC_ARN=$(cd terraform && tofu output -raw alarm_topic_arn)`,
> `DLQ_URL=$(aws sqs get-queue-url --queue-name cdr-lambda-dlq --query QueueUrl --output text)`.
> The bucket variables come from the corresponding `tofu output` values. The EventBridge
> rule is `cdr-s3-object-created` (Terraform) vs `cdr-lambda-S3Upload` (SAM); §4.1 finds
> it by `cdr` prefix, so that check works for both.

---

## 1. Lambda execution role — least privilege

### 1.1 List the role's attached policies

```bash
STACK=cdr-lambda-staging

# Get the Lambda execution role name
ROLE_NAME=$(aws cloudformation describe-stack-resources \
  --stack-name $STACK \
  --query "StackResources[?ResourceType=='AWS::IAM::Role'].PhysicalResourceId" \
  --output text)

echo "Role: $ROLE_NAME"

# List attached managed policies
aws iam list-attached-role-policies --role-name $ROLE_NAME \
  --query 'AttachedPolicies[].PolicyName' --output table

# List inline policies
aws iam list-role-policies --role-name $ROLE_NAME \
  --query 'PolicyNames' --output table
```

The role should have **no AWS managed policies** beyond `AWSLambdaBasicExecutionRole`
(which grants CloudWatch Logs write only). All S3, SNS, SQS, and CloudWatch Metrics
permissions should be in inline policies scoped to specific resource ARNs.

### 1.2 Verify S3 permissions are resource-scoped

```bash
# Retrieve and inspect each inline policy
for POLICY_NAME in $(aws iam list-role-policies --role-name $ROLE_NAME --query 'PolicyNames[]' --output text); do
  echo "=== $POLICY_NAME ==="
  aws iam get-role-policy \
    --role-name $ROLE_NAME \
    --policy-name $POLICY_NAME \
    --query 'PolicyDocument' \
    --output json
done
```

Check each S3 statement. Every `s3:GetObject`, `s3:PutObject`, and `s3:DeleteObject`
action must have a `Resource` that is a specific bucket ARN, not `"arn:aws:s3:::*"`.

Example of a correctly scoped S3 statement:

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:DeleteObject"],
  "Resource": "arn:aws:s3:::cdr-prod-source-acme/*"
}
```

Note: the template scopes the source statements to the whole bucket
(`${SourceBucketName}/*`), not a key prefix — the EventBridge rule has no key-prefix
filter, so processing must work for any key. Do not over-tighten to `incoming/*` unless
you also add a matching prefix filter to the EventBridge rule.

**Flag:** Any statement with `Resource: "*"` or `Resource: "arn:aws:s3:::*"` is
over-privileged. Tighten the scope in `src/template.yaml` and redeploy.

### 1.3 Confirm the quarantine copy path is authorised (GetObject + PutObject)

There is no `s3:CopyObject` IAM action — a server-side copy is authorised by
`s3:GetObject` on the source and `s3:PutObject` on the destination. Simulate BOTH legs:

```bash
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::$ACCOUNT:role/$ROLE_NAME \
  --action-names s3:GetObject \
  --resource-arns arn:aws:s3:::$SOURCE_BUCKET/* \
  --query 'EvaluationResults[0].EvalDecision'
# Expected: "allowed"

aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::$ACCOUNT:role/$ROLE_NAME \
  --action-names s3:PutObject \
  --resource-arns arn:aws:s3:::$QUARANTINE_BUCKET/* \
  --query 'EvaluationResults[0].EvalDecision'
# Expected: "allowed"
```

If either is `"implicitDeny"`: the oversized-file quarantine copy will silently fail.
Update the IAM policy and redeploy.

---

## 2. S3 bucket hardening

### 2.1 All buckets block public access

```bash
for BUCKET in $SOURCE_BUCKET $SANITISED_BUCKET $QUARANTINE_BUCKET; do
  [ -z "$BUCKET" ] && continue
  echo "=== $BUCKET ==="
  aws s3api get-public-access-block --bucket $BUCKET \
    --query 'PublicAccessBlockConfiguration'
done
```

All four fields must be `true`:

```json
{
    "BlockPublicAcls": true,
    "IgnorePublicAcls": true,
    "BlockPublicPolicy": true,
    "RestrictPublicBuckets": true
}
```

**Fix if false:**

```bash
aws s3api put-public-access-block \
  --bucket $BUCKET \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,\
    BlockPublicPolicy=true,RestrictPublicBuckets=true
```

### 2.2 Server-side encryption enabled

```bash
for BUCKET in $SOURCE_BUCKET $SANITISED_BUCKET $QUARANTINE_BUCKET; do
  [ -z "$BUCKET" ] && continue
  echo "=== $BUCKET ==="
  aws s3api get-bucket-encryption --bucket $BUCKET \
    --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm'
done
# Expected: "AES256" for each bucket
```

### 2.3 Versioning enabled on all three buckets

```bash
for BUCKET in $SOURCE_BUCKET $SANITISED_BUCKET $QUARANTINE_BUCKET; do
  [ -z "$BUCKET" ] && continue
  echo "=== $BUCKET ==="
  aws s3api get-bucket-versioning --bucket $BUCKET \
    --query 'Status'
done
# Expected: "Enabled" for each
```

Versioning allows recovery of a file if the sanitised output is accidentally overwritten
or a delete races with a downstream read. The quarantine bucket is versioned too — it
holds rejected/malicious evidence, where preserving overwritten objects matters most.

### 2.4 TLS-only bucket policy present; no public-*allow* statement

Each bucket has a TLS-only policy: a single `Deny` statement on `aws:SecureTransport=false`
with `Principal: "*"`. A `"*"` principal on a **Deny** is correct and intended; a `"*"`
principal on an **Allow** would grant public access and must be removed. (BlockPublicPolicy
does not interfere with a non-public deny policy.)

```bash
for BUCKET in $SOURCE_BUCKET $SANITISED_BUCKET $QUARANTINE_BUCKET; do
  [ -z "$BUCKET" ] && continue
  echo "=== $BUCKET ==="
  aws s3api get-bucket-policy --bucket $BUCKET --query Policy --output text 2>/dev/null \
    | python3 -m json.tool || echo "FAIL: no bucket policy (expected a TLS-only deny)"
done
```

For each bucket confirm:
- A statement with `"Effect": "Deny"`, `"Condition": {"Bool": {"aws:SecureTransport": "false"}}` (the TLS-only guard) is present.
- **No** statement with `"Effect": "Allow"` and `"Principal": "*"` (that would be public access — remove it immediately).

### 2.5 SNS topics and DLQ encrypted at rest

```bash
# Both SNS topics should use SSE (the AWS-managed key alias/aws/sns).
for ARN in $RESULT_TOPIC_ARN $ALARM_TOPIC_ARN; do
  [ -z "$ARN" ] && continue
  echo "=== $ARN ==="
  aws sns get-topic-attributes --topic-arn $ARN \
    --query 'Attributes.KmsMasterKeyId'
done
# Expected: "alias/aws/sns" (not null)
```

The DLQ encryption is verified in §6.

---

## 3. Presigned POST policy

The source bucket accepts uploads from your application via presigned POST URLs. Confirm
the policy your application generates matches these requirements:

| Field | Required value | Why |
|---|---|---|
| `Content-Type` | Restricted to accepted MIME types (e.g. `application/vnd.openxmlformats-officedocument.*`, `application/pdf`, `image/*`) | First-line filter on accepted types (weak, client-declared — the CDR Lambda fails closed on any unrecognised extension regardless) |
| `key` | Starts with `incoming/` (optional convention) | A key-prefix convention for tidiness. NOTE: the EventBridge rule does **not** filter by key prefix today, so this is not load-bearing; if you rely on it, add a matching `key` prefix to the EventBridge pattern |
| `content-length-range` | `0` to `104857600` (100 MB) | Matches `CdrMaxFileBytes`; prevents the Lambda from receiving files larger than it will accept |
| Expiry | ≤ 15 minutes | Limits the window during which a leaked URL can be reused |

If your application generates presigned POST URLs, verify the policy:

```bash
# Generate a test presigned POST from your application, then inspect the
# 'fields' object it returns. The 'Policy' field is base64-encoded JSON.
echo "<paste the Policy value here>" | base64 -d | python3 -m json.tool
```

Look for `content-length-range`, `Content-Type`, and `key` conditions in the decoded
policy. If any are missing, fix the URL generation code in your application layer —
CDR cannot enforce these at the Lambda level.

---

## 4. EventBridge rule — scope and state

### 4.1 Rule is ENABLED

```bash
RULE_NAME=$(aws events list-rules \
  --query "Rules[?contains(Name,'cdr')].Name" \
  --output text | head -1)

aws events describe-rule --name $RULE_NAME --query 'State'
# Expected: "ENABLED"
```

### 4.2 Event pattern restricts to correct bucket and reason

```bash
aws events describe-rule --name $RULE_NAME \
  --query 'EventPattern' --output text | python3 -m json.tool
```

The event pattern must include:

```json
"detail": {
  "bucket": { "name": ["cdr-prod-source-acme"] },
  "reason": ["PutObject", "CompleteMultipartUpload"]
}
```

**If `reason` is missing:** The rule fires on `CopyObject` events too. CDR uses
`s3.copy_object` to quarantine oversized files — if the quarantine bucket is also
watched by EventBridge, this creates an infinite processing loop. Fix by adding
`"reason": ["PutObject", "CompleteMultipartUpload"]` to the event pattern in
`src/template.yaml` and redeploying.

**If the bucket name is a wildcard:** CDR will process uploads to all buckets in
the account, including the sanitised bucket. Fix immediately.

---

## 5. CloudWatch alarms — verify wiring

### 5.1 All six alarms exist

```bash
aws cloudwatch describe-alarms \
  --alarm-name-prefix cdr-lambda \
  --query 'MetricAlarms[].{Name:AlarmName,State:StateValue,Actions:AlarmActions}' \
  --output table
```

Expected alarms:
- `cdr-lambda-errors` — threshold 1, period 60 s
- `cdr-lambda-duration-p99` — threshold 250000 ms, period 300 s
- `cdr-lambda-throttles` — threshold 1, period 60 s
- `cdr-lambda-dlq-depth` — threshold 1, period 60 s
- `cdr-lambda-passthrough` — threshold 1, period 300 s
- `cdr-lambda-zip-anomalies` — threshold 5, period 300 s

### 5.2 Each alarm has an action pointing to `CdrAlarmTopic`

In the output above, `Actions` must list the `CdrAlarmTopic` ARN — not
`CdrResultTopic`, not an empty list.

```bash
ALARM_TOPIC_ARN=$(aws cloudformation describe-stack-resources \
  --stack-name $STACK \
  --query "StackResources[?LogicalResourceId=='CdrAlarmTopic'].PhysicalResourceId" \
  --output text)

aws cloudwatch describe-alarms \
  --alarm-name-prefix cdr-lambda \
  --query "MetricAlarms[?!contains(AlarmActions, '$ALARM_TOPIC_ARN')].AlarmName" \
  --output text
# Expected: empty output (all alarms have the correct topic)
```

Any alarm name printed means it is missing its SNS action. Fix in `src/template.yaml`
and redeploy.

### 5.3 Alarm topic subscription confirmed

```bash
aws sns list-subscriptions-by-topic \
  --topic-arn $ALARM_TOPIC_ARN \
  --query 'Subscriptions[].{Protocol:Protocol,Endpoint:Endpoint,Status:SubscriptionArn}'
```

Confirm at least one subscription is `PendingConfirmation` (email) or `Confirmed`
(all other protocols). If the list is empty, alarm notifications will be silently
discarded.

---

## 6. DLQ — confirm retention and alarm

```bash
DLQ_URL=$(aws cloudformation describe-stack-resources \
  --stack-name $STACK \
  --query "StackResources[?LogicalResourceId=='CdrDlq'].PhysicalResourceId" \
  --output text)

aws sqs get-queue-attributes \
  --queue-url $DLQ_URL \
  --attribute-names MessageRetentionPeriod ApproximateNumberOfMessages SqsManagedSseEnabled \
  --query 'Attributes'
```

Expected:
- `MessageRetentionPeriod`: `1209600` (14 days = 1,209,600 seconds)
- `ApproximateNumberOfMessages`: `0`
- `SqsManagedSseEnabled`: `true` (SSE at rest)

If depth > 0 before smoke tests have run, an event from a previous deploy cycle
may be stuck. See `docs/04-operations-runbook.md` §3 for DLQ inspection procedure.

---

## 7. Lambda concurrency and tracing

```bash
aws lambda get-function-concurrency --function-name cdr-lambda
```

Expected: `ReservedConcurrentExecutions: 20`

If not set, a burst of simultaneous large-file uploads can cause the Lambda to
scale to hundreds of concurrent instances, exhausting `/tmp` storage and memory.

X-Ray active tracing is enabled by default (set `enable_xray_tracing=false` for the
Terraform path, or remove `Tracing: Active` for SAM, to disable it):

```bash
aws lambda get-function-configuration --function-name cdr-lambda \
  --query 'TracingConfig.Mode'
# Expected: "Active" (or "PassThrough" if intentionally disabled)
```

---

## 8. CloudWatch Logs retention

By default, Lambda log groups have **infinite retention**, which accumulates cost
indefinitely. Set a finite retention period:

```bash
aws logs put-retention-policy \
  --log-group-name /aws/lambda/cdr-lambda \
  --retention-in-days 90
```

Verify:

```bash
aws logs describe-log-groups \
  --log-group-name-prefix /aws/lambda/cdr-lambda \
  --query 'logGroups[].{Name:logGroupName,RetentionDays:retentionInDays}' \
  --output table
# Expected: retentionInDays = 90
```

Choose a retention period that satisfies your data retention policy. 90 days is a
common baseline — enough for incident forensics and `docs/benchmark.py` queries,
without open-ended log accumulation.

---

## 9. S3 lifecycle rules

Without lifecycle rules, objects in the sanitised and quarantine buckets accumulate
indefinitely. Configure rules to expire old objects on a schedule that matches your
data retention policy.

### 9.1 Sanitised bucket — expire after downstream consumption window

```bash
aws s3api put-bucket-lifecycle-configuration \
  --bucket $SANITISED_BUCKET \
  --lifecycle-configuration '{
    "Rules": [{
      "ID": "expire-sanitised-objects",
      "Status": "Enabled",
      "Filter": {"Prefix": "sanitised/"},
      "Expiration": {"Days": 30},
      "NoncurrentVersionExpiration": {"NoncurrentDays": 7}
    }]
  }'
```

Adjust `Days` to match how long your downstream consumers need access after CDR
completes. If downstream consumers process files within minutes, 7 days is a
generous window; 30 days suits longer audit requirements.

### 9.2 Quarantine bucket — retain for investigation, then expire

```bash
aws s3api put-bucket-lifecycle-configuration \
  --bucket $QUARANTINE_BUCKET \
  --lifecycle-configuration '{
    "Rules": [{
      "ID": "expire-quarantine-objects",
      "Status": "Enabled",
      "Filter": {"Prefix": ""},
      "Expiration": {"Days": 90},
      "NoncurrentVersionExpiration": {"NoncurrentDays": 7}
    }]
  }'
```

90 days gives the security team time to review quarantined files before automatic
deletion. Adjust to match your data retention policy. Do not set this shorter than
the investigation SLA agreed in `docs/04-operations-runbook.md` §7.

### 9.3 Verify rules are active

```bash
for BUCKET in $SANITISED_BUCKET $QUARANTINE_BUCKET; do
  [ -z "$BUCKET" ] && continue
  echo "=== $BUCKET ==="
  aws s3api get-bucket-lifecycle-configuration --bucket $BUCKET \
    --query 'Rules[].{ID:ID,Status:Status,Expiry:Expiration.Days}' \
    --output table
done
```

---

## Security review sign-off

- [ ] Lambda execution role has no wildcard `Resource` in S3 statements
- [ ] Quarantine copy path authorised: `s3:GetObject` on source AND `s3:PutObject` on quarantine both simulate `allowed`
- [ ] All three buckets have all four public access block settings = `true`
- [ ] All three buckets have `AES256` encryption
- [ ] All three buckets (source, sanitised, quarantine) have versioning `Enabled`
- [ ] All three buckets have a TLS-only `Deny` policy (`aws:SecureTransport=false`); no `Allow` statement with `Principal: "*"`
- [ ] Both SNS topics + the DLQ have SSE at rest enabled
- [ ] Presigned POST policy includes `Content-Type`, `key`, and `content-length-range` conditions
- [ ] EventBridge rule is `ENABLED`, scoped to correct bucket, and has `reason` filter
- [ ] All six CloudWatch alarms exist, have `CdrAlarmTopic` action, and at least one confirmed subscription
- [ ] DLQ retention = 14 days, depth = 0
- [ ] Lambda `ReservedConcurrentExecutions` = 20 (or tuned value); X-Ray tracing `Active` (or disabled-by-choice documented)
- [ ] CloudWatch Logs retention set on `/aws/lambda/cdr-lambda` (90 days or per policy)
- [ ] S3 lifecycle rule on sanitised bucket: objects expire after downstream consumption window
- [ ] S3 lifecycle rule on quarantine bucket: objects expire after investigation retention period

**Next step:** `docs/04-operations-runbook.md` — incident response procedures.
