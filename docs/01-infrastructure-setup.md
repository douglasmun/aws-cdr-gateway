# Manual 01 — Infrastructure Setup

This manual covers everything that must be in place before you run `sam deploy` for
the first time. Complete every section in order. Each step includes a verification
command so you can confirm success before moving on.

Estimated time: 45–90 minutes (mostly waiting on IAM propagation and bucket creation).

---

## 1. AWS account and credentials

### 1.1 Choose the right account

CDR must be deployed in an account that is **not** your production application account
for the first deploy. Use a dedicated staging account or an isolated sandbox.

```bash
# Confirm you are authenticated to the correct account
aws sts get-caller-identity
```

Expected output:
```json
{
    "UserId": "AIDA...",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/your-name"
}
```

Write down the account ID — you will need it when scoping IAM policies.

If the command returns an error, authenticate first:

```bash
# SSO-based login (recommended)
aws sso login --profile your-staging-profile
export AWS_PROFILE=your-staging-profile

# Key-based (if SSO is not available)
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=ap-southeast-1   # or your preferred region
```

### 1.2 Confirm region

All resources must be in the same region. Pick one and stick to it throughout this
manual.

```bash
aws configure get region
# Should print your target region, e.g. ap-southeast-1
```

If it prints nothing, set it:

```bash
aws configure set region ap-southeast-1
```

---

## 2. Toolchain versions

```bash
sam --version   # must be >= 1.100.0
aws --version   # must be >= 2.x
python3 --version  # must be >= 3.12
```

Install SAM CLI if missing:

```bash
# macOS
brew install aws-sam-cli

# Linux (x86_64)
curl -Lo sam.zip https://github.com/aws/aws-sam-cli/releases/latest/download/aws-sam-cli-linux-x86_64.zip
unzip sam.zip -d sam-install
sudo ./sam-install/install
```

---

## 3. Decide your bucket names

S3 bucket names are globally unique across all AWS accounts. Choose names now and
record them — you will enter them during `sam deploy --guided`.

| Bucket | Naming convention | Example |
|---|---|---|
| Source | `<project>-<env>-source-<suffix>` | `cdr-prod-source-acme` |
| Sanitised | `<project>-<env>-sanitised-<suffix>` | `cdr-prod-sanitised-acme` |
| Quarantine | `<project>-<env>-quarantine-<suffix>` | `cdr-prod-quarantine-acme` |

Rules:
- 3–63 characters, lowercase letters, numbers, hyphens only
- Must not start or end with a hyphen
- Must not look like an IP address (`192.168.1.1`)
- Must be globally unique — if `sam deploy` fails with `BucketAlreadyExists`, add
  a random suffix

Check availability before deploying:

```bash
SOURCE_BUCKET=cdr-prod-source-acme
SANITISED_BUCKET=cdr-prod-sanitised-acme
QUARANTINE_BUCKET=cdr-prod-quarantine-acme

for b in $SOURCE_BUCKET $SANITISED_BUCKET $QUARANTINE_BUCKET; do
  aws s3api head-bucket --bucket $b 2>/dev/null \
    && echo "TAKEN: $b" \
    || echo "AVAILABLE: $b"
done
```

Anything that prints `AVAILABLE` is safe to use.

---

## 4. Decide SAM parameters

Open `src/samconfig.toml` (created on first `--guided` deploy) or record these values
to enter at the `sam deploy --guided` prompt:

| Parameter | Description | Default | Your value |
|---|---|---|---|
| `SourceBucketName` | S3 bucket for incoming uploads | *(required)* | |
| `SanitisedBucketName` | S3 bucket for CDR output | *(required)* | |
| `QuarantineBucketName` | S3 bucket for rejected/errored files | *(empty = disabled)* | |
| `CdrMaxFileBytes` | Pre-download size limit in bytes | `104857600` (100 MB) | |
| `CdrMaxEntryBytes` | Per-ZIP-entry decompression limit | `209715200` (200 MB) | |

**On `QuarantineEnabled`:** The template deploys cleanly with an empty
`QuarantineBucketName`. If you leave it empty, oversized and rejected files are still
logged and published to SNS — they are just not copied to a quarantine bucket. For
production, enabling quarantine is strongly recommended so you can inspect rejected
files for threat intelligence.

---

## 5. Confirm SNS subscriber endpoints

The pipeline publishes to two SNS topics. You must decide who subscribes to each
before or immediately after deploy.

### 5.1 `CdrResultTopic` — application consumers

This topic receives a JSON message for every file processed:

```json
{
  "source": "s3://source-bucket/incoming/file.xlsx",
  "status": "sanitised",
  "timestamp": "2026-05-06T12:00:00Z",
  "report": { "ext": "xlsx", "removed": [...], "cdr_mode": "full" }
}
```

Status values: `sanitised`, `quarantined`, `rejected`, `source-missing`, `error`,
`unsupported-format`.

Subscribers might be:
- A Lambda that routes the sanitised file to downstream storage
- An SQS queue feeding a processing pipeline
- A webhook endpoint updating an audit log

**Do not subscribe your ops alerting endpoint to this topic.** CloudWatch alarm
notifications go to `CdrAlarmTopic` (see §5.2). Mixing them breaks application
message parsing.

To add a subscriber after deploy:

```bash
TOPIC_ARN=$(aws cloudformation describe-stack-resources \
  --stack-name cdr-lambda-staging \
  --query "StackResources[?LogicalResourceId=='CdrResultTopic'].PhysicalResourceId" \
  --output text)

# Subscribe an SQS queue
aws sns subscribe \
  --topic-arn $TOPIC_ARN \
  --protocol sqs \
  --notification-endpoint arn:aws:sqs:REGION:ACCOUNT:your-queue

# Subscribe an HTTPS endpoint
aws sns subscribe \
  --topic-arn $TOPIC_ARN \
  --protocol https \
  --notification-endpoint https://your-service.example.com/cdr-webhook
```

### 5.2 `CdrAlarmTopic` — ops alerting

This topic receives CloudWatch alarm state-change notifications. Subscribe your
on-call channel here (email, PagerDuty SNS endpoint, Slack via AWS Chatbot, etc.).

```bash
ALARM_TOPIC_ARN=$(aws cloudformation describe-stack-resources \
  --stack-name cdr-lambda-staging \
  --query "StackResources[?LogicalResourceId=='CdrAlarmTopic'].PhysicalResourceId" \
  --output text)

# Subscribe an email address (requires confirmation click in inbox)
aws sns subscribe \
  --topic-arn $ALARM_TOPIC_ARN \
  --protocol email \
  --notification-endpoint oncall@your-org.example.com
```

Check the inbox and click the confirmation link. Until confirmed, no alarm
notifications will be delivered.

---

## 6. Confirm the EventBridge rule scope

After deploy, verify the rule is restricted to your source bucket only and fires
only on `PutObject` / `CompleteMultipartUpload` — not on CDR's own `CopyObject`
calls, which would create a processing loop.

```bash
RULE_NAME=$(aws events list-rules \
  --query "Rules[?contains(Name,'cdr')].Name" \
  --output text | head -1)

aws events describe-rule --name $RULE_NAME \
  --query '{State:State,EventPattern:EventPattern}'
```

The `EventPattern` must contain:

```json
{
  "source": ["aws.s3"],
  "detail-type": ["Object Created"],
  "detail": {
    "bucket": { "name": ["YOUR-SOURCE-BUCKET"] },
    "reason": ["PutObject", "CompleteMultipartUpload"]
  }
}
```

If `reason` is missing or the bucket name is a wildcard, the rule is too broad.
Edit `src/template.yaml` → `CdrLambdaRule` → `EventPattern` and redeploy.

---

## 7. Confirm Lambda packaging

After `sam build`, confirm that the runtime dependencies were bundled correctly:

```bash
# Check that pyxlsb, openpyxl, pikepdf, and Pillow are in the build artifact
ls .aws-sam/build/CdrLambda/
```

You should see the library directories alongside `lambda_function.py`:

```
lambda_function.py
openpyxl/
pikepdf/
PIL/
pyxlsb/
boto3/
...
```

If any library is missing, check `src/requirements.txt` pins and re-run `sam build`.

---

## 8. Downstream dependencies

The architecture diagram shows a Malware Scan Lambda and a Result Aggregator Lambda.
These are **not** in this repository.

Before go-live, confirm one of the following:

**Option A — Full dual-layer pipeline deployed:**
Both the Malware Scan Lambda and Result Aggregator Lambda are deployed and
subscribed to the same EventBridge rule or topic. Verify by checking your
EventBridge rule targets:

```bash
aws events list-targets-by-rule --rule $RULE_NAME \
  --query 'Targets[].Arn'
```

**Option B — CDR-only deployment (no AV scan):**
The CDR Lambda operates standalone. Files flow: S3 → EventBridge → CDR Lambda →
Sanitised bucket. There is no AV gate. Downstream consumers subscribe directly to
`CdrResultTopic`. This is acceptable for an initial deployment but documents a
known gap in the defence-in-depth model.

Record which option applies to your deployment in your change management system.

---

## Checklist

Before running `sam deploy --guided`, confirm:

- [ ] `aws sts get-caller-identity` returns the correct staging account
- [ ] `sam --version` >= 1.100, `aws --version` >= 2.x
- [ ] Three bucket names chosen and confirmed available
- [ ] SAM parameters recorded (including quarantine decision)
- [ ] `CdrResultTopic` subscriber endpoint(s) identified
- [ ] `CdrAlarmTopic` subscriber endpoint(s) identified (email confirmed)
- [ ] Downstream Lambda dependencies confirmed (Option A or B above documented)

**Next step:** `docs/deployment-runbook.md` — build, deploy, and smoke test.
