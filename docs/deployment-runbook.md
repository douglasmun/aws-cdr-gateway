# CDR Lambda — Staging Deployment and Load Benchmark Runbook

This runbook takes you from zero to a deployed, benchmarked CDR Lambda in a staging
AWS account. Estimated time: 30–45 minutes.

## Choose an IaC path

There are two equivalent infrastructure-as-code paths that provision the **same** stack —
pick one:

- **Option A — AWS SAM** (Sections 1A–2A). One toolchain handles build + deploy.
- **Option B — OpenTofu / Terraform** (Sections 1B–2B). A standalone build step produces
  the Lambda zip, then `tofu`/`terraform` provisions everything else.

Both produce a Lambda named `<ResourcePrefix>-lambda` and the same buckets/alarms/topics,
so the **smoke test, benchmark, and tuning (Sections 3–7) are identical regardless of
path** — only the deploy and teardown commands differ. Section 8 (cleanup) and Section 9
(known issues) have a subsection per path where they diverge.

> **Set `ResourcePrefix` before you deploy.** The Lambda, SNS topics, DLQ and alarm names
> are account-and-region-scoped and derive from the `ResourcePrefix` parameter (default
> `cdr`). Two stacks in one region collide unless it differs, and a `cdr-*` deployment may
> already exist in your target account — possibly managed by another IaC tool and serving
> live traffic. **Absence from CloudFormation does not mean unmanaged.** If a deploy fails
> at `AWS::EarlyValidation::ResourceExistenceCheck`, choose a distinct prefix; never delete
> the resource holding the name (see Section 9).
>
> Every command below uses `$PREFIX`. Export it once, matching your deployed value:
>
> ```bash
> PREFIX=cdr-staging   # must match the ResourcePrefix you deployed with
> ```

---

## Prerequisites

```bash
# Verify the AWS CLI and authenticate (both paths)
aws --version                 # must be >= 2.x
aws sso login                 # or: export AWS_PROFILE=your-staging-profile
aws sts get-caller-identity   # must print your account ID cleanly
```

**Option A (SAM):**
```bash
brew install aws-sam-cli       # macOS
sam --version                  # must be >= 1.100
```

**Option B (OpenTofu / Terraform) — also needs the build toolchain:**
```bash
brew install opentofu          # or: brew install terraform
tofu version                   # >= 1.6  (or terraform >= 1.5)
python3 --version              # 3.x + pip, and the `zip` CLI, for scripts/build.sh
```

Python 3.x and `pip` are required for the benchmark script (`docs/benchmark.py`)
regardless of path.

---

## 1A. Build (SAM)

```bash
cd src

# SAM builds a deployment package inside .aws-sam/build/
sam build
```

Expected output ends with `Build Succeeded`. If it fails:
- `ModuleNotFoundError` — check `src/requirements.txt` pins; run `pip install -r requirements.txt` locally to verify
- `Template format error` — validate with `sam validate`

> **The package includes the test and local-service files — this is known and accepted.**
> `template.yaml` uses `CodeUri: ./`, so `sam build` bundles all of `src/`: `app.py`,
> `conftest.py`, `test_cdr.py`, `test_cdr_local.py`, `requirements-dev.txt` and
> `requirements-local.txt` ship alongside `lambda_function.py`. Measured 2026-08-14 at
> **296 KB of a 66.8 MB package (0.43%)**, far from Lambda's 250 MB limit. None of it is
> reachable: `Handler` is pinned to `lambda_function.handler`, and fastapi/uvicorn/
> starlette/pytest are absent from the package, so `app.py` and the test modules raise
> `ModuleNotFoundError` if anything tries to import them.
>
> **Do not "fix" this with a `.samignore`** — SAM CLI 1.163.0's Python builder does not
> honour one. Verified empirically: adding the file and rebuilding from clean changed
> nothing. (`sam build -x/--exclude` excludes whole *resources*, not files.) The two
> approaches that do work are `Metadata: BuildMethod: makefile` on the function, or
> repointing `CodeUri` at a runtime-only subdirectory. Both were rejected as a worse
> trade than 296 KB: the makefile route replaces SAM's tested dependency install with a
> hand-written step that must reproduce the hash-pinned `scripts/lambda-requirements.txt`
> exactly (a naive version built from `src/requirements.txt` instead and came out **16 MB
> larger**, with 65 stray `__pycache__` directories), and `CodeUri` retargeting breaks the
> `import lambda_function` co-location that `app.py` and both test modules depend on.
> Revisit only if package size becomes a real constraint.

---

## 2A. First deploy — SAM (guided)

```bash
sam deploy --guided
```

SAM will prompt for each parameter. Suggested staging values:

| Parameter | Staging value |
|---|---|
| `ResourcePrefix` | `cdr-staging` — **do not leave at the `cdr` default** unless you have confirmed nothing in the account already owns those names |
| `SourceBucketName` | `cdr-staging-source-<your-alias>` |
| `SanitisedBucketName` | `cdr-staging-sanitised-<your-alias>` |
| `QuarantineBucketName` | `cdr-staging-quarantine-<your-alias>` (or leave blank) |
| `CdrMaxFileBytes` | `104857600` (100 MB default) |
| `CdrMaxEntryBytes` | `209715200` (200 MB default) |
| Stack name | `cdr-staging-stack` (typed literally — SAM prompts are not shell-expanded) |
| AWS Region | your preferred region |
| Confirm changeset | `y` |
| Save config | `y` → saved to `samconfig.toml` |

The deploy creates all buckets, Lambda, EventBridge rule, SNS topics, SQS DLQ,
and CloudWatch alarms in one stack. Subsequent deploys:

```bash
sam deploy   # uses saved samconfig.toml — no prompts
```

> Skip Sections 1B–2B if you deployed with SAM. Continue at **Section 3 (Verify)**.

---

## 1B. Build the Lambda package (OpenTofu / Terraform)

The Terraform path does not package the Lambda itself — `scripts/build.sh` does. It
installs the C-extension dependencies (`pikepdf`, `Pillow`) as **Linux** wheels for the
3.12 runtime (host/macOS wheels would not run on Lambda), verifies them against the
hash-pinned `scripts/lambda-requirements.txt`, and produces a reproducible
`build/lambda.zip`.

```bash
# From the repo root
./scripts/build.sh
```

Expected tail: `>> Done: …/build/lambda.zip (12M)`. The same inputs always produce an
identical zip (and therefore an identical `source_code_hash`). If it fails:
- `'zip'/'python3' not found` — install the missing tool (the script preflights both).
- A hash mismatch — a dependency version changed; regenerate the hashes with
  `python3 scripts/regen_lambda_requirements.py` (it reads the versions from
  `src/requirements.txt` and rewrites `scripts/lambda-requirements.txt`).

> **Bumping a dependency is a two-file change.** `src/requirements.txt` feeds the tests,
> the container and local dev; `scripts/lambda-requirements.txt` is what actually ships to
> Lambda. Editing only the former leaves the deployed artifact on the old version — how
> `pikepdf`/`Pillow` silently fell two releases behind. Run the regen script after any bump;
> CI (`scripts/check_lambda_requirements.py`) fails the build if the two disagree.

---

## 2B. Deploy — OpenTofu / Terraform

Examples use `tofu`; substitute `terraform` if that is what you have (the `.tf` files are
identical).

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars        # set globally-unique bucket names + region
```

Suggested staging values for `terraform.tfvars`:

| Variable | Staging value |
|---|---|
| `aws_region` | your preferred region |
| `source_bucket_name` | `cdr-staging-source-<your-alias>` |
| `sanitised_bucket_name` | `cdr-staging-sanitised-<your-alias>` |
| `quarantine_bucket_name` | `cdr-staging-quarantine-<your-alias>` (or `""` to disable) |
| `cdr_max_file_bytes` | `104857600` (default) — optional |
| `cdr_max_entry_bytes` | `209715200` (default) — optional |

```bash
tofu init      # downloads the AWS provider pinned by .terraform.lock.hcl
tofu plan      # review: ~20 resources to add
tofu apply     # type 'yes' to create the stack
```

`tofu apply` creates all buckets (with TLS-only policies), the Lambda (X-Ray on), the
EventBridge rule, both SNS topics, the SQS DLQ, and the six CloudWatch alarms.

Capture the outputs (used by the smoke test and benchmark below):

```bash
tofu output                                   # all outputs
SOURCE_BUCKET=$(tofu output -raw source_bucket)
SANITISED_BUCKET=$(tofu output -raw sanitised_bucket)
ALARM_TOPIC=$(tofu output -raw alarm_topic_arn)
```

Subscribe your ops channel to `alarm_topic_arn` and any downstream consumer to
`result_topic_arn`.

**Re-deploying after a code change:** rebuild, then apply — Terraform updates the function
when the zip hash changes.

```bash
./scripts/build.sh && (cd terraform && tofu apply)
```

> Continue at **Section 3 (Verify)**. The `STACK` / `describe-stacks` commands there are
> SAM-specific; the Terraform equivalents are noted inline.

---

## 3. Verify the stack

The Lambda check is identical for both paths. The resource-inventory and EventBridge-rule
commands differ — use the block for your path.

```bash
# Lambda deployed and healthy (both paths)
aws lambda get-function-configuration \
  --function-name $PREFIX-lambda \
  --query '{Runtime:Runtime,MemorySize:MemorySize,Timeout:Timeout,State:State}'
```

**SAM** — the EventBridge rule's logical ID is `CdrFunctionS3Upload`, but its physical name is auto-generated with a random suffix (e.g. `$PREFIX-stack-CdrFunctionS3Upload-BJXdknPZ9Hq7`), not a fixed string — look it up from the stack resources first:
```bash
STACK=$PREFIX-stack

aws cloudformation describe-stack-resources \
  --stack-name $STACK \
  --query 'StackResources[].{Type:ResourceType,Status:ResourceStatus,Name:LogicalResourceId}' \
  --output table

RULE_NAME=$(aws cloudformation describe-stack-resource \
  --stack-name $STACK \
  --logical-resource-id CdrFunctionS3Upload \
  --query 'StackResourceDetail.PhysicalResourceId' --output text)

aws events list-targets-by-rule \
  --rule "$RULE_NAME" \
  --query 'Targets[].Arn'
```

**OpenTofu / Terraform** — the EventBridge rule is named `${resource_prefix}-s3-object-created`, i.e. `$PREFIX-s3-object-created` (it is *not* the fixed string `cdr-s3-object-created` unless you deployed with the default prefix):
```bash
( cd terraform && tofu state list )          # resource inventory

aws events list-targets-by-rule \
  --rule $PREFIX-s3-object-created \
  --query 'Targets[].Arn'
```

---

## 4. Smoke test — single file upload

First resolve the bucket names (skip if you already exported them in Section 2B):

```bash
# SAM:
SOURCE_BUCKET=$(aws cloudformation describe-stacks --stack-name $STACK \
  --query "Stacks[0].Parameters[?ParameterKey=='SourceBucketName'].ParameterValue" --output text)
SANITISED_BUCKET=$(aws cloudformation describe-stacks --stack-name $STACK \
  --query "Stacks[0].Parameters[?ParameterKey=='SanitisedBucketName'].ParameterValue" --output text)

# OpenTofu / Terraform:
# SOURCE_BUCKET=$(cd terraform && tofu output -raw source_bucket)
# SANITISED_BUCKET=$(cd terraform && tofu output -raw sanitised_bucket)
```

```bash
# Upload a test DOCX (create one or use any .docx from your machine)
aws s3 cp /path/to/test.docx s3://$SOURCE_BUCKET/smoke/test.docx

# Wait ~5 seconds, then check sanitised bucket
aws s3 ls s3://$SANITISED_BUCKET/sanitised/smoke/

# Check S3 tags on the sanitised output
aws s3api get-object-tagging \
  --bucket $SANITISED_BUCKET \
  --key sanitised/smoke/test.docx \
  --query 'TagSet'
```

Expected tags: `cdr-status=sanitised`, `cdr-mode=full`, `cdr-removals=N`,
`cdr-original-ext=docx`, `cdr-zip-anomaly=false`.

Check Lambda logs for the CDR completion line:

```bash
aws logs tail /aws/lambda/$PREFIX-lambda --follow --format short
```

---

## 5. Load benchmark

Run the benchmark script after the smoke test passes:

```bash
# From repo root
source bin/activate
pip install boto3            # add botocore[crt] if you authenticate with `aws login`

python docs/benchmark.py \
  --bucket $SOURCE_BUCKET \
  --files docs/fixtures/ \
  --concurrency 5 \
  --function $PREFIX-lambda \
  --log-group /aws/lambda/$PREFIX-lambda
```

> **Pass `--function`.** It defaults to `cdr-lambda`, so omitting it on a stack deployed
> with any other prefix silently queries the wrong function — CloudWatch returns no
> datapoints for a function that never ran your load. The script now exits non-zero rather
> than printing a pass on empty metrics, but a run that errors out mid-benchmark still
> costs you the whole cycle. It must match the deployed `ResourcePrefix`.

`docs/fixtures/` contains 17 pre-built files with real active content covering every
CDR path (VBA, DDE, PDF JavaScript, xlsb conversion, GIF comment block, etc.). Run
`python docs/fixtures/generate_fixtures.py` first if the directory is empty.

The script uploads every non-`.py`/`.md` file in the directory, waits for Lambda
invocations to complete, then reports p50/p99 Duration, peak memory, error count,
and throttle count with automatic tuning recommendations.

See **Section 6** below for interpreting results and tuning decisions.

---

## 6. Benchmark results — what to look for

Query Lambda metrics after the benchmark run:

```bash
FUNCTION_ARN=$(aws lambda get-function \
  --function-name $PREFIX-lambda \
  --query 'Configuration.FunctionArn' --output text)

# Date helper — macOS uses -v, Linux uses -d
# macOS:  START=$(date -u -v-10M '+%Y-%m-%dT%H:%M:%SZ')
# Linux:  START=$(date -u -d '10 minutes ago' '+%Y-%m-%dT%H:%M:%SZ')
# Cross-platform Python alternative:
START=$(python3 -c "from datetime import datetime,timezone,timedelta; print((datetime.now(timezone.utc)-timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ'))")
END=$(python3   -c "from datetime import datetime,timezone; print(datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))")

# p99 duration over the last 10 minutes
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Duration \
  --dimensions Name=FunctionName,Value=$PREFIX-lambda \
  --start-time $START \
  --end-time   $END \
  --period 600 \
  --extended-statistics p50 p99 \
  --query 'Datapoints[0].{p50:ExtendedStatistics.p50,p99:ExtendedStatistics.p99}'

# Max memory used — NOT a CloudWatch metric. `MaxMemoryUsed` does not exist in the
# AWS/Lambda namespace; querying it returns an empty Datapoints list, which reads as
# "no memory pressure" when it actually means "no such metric". The number lives only
# in the Lambda REPORT log line, so pull it from Logs Insights (this is what
# docs/benchmark.py does):
START_EPOCH=$(python3 -c "from datetime import datetime,timezone,timedelta; print(int((datetime.now(timezone.utc)-timedelta(minutes=10)).timestamp()))")
END_EPOCH=$(python3   -c "from datetime import datetime,timezone; print(int(datetime.now(timezone.utc).timestamp()))")
QID=$(aws logs start-query \
  --log-group-name /aws/lambda/$PREFIX-lambda \
  --start-time $START_EPOCH \
  --end-time   $END_EPOCH \
  --query-string 'filter @message like /REPORT/ | parse @message "Max Memory Used: * MB" as mem | stats max(mem) as max_mem' \
  --query queryId --output text)
sleep 5
aws logs get-query-results --query-id "$QID" --query 'results[0][0].value'
```

Or skip the manual queries entirely and run `python docs/benchmark.py --bucket <source-bucket>`,
which reports p50/p99 duration, throttles and max memory in one pass.

### Tuning thresholds

| Metric | Current setting | Action if exceeded |
|---|---|---|
| p99 Duration > 250 s | Timeout = 300 s | Increase `Timeout` in `template.yaml`; re-deploy |
| p99 Duration > 200 s on PDFs | 1024 MB memory | Increase `MemorySize` (Lambda CPU scales with RAM) |
| Max Memory Used > 900 MB (REPORT log line) | 1024 MB memory | Increase `MemorySize` to 2048 MB |
| Throttles > 0 | `ReservedConcurrentExecutions: 20` | Increase reservation if throughput SLA demands it |
| DLQ depth > 0 | — | Inspect DLQ messages: `aws sqs receive-message --queue-url <DLQ_URL>` |

To change memory or timeout without recreating everything (in-place update, no bucket
recreation):

```bash
# SAM — edit MemorySize/Timeout in src/template.yaml, then:
sam deploy

# OpenTofu / Terraform — set lambda_memory_mb / lambda_timeout_seconds in
# terraform.tfvars (they are variables, no code edit needed), then:
cd terraform && tofu apply
```

---

## 7. Benchmark fixture sizes

Test with files that represent your real workload. Minimum recommended set:

| File | Size | Why |
|---|---|---|
| Small DOCX (clean) | ~50 KB | Baseline cold/warm start |
| Large XLSX with macros | ~5 MB | Typical business file |
| Large XLSX | ~50 MB | Exercises size guard boundary |
| PDF with JavaScript | ~1 MB | pikepdf path |
| Large PDF | ~100 MB | Exercises p99 duration for pikepdf |
| PNG | ~2 MB | Pillow path |
| DOCX with VBA + external links | any | Multi-threat CDR path |

Use `docs/fixtures/` (run `python docs/fixtures/generate_fixtures.py` once to
produce all 17 files). These cover every CDR path with real active content and are
more representative than synthetic random bytes.

---

## 8. Cleanup

The buckets are **versioned** (including quarantine), so neither tool can delete them
while they hold objects or delete-markers. Empty all object *versions* first. This is a
deliberate safety property — the IaC does not set `force_destroy`, so a teardown of a
non-empty bucket fails loudly rather than silently destroying evidence.

```bash
# Purge every version + delete-marker from each bucket (repeat per bucket).
empty_bucket () {
  local b="$1"
  aws s3api list-object-versions --bucket "$b" \
    --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}' --output json \
    > /tmp/v.json
  aws s3api delete-objects --bucket "$b" --delete file:///tmp/v.json 2>/dev/null || true
  aws s3api list-object-versions --bucket "$b" \
    --query '{Objects: DeleteMarkers[].{Key:Key,VersionId:VersionId}}' --output json \
    > /tmp/d.json
  aws s3api delete-objects --bucket "$b" --delete file:///tmp/d.json 2>/dev/null || true
}
empty_bucket "$SOURCE_BUCKET"
empty_bucket "$SANITISED_BUCKET"
# empty_bucket "<quarantine-bucket>"   # if one was created
```

**SAM:**
```bash
aws cloudformation delete-stack --stack-name $STACK
aws cloudformation wait stack-delete-complete --stack-name $STACK
echo "Stack deleted."
```

**OpenTofu / Terraform:**
```bash
cd terraform
tofu destroy        # type 'yes'; fails on any bucket still holding versions
echo "Stack destroyed."
```

---

## 9. Known deployment issues

**`CREATE_FAILED` on S3 bucket — BucketAlreadyExists**
Bucket names are globally unique. Add a suffix to `SourceBucketName` /
`SanitisedBucketName`. Alternatively, if the buckets were created by a previous
failed deploy, delete them manually before redeploying.

**(SAM) Deploy fails at `AWS::EarlyValidation::ResourceExistenceCheck`**
Something in the account already owns a name this stack wants. The Lambda, SNS topics, DLQ
and alarm names are account-and-region-scoped and derive from `ResourcePrefix`, so this
fires when another stack — or another IaC tool entirely — holds them.

**Do not delete the resource to free the name.** Absence from CloudFormation does not mean
it is unmanaged or unused: it may be a live service managed by Terraform/CDK from a
different repo. Identify the owner before doing anything:

<!-- prefix-literal-ok: this whole block investigates the FOREIGN cdr-lambda that already owns the name — $PREFIX would point at the reader's own stack and defeat the check -->
```bash
# Is it serving traffic? Recent log activity is the fastest tell.
aws logs tail /aws/lambda/cdr-lambda --since 30d --format short | tail -20

# Who created it? Check for tags and any IaC state you can reach.
aws lambda list-tags --resource "$(aws lambda get-function \
  --function-name cdr-lambda --query 'Configuration.FunctionArn' --output text)"
```

The correct fix is a distinct `ResourcePrefix` for *your* stack. If the existing deployment
genuinely should go, removal is the owning tool's job (`terraform destroy` from that repo)
— deleting via CLI or console desyncs its state and breaks whatever depends on it.

**(SAM) `ROLLBACK_COMPLETE` — SNSPublishMessagePolicy cannot find topic**
The `CdrResultTopic` must exist before the policy is evaluated. This is a SAM
ordering issue that resolves by running `sam deploy` a second time after the
rollback completes. (The Terraform path declares this dependency explicitly and is
not affected.)

**Lambda function not triggered after upload**
Check that the EventBridge rule is `ENABLED`. The rule name differs by path:
```bash
# SAM: physical name has an auto-generated suffix — look it up first (see section 3)
RULE_NAME=$(aws cloudformation describe-stack-resource \
  --stack-name $PREFIX-stack \
  --logical-resource-id CdrFunctionS3Upload \
  --query 'StackResourceDetail.PhysicalResourceId' --output text)
aws events describe-rule --name "$RULE_NAME"             --query 'State'

# OpenTofu / Terraform:
aws events describe-rule --name $PREFIX-s3-object-created --query 'State'
```
If disabled, enable it with `aws events enable-rule --name <rule>`.

**`AccessDenied` writing an oversized file to quarantine**
The quarantine copy is authorised by `s3:GetObject` (source) + `s3:PutObject`
(destination) — there is no `s3:CopyObject` IAM action. Verify quarantine was enabled
at deploy time (`QuarantineBucketName` non-empty for SAM; `quarantine_bucket_name` set
for Terraform). If quarantine was disabled, oversized files log a warning but still
publish a `rejected` result — no data loss.

**(Terraform) `tofu plan`/`apply` errors that the file `../build/lambda.zip` does not exist**
The package is built out of band. Run `./scripts/build.sh` (Section 1B) before
`tofu plan`. The `source_code_hash` is read from that file at plan time.

**(Terraform) Lambda fails at runtime with an import error for pikepdf/Pillow**
The package was built with the wrong wheel platform. `scripts/build.sh` must install
`manylinux_2_28_x86_64` wheels (the default), and `lambda_architecture` must be `x86_64`
to match. For arm64, switch both (see `terraform/README.md`).

**(Terraform) provider version drift between operators**
`.terraform.lock.hcl` is committed and pins the provider with checksums; everyone runs
the same version. If `tofu init` reports a lock mismatch, run `tofu init -upgrade` and
commit the updated lock file rather than deleting it.
