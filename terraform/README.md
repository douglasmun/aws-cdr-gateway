# OpenTofu / Terraform deployment

OpenTofu (`tofu`) configuration that provisions the **general CDR Lambda** and all its
infrastructure — a faithful port of `src/template.yaml` (the AWS SAM template). The two
are parallel deploy paths; pick one. This config manages everything *except* packaging:
the Lambda zip is built separately by `scripts/build.sh`.

> The `.tf` files are standard HCL and work unchanged with either **OpenTofu** (`tofu`)
> or **Terraform** (`terraform`). Examples below use `tofu`; swap the binary name if you
> use Terraform.

## What it creates

- Source, sanitised, and (optional) quarantine S3 buckets — AES256, versioning,
  public-access blocked, and a TLS-only bucket policy; EventBridge notifications enabled
  on the source bucket
- The CDR Lambda (`python3.12`, x86_64, 1024 MB, 300 s, `ReservedConcurrentExecutions = 20`,
  X-Ray active tracing) with a least-privilege IAM role
- EventBridge rule restricted to `PutObject` / `CompleteMultipartUpload`
- SQS dead-letter queue (14-day retention, SSE at rest)
- Two SNS topics — `cdr-result-topic` (result metadata) and `cdr-alarm-topic` (alarms),
  both with SSE at rest
- Six CloudWatch alarms → the alarm topic: errors, p99 duration, throttles, DLQ depth,
  passthrough files, ZIP anomalies

## Prerequisites

- OpenTofu >= 1.6 (or Terraform >= 1.5), AWS provider ~> 5.0
- AWS credentials with permission to create the above
- `python3` + `pip` and the `zip` CLI (for the build step)

## Deploy

```bash
# 1. Build the Lambda package (Linux wheels for pikepdf/Pillow + handler source).
#    Run from the repo root. Produces build/lambda.zip.
./scripts/build.sh

# 2. Configure variables.
cd terraform
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars        # set globally-unique bucket names + region

# 3. Provision.
tofu init
tofu plan
tofu apply
```

After `apply`, subscribe your ops channel to the `alarm_topic_arn` output and your
downstream consumer to `result_topic_arn`.

## Rebuilding after a code change

The Lambda is updated when the zip's hash changes:

```bash
./scripts/build.sh
cd terraform && tofu apply
```

## Notes

- **Native wheels:** `pikepdf` and `Pillow` are C extensions. `scripts/build.sh` installs
  `manylinux_2_28_x86_64` wheels (glibc 2.28; the Lambda runtime is Amazon Linux 2023 /
  glibc 2.34, so they run) — hash-pinned in `scripts/lambda-requirements.txt`. For an
  arm64 (Graviton) Lambda: change `PLATFORM` in `build.sh` to `manylinux_2_28_aarch64`,
  **regenerate the hashes** in `lambda-requirements.txt` (the wheel sha256s differ per
  platform — the file has the command), and set `lambda_architecture = "arm64"`.
- **X-Ray:** active tracing is on by default; set `enable_xray_tracing = false` to disable
  it (and its IAM grant).
- **Quarantine is optional:** leave `quarantine_bucket_name = ""` to skip the quarantine
  bucket and its IAM grant entirely (mirrors the SAM `QuarantineEnabled` condition).
- **Provider lock:** `.terraform.lock.hcl` is committed and pins the exact AWS provider
  version with checksums for `linux_amd64`, `darwin_arm64`, and `linux_arm64`, so CI and
  laptops resolve the same provider. To bump it: `tofu init -upgrade` then
  `tofu providers lock -platform=…` and commit the result.
- **Encryption at rest:** S3 buckets use SSE-S3 (AES256); the DLQ uses SQS-managed SSE and
  both SNS topics use the AWS-managed key (`alias/aws/sns`). All three S3 buckets —
  including quarantine — have versioning enabled.
- **State:** local by default. To use an S3 + DynamoDB backend, create the bucket and
  lock table, then uncomment the `backend "s3"` block in `versions.tf` and run
  `tofu init -migrate-state`.
- **Pre-existing source bucket:** if the source bucket already exists, remove the
  `aws_s3_bucket.source` resources and instead `tofu import` it (or enable EventBridge
  notifications on it manually).
- The full operational guidance (smoke tests, IAM review, runbooks) lives in `docs/00–04`
  and applies regardless of whether you deploy via Terraform or SAM.
