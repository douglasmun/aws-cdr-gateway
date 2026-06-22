# CDR Pipeline — Production Readiness Index

This index lists every manual and runbook required to take the CDR Lambda pipeline
from a tested codebase to a live production deployment. Complete the manuals in the
order listed. Do not skip ahead — each manual assumes the previous one is done.

---

## Document map

| # | Document | Purpose | Who |
|---|---|---|---|
| 00 | This file | Sequence guide and overall checklist | Tech lead |
| 01 | `01-infrastructure-setup.md` | Account, credentials, bucket names, SNS subscribers, downstream dependencies | DevOps / infra |
| 02 | `deployment-runbook.md` | Build, deploy, smoke test (single file), load benchmark | DevOps |
| 03 | `02-smoke-test-playbook.md` | Full smoke test across all CDR paths (all formats + rejection paths) | DevOps / QA |
| 04 | `03-security-iam-review.md` | IAM least-privilege, bucket hardening, EventBridge scope, alarm wiring | Security / DevOps |
| 05 | `04-operations-runbook.md` | Incident response for every alarm type; rollback; quarantine review; maintenance schedule | On-call engineer |
| — | `../terraform/README.md` | OpenTofu/Terraform deploy reference (alternative to SAM) | DevOps |
| — | `local-cdr.md` | Local CDR HTTP service (`app.py`) — run, configure, embed, deploy-behind-proxy, API contract, security model. Same `cdr_dispatch` core as the Lambda; no AWS account | App devs / integrators |
| — | `deploy-container.md` | Containerise the local service as a sidecar — Docker, Compose, Kubernetes, hardening checklist | App devs / DevOps |
| — | `cdr-gap-analysis-stevens.md` | Threat-coverage gap analysis vs Didier Stevens' maldoc toolkit; documents the JBIG2/JPX decoder-filter hardening | Security |

**Choose an IaC path before starting.** The stack can be deployed with **AWS SAM**
(`src/template.yaml`) or **OpenTofu/Terraform** (`terraform/`). They provision the same
resources; the `deployment-runbook.md` documents both, and this checklist is written to
apply to either — items that differ are marked **(SAM)** or **(Terraform)**.

---

## Deployment sequence

```
01-infrastructure-setup.md
        │
        │  Prerequisites satisfied, bucket names chosen, SNS subscribers identified
        ▼
deployment-runbook.md  §1–3
        │
        │  SAM:        sam build && sam deploy --guided        → stack created
        │  Terraform:  ./scripts/build.sh && tofu apply        → stack created
        ▼
deployment-runbook.md  §4
        │
        │  Single DOCX smoke test passes (tags correct, source deleted)
        ▼
02-smoke-test-playbook.md
        │
        │  All 7 format/rejection tests pass, alarms OK, DLQ = 0
        ▼
03-security-iam-review.md
        │
        │  IAM, bucket hardening, EventBridge scope, alarm wiring all verified
        ▼
deployment-runbook.md  §5–6
        │
        │  Load benchmark: p99 < 250 s, peak memory < 900 MB, 0 errors, 0 throttles
        ▼
04-operations-runbook.md  (read-through before go-live)
        │
        │  Emergency contacts filled in, SLAs confirmed, team briefed
        ▼
Go live — open source bucket to application traffic
```

---

## Pre-production sign-off checklist

All items below must be checked before opening the source bucket to live traffic.
The responsible person and date should be recorded alongside each check.

### Infrastructure (Manual 01)

- [ ] AWS account confirmed (`aws sts get-caller-identity` returns staging/prod account)
- [ ] AWS CLI ≥ 2.x installed and verified
- [ ] IaC path chosen and toolchain installed: **(SAM)** SAM CLI ≥ 1.100 — or — **(Terraform)** OpenTofu ≥ 1.6 / Terraform ≥ 1.5, plus `python3`+`pip`+`zip` for `scripts/build.sh`
- [ ] Three bucket names chosen, globally unique, confirmed available
- [ ] Quarantine decision documented (enabled or disabled, with reason)
- [ ] `CdrResultTopic` subscriber endpoints identified and documented
- [ ] `CdrAlarmTopic` subscriber endpoints identified; email subscription confirmed (clicked link)
- [ ] Downstream dependency confirmed: either dual-layer pipeline deployed (Option A) or CDR-only gap documented (Option B)

### Deployment (deployment-runbook.md)

- [ ] Build completed without errors: **(SAM)** `sam build` — or — **(Terraform)** `./scripts/build.sh` produced `build/lambda.zip`
- [ ] Deploy completed; all resources created: **(SAM)** `sam deploy --guided` → `CREATE_COMPLETE` — or — **(Terraform)** `tofu apply` → apply complete
- [ ] Stack outputs verified: Lambda exists, EventBridge rule active (`cdr-lambda-S3Upload` for SAM / `cdr-s3-object-created` for Terraform), SNS topics created
- [ ] Deploy config stored: **(SAM)** `samconfig.toml` committed/secured — or — **(Terraform)** `.terraform.lock.hcl` committed; `terraform.tfvars` stored securely (not committed); remote state backend configured for production

### Smoke tests — all formats (Manual 02)

- [ ] Test 1 — DOCX with VBA macro: sanitised, VBA absent, source deleted, tags correct
- [ ] Test 2 — PDF with `/OpenAction`: sanitised, `/OpenAction` absent
- [ ] Test 3 — xlsb with sheet binary: output is `.xlsx`, cell values correct, no `<f>` formula elements
- [ ] Test 4 — GIF: output is `.gif`, comment block (`0x21 0xFE`) absent
- [ ] Test 5 — Legacy `.doc`: quarantined under `unsupported/`, not sanitised, source deleted
- [ ] Test 6 — Oversized file: quarantined under `oversized/` via `copy_object`, source not deleted
- [ ] Test 7 — Bad ZIP magic: quarantined under `rejected/`, source deleted
- [ ] All six CloudWatch alarms in `OK` state after smoke tests
- [ ] DLQ depth = 0

### Security review (Manual 03)

- [ ] Lambda execution role has no wildcard `Resource` in S3 statements
- [ ] IAM policy simulation: `s3:GetObject` (source) + `s3:PutObject` (quarantine) both = `allowed` (the copy path; there is no `s3:CopyObject` action)
- [ ] All three buckets: all four public access block settings = `true`
- [ ] All three buckets: server-side encryption = `AES256`
- [ ] All three buckets (source, sanitised, **and quarantine**): versioning = `Enabled`
- [ ] All three buckets: TLS-only bucket policy present (`Deny` on `aws:SecureTransport=false`); no policy with `Principal: "*"` that *allows* access
- [ ] Presigned POST policy: `Content-Type`, `key` prefix, and `content-length-range` conditions present
- [ ] EventBridge rule: `ENABLED`, correct bucket name, `reason` filter = `[PutObject, CompleteMultipartUpload]` (rule name `cdr-lambda-S3Upload` for SAM / `cdr-s3-object-created` for Terraform)
- [ ] All six CloudWatch alarms have `CdrAlarmTopic` SNS action (not `CdrResultTopic`)
- [ ] `CdrAlarmTopic`: at least one confirmed subscriber
- [ ] DLQ: `MessageRetentionPeriod` = 1209600 (14 days), SSE at rest enabled, depth = 0
- [ ] Both SNS topics: SSE at rest enabled (`alias/aws/sns`)
- [ ] Lambda: X-Ray active tracing enabled (or `enable_xray_tracing=false` documented), architecture matches the built wheels (`x86_64`)
- [ ] Lambda `ReservedConcurrentExecutions` set (default 20 or tuned value documented)
- [ ] CloudWatch Logs retention set on `/aws/lambda/cdr-lambda` (90 days or per data retention policy)
- [ ] S3 lifecycle rule on sanitised bucket: objects expire after downstream consumption window
- [ ] S3 lifecycle rule on quarantine bucket: objects expire after investigation retention period (≥ 90 days)

### Load benchmark (deployment-runbook.md §5–6)

- [ ] `docs/benchmark.py` executed with `--log-group` specified
- [ ] p99 duration < 250,000 ms (250 s)
- [ ] Peak memory < 900 MB
- [ ] Error count = 0
- [ ] Throttle count = 0 (or acceptable throttle rate documented)
- [ ] DLQ depth = 0 after benchmark

### Operational readiness (Manual 04)

- [ ] Emergency contacts table filled in (`04-operations-runbook.md` §9)
- [ ] SLAs confirmed with stakeholders and filled in
- [ ] On-call engineer has read `04-operations-runbook.md` and can execute each incident procedure
- [ ] Quarantine review process agreed (who reviews, what tool, retention policy)
- [ ] Rollback procedure tested in staging at least once

---

## Known gaps (document before go-live)

The following items are outside the scope of this codebase and must be tracked
separately:

1. **Malware Scan Lambda** — the AV scanning half of the dual-layer pipeline is not
   in this repository. If deploying CDR-only, document that the AV layer is absent.

2. **Result Aggregator Lambda** — the component that combines CDR and AV results and
   routes files to clean/sanitised/quarantine is not in this repository. Until it is
   deployed, files are sanitised by CDR but not routed downstream.

3. **Application-layer presigned POST URL generation** — the backend that generates
   presigned POST URLs for clients is not in this repository. The `Content-Type`
   restriction, `key` prefix, and `content-length-range` conditions in the policy
   must be verified in that codebase.

4. **Downstream consumer readiness** — whatever subscribes to `CdrResultTopic` and
   acts on CDR results must be deployed and smoke-tested independently.

5. **Automated deploy (CD)** — a GitHub Actions CI workflow (`.github/workflows/tests.yml`)
   already runs the full test suite and builds the Lambda package on every push/PR, and
   Dependabot keeps the pinned actions and Python deps current. There is **no automated
   *deploy* step** — `sam deploy` / `tofu apply` are still run manually by an operator. If
   you add continuous deployment, gate it on the existing test job and store the deploy
   parameters (SAM `samconfig.toml`, or Terraform `tfvars` + a remote state backend with
   locking) as CI secrets/OIDC — do not commit `terraform.tfvars`.

6. **`main` branch protection is NOT enabled.** GitHub blocks server-side branch
   protection (classic protection *and* repository rulesets) on **free private** repos —
   it requires GitHub Pro/Team, or the repo to be public. While the repo is private with a
   single contributor this is a workflow-safety gap (accidental force-push / history
   rewrite), **not a security exposure** — only granted collaborators can push at all.

   **⚠ Action required if this repo is ever made public OR gains additional collaborators:**
   enable branch protection on `main` immediately. Settings → Branches (or Rules → Rulesets):
   require a pull request before merging, require the CI status checks **`test (3.12)`** and
   **`build-package`** to pass, and block force-pushes and branch deletion. Equivalent via
   the API once the plan/visibility allows it:

   ```bash
   gh api -X PUT repos/douglasmun/aws-cdr-gateway/branches/main/protection \
     -f required_status_checks.strict=true \
     -f 'required_status_checks.contexts[]=test (3.12)' \
     -f 'required_status_checks.contexts[]=build-package' \
     -F enforce_admins=true \
     -f required_pull_request_reviews.required_approving_review_count=1 \
     -F restrictions=  # null = no push restriction beyond the above
   ```

   In the meantime, a client-side `pre-push` hook (`scripts/hooks/pre-push`, installed via
   `./scripts/install-hooks.sh`) blocks force-pushes and deletions of `main` in a local
   clone — but it only protects the machine it is installed on, and is bypassable with
   `git push --no-verify`. It is a mitigation, not a replacement for server-side rules.

---

## Version history

| Date | Change | Author |
|---|---|---|
| 2026-05-06 | Initial version | |
| 2026-06-21 | Added OpenTofu/Terraform deploy path; updated checklist for 6 alarms, all-bucket versioning + TLS-only policies, DLQ/SNS SSE, X-Ray, and the GitHub Actions CI | |
| 2026-06-21 | Documented Known Gap #6: `main` branch protection unavailable on free private repo — must be enabled if the repo goes public or gains collaborators | |

Update this table whenever a manual is revised.
