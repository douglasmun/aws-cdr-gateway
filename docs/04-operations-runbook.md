# Manual 04 — Operations Runbook

This runbook is the on-call reference for the CDR Lambda pipeline. Each section
describes a specific failure mode, how to confirm it, and what to do.

Keep this document open whenever you are on-call for the CDR system.

> To subscribe an email/endpoint to the alarm topic, or to safely fire an alarm in a
> non-prod stack (e.g. to validate the notification chain before go-live), see
> [`docs/05-alarm-demo-walkthrough.md`](05-alarm-demo-walkthrough.md).

---

## Quick reference

| Alarm | Meaning | First action |
|---|---|---|
| `cdr-lambda-errors` | Lambda threw an unhandled exception | Jump to §1 |
| `cdr-lambda-duration-p99` | Processing is slow (> 250 s p99) | Jump to §2 |
| `cdr-lambda-throttles` | Concurrency limit hit | Jump to §3 |
| `cdr-lambda-dlq-depth` | Event exhausted all retries | Jump to §4 |
| `cdr-lambda-passthrough` | Unknown file extension reached pipeline | Jump to §5 |

---

## 1. Lambda errors spike

**Alarm:** `cdr-lambda-errors` fires (≥ 1 error in 60 s)

### Confirm

```bash
# Find the failing invocation's request ID
aws logs filter-log-events \
  --log-group-name /aws/lambda/cdr-lambda \
  --filter-pattern "ERROR" \
  --start-time $(python3 -c "import time; print(int((time.time()-600)*1000))") \
  --query 'events[*].message' \
  --output text | tail -20
```

CDR Lambda logs all errors with `key=value` format. Look for:
- `CDR processing failed: key=... error=...` — CDR threw during processing
- `Download failed: bucket=... key=...` — S3 get_object failed
- `Malformed EventBridge event` — upstream EventBridge misconfiguration

### Triage by error type

**`pikepdf.PdfError` or `zipfile.BadZipFile`**
The uploaded file is structurally malformed. Check whether `_validate_zip_structure`
should have caught this before CDR was attempted (it only runs for Office extensions).
If the file is from a known-good source and the error is repeatable, open a bug.

**`OutOfMemoryError` / `Runtime exited with error: signal: killed`**
The Lambda ran out of memory. Check peak memory used:

```bash
aws logs filter-log-events \
  --log-group-name /aws/lambda/cdr-lambda \
  --filter-pattern "Max Memory Used" \
  --start-time $(python3 -c "import time; print(int((time.time()-3600)*1000))") \
  --query 'events[*].message' \
  --output text | tail -5
```

If `Max Memory Used` is close to or equal to `MemorySize` (default 1024 MB),
increase memory:

```bash
# Edit src/template.yaml: MemorySize: 2048
sam deploy   # in-place update, no bucket recreation
```

**`botocore.exceptions.ClientError: AccessDenied`**
The Lambda execution role lacks a permission. Identify which API call failed from
the log line and check the IAM policy (`docs/03-security-iam-review.md` §1).

**`botocore.exceptions.EndpointResolutionError` / `Connection timeout`**
Transient AWS service issue. The file will be retried automatically by EventBridge
(up to the configured retry count). Monitor whether the error clears within 15 minutes.
If it persists, check the AWS Service Health Dashboard.

### Confirm recovery

After the root cause is resolved:

```bash
# Verify error rate returns to zero
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Errors \
  --dimensions Name=FunctionName,Value=cdr-lambda \
  --start-time $(python3 -c "import time; from datetime import datetime,timezone,timedelta; print((datetime.now(timezone.utc)-timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ'))") \
  --end-time   $(python3 -c "from datetime import datetime,timezone; print(datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))") \
  --period 60 \
  --statistics Sum \
  --query 'Datapoints[*].Sum'
```

Zero or absent means the error cleared.

---

## 2. p99 duration alarm

**Alarm:** `cdr-lambda-duration-p99` fires (p99 > 250,000 ms = 250 s)

The Lambda timeout is 300 s. A p99 over 250 s means some invocations are approaching
the timeout wall.

### Identify slow files

```bash
# Find invocations with duration > 200 s in CloudWatch Logs Insights
# (Run in the AWS Console → CloudWatch → Logs Insights, or via CLI)
aws logs start-query \
  --log-group-name /aws/lambda/cdr-lambda \
  --start-time $(python3 -c "import time; print(int(time.time()-3600))") \
  --end-time   $(python3 -c "import time; print(int(time.time()))") \
  --query-string 'filter @type="REPORT" | parse @message "Billed Duration: * ms" as duration | filter duration > 200000 | sort duration desc | limit 10 | fields @requestId, duration'
```

Copy the `queryId` from the output, then poll for results:

```bash
aws logs get-query-results --query-id <queryId>
```

Cross-reference request IDs with CDR log lines to find the file extension and size.

### Tuning actions

| Observation | Action |
|---|---|
| Slow invocations are all PDFs | Increase `MemorySize` to 2048 MB (Lambda CPU scales with RAM; `pikepdf` is CPU-bound) |
| Slow invocations are large Office files | Check file size — files approaching 100 MB take longer; consider lowering `CdrMaxFileBytes` if your use case allows |
| All file types are slow | Increase `MemorySize` to 2048 MB; if still slow, increase `Timeout` in `template.yaml` |
| Random slow invocations | Lambda cold starts; consider provisioned concurrency if latency SLA is strict |

Apply changes:

```bash
# Edit src/template.yaml (MemorySize, Timeout, or both), then:
sam deploy
```

---

## 3. Throttle alarm

**Alarm:** `cdr-lambda-throttles` fires (≥ 1 throttle in 60 s)

Throttles occur when the number of concurrent Lambda invocations hits
`ReservedConcurrentExecutions` (default 20).

### Confirm throttle rate

```bash
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Throttles \
  --dimensions Name=FunctionName,Value=cdr-lambda \
  --start-time $(python3 -c "from datetime import datetime,timezone,timedelta; print((datetime.now(timezone.utc)-timedelta(minutes=30)).strftime('%Y-%m-%dT%H:%M:%SZ'))") \
  --end-time   $(python3 -c "from datetime import datetime,timezone; print(datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))") \
  --period 60 \
  --statistics Sum \
  --query 'sort_by(Datapoints,&Timestamp)[*].{Time:Timestamp,Throttles:Sum}'
```

### Decision: increase or accept

Throttles cause EventBridge to retry the event after a backoff delay. For most
workloads, occasional throttles are acceptable — the file will be processed on retry.
If throttles are sustained or the retry delay violates your SLA:

```bash
# Increase reserved concurrency
# Edit src/template.yaml: ReservedConcurrentExecutions: 40
sam deploy
```

**Warning:** Each concurrent Lambda invocation can use up to 1024 MB of memory
(or 2048 MB if you increased it). Increasing concurrency increases peak memory
consumption on the Lambda service. Monitor `MaxMemoryUsed` after the change.

### Check account-level concurrency limit

AWS accounts have a default limit of 1,000 concurrent Lambda executions per region.
If other Lambdas in the account are also under load:

```bash
aws lambda get-account-settings \
  --query '{TotalConcurrency:AccountLimit.ConcurrentExecutions,UnreservedConcurrency:AccountLimit.UnreservedConcurrentExecutions}'
```

If total concurrency is near the account limit, request a limit increase via AWS
Support before increasing CDR's reservation.

---

## 4. DLQ depth alarm

**Alarm:** `cdr-lambda-dlq-depth` fires (≥ 1 message in 60 s)

A message in the DLQ means an event exhausted all EventBridge retries without the
Lambda returning success. The file was not sanitised and is still in the source bucket
(if it was not deleted by a partial run).

### Step 1 — Inspect the stuck message

```bash
DLQ_URL=$(aws cloudformation describe-stack-resources \
  --stack-name cdr-lambda-staging \
  --query "StackResources[?LogicalResourceId=='CdrDlq'].PhysicalResourceId" \
  --output text)

# Peek at the message (does not delete it)
aws sqs receive-message \
  --queue-url $DLQ_URL \
  --max-number-of-messages 1 \
  --visibility-timeout 300 \
  --query 'Messages[0]'
```

The message body is the original EventBridge event JSON. Extract the file key:

```bash
aws sqs receive-message \
  --queue-url $DLQ_URL \
  --max-number-of-messages 1 \
  --query 'Messages[0].Body' \
  --output text | python3 -m json.tool | grep '"key"'
```

### Step 2 — Find the Lambda error

```bash
# Search logs for this key
KEY="incoming/the-file.xlsx"  # replace with actual key from DLQ message

aws logs filter-log-events \
  --log-group-name /aws/lambda/cdr-lambda \
  --filter-pattern "$KEY" \
  --query 'events[*].message' \
  --output text
```

### Step 3 — Decide: replay or discard

**Replay** (fix the root cause first, then re-trigger):

```bash
# Re-upload the file to trigger a fresh EventBridge event
SOURCE_KEY="the-file.xlsx"
aws s3 cp s3://$SOURCE_BUCKET/incoming/$SOURCE_KEY /tmp/$SOURCE_KEY
aws s3 cp /tmp/$SOURCE_KEY s3://$SOURCE_BUCKET/incoming/$SOURCE_KEY

# Then delete the DLQ message
RECEIPT_HANDLE=$(aws sqs receive-message \
  --queue-url $DLQ_URL \
  --max-number-of-messages 1 \
  --query 'Messages[0].ReceiptHandle' \
  --output text)

aws sqs delete-message \
  --queue-url $DLQ_URL \
  --receipt-handle $RECEIPT_HANDLE
```

**Discard** (file is corrupt or unrecoverable):

```bash
# Delete the DLQ message
aws sqs delete-message \
  --queue-url $DLQ_URL \
  --receipt-handle $RECEIPT_HANDLE

# If the file is still in the source bucket, move it to quarantine manually
aws s3 mv s3://$SOURCE_BUCKET/incoming/$SOURCE_KEY \
          s3://$QUARANTINE_BUCKET/manual-review/$SOURCE_KEY
```

Document the discard decision and the reason in your incident log.

### Step 4 — Confirm DLQ is clear

```bash
aws sqs get-queue-attributes \
  --queue-url $DLQ_URL \
  --attribute-names ApproximateNumberOfMessages \
  --query 'Attributes.ApproximateNumberOfMessages'
# Expected: "0"
```

---

## 5. Passthrough alarm

**Alarm:** `cdr-lambda-passthrough` fires (≥ 1 passthrough file in 5 min)

A passthrough means a file with an unrecognised extension reached the pipeline and
was copied to the sanitised bucket without any CDR processing. This is a warning, not
an error — the file is not malicious by definition (CDR was not attempted), but it
bypassed all CDR defences.

### Find the file

```bash
aws logs filter-log-events \
  --log-group-name /aws/lambda/cdr-lambda \
  --filter-pattern "Unknown extension" \
  --query 'events[*].message' \
  --output text | tail -5
```

The log line includes `key=` and `ext=`.

### Decision tree

| Extension | Action |
|---|---|
| A common Office or image format you forgot to allow | Add it to `OFFICE_EXTS` or the image handler in `lambda_function.py`, add a test, redeploy |
| An extension your application should never send | Fix the upload validation in your application layer |
| A one-off edge case from a legitimate user | Accept for now; consider adding to a block-list in the handler if it recurs |
| An unknown binary format | Review the file in quarantine; if it looks malicious, delete from sanitised bucket immediately |

**If the file should not have been passed through:**

```bash
# Delete the passthrough file from the sanitised bucket
aws s3 rm s3://$SANITISED_BUCKET/sanitised/incoming/the-file.xyz

# If you have the original and want to quarantine it:
aws s3 cp s3://$SOURCE_BUCKET/incoming/the-file.xyz \
          s3://$QUARANTINE_BUCKET/manual-review/the-file.xyz
aws s3 rm s3://$SOURCE_BUCKET/incoming/the-file.xyz
```

---

## 6. Rollback procedure

If a deployment introduces a regression and smoke tests fail, roll back immediately.

### Option A — Redeploy previous version from Git

```bash
git log --oneline -5   # find the last known-good commit
git checkout <commit> -- src/lambda_function.py
sam build && sam deploy
```

### Option B — AWS Lambda version rollback

SAM deploys a new Lambda version on each `sam deploy`. To roll back to the previous
version:

```bash
# List published versions
aws lambda list-versions-by-function --function-name cdr-lambda \
  --query 'Versions[-5:].{Version:Version,Description:Description}' \
  --output table

# Point the function alias to a previous version (if you use aliases)
aws lambda update-alias \
  --function-name cdr-lambda \
  --name live \
  --function-version <previous-version-number>
```

If you do not use aliases, the simplest rollback is Option A.

---

## 7. Quarantine bucket review process

Files in the quarantine bucket are evidence. Follow this process:

1. **Do not open quarantined files on your workstation.** Download to an isolated
   analysis environment (sandbox VM, cloud-based malware analysis service).

2. **Log every review.** Record: file key, quarantine reason (from S3 tag
   `cdr-reason` or `cdr-status`), reviewer name, date, disposition.

3. **Disposition options:**
   - **False positive** — CDR rejected a legitimate file. Determine the root cause
     (e.g. non-standard ZIP structure). Fix CDR if appropriate. Re-upload the original
     through the pipeline after the fix is deployed.
   - **True positive** — File contains active content or malware. Do not re-upload.
     Escalate to your security team. Identify the uploader.
   - **Inconclusive** — Send to a malware analysis service (e.g. VirusTotal file
     submission API, any.run sandbox). Record the analysis result.

4. **Retention:** Keep quarantined files for at least 90 days or as required by your
   data retention policy.

```bash
# List quarantined files in the last 24 hours
aws s3api list-objects-v2 \
  --bucket $QUARANTINE_BUCKET \
  --query "Contents[?to_string(LastModified) > '\"`date -u -v-1d '+%Y-%m-%d'`\"'].{Key:Key,Size:Size,LastModified:LastModified}" \
  --output table
```

---

## 8. Routine maintenance

### 8.1 Weekly

```bash
# Check DLQ depth
aws sqs get-queue-attributes \
  --queue-url $DLQ_URL \
  --attribute-names ApproximateNumberOfMessages \
  --query 'Attributes.ApproximateNumberOfMessages'

# Check for alarm state changes in the last 7 days
aws cloudwatch describe-alarm-history \
  --alarm-name-prefix cdr-lambda \
  --history-item-type StateUpdate \
  --start-date $(python3 -c "from datetime import datetime,timezone,timedelta; print((datetime.now(timezone.utc)-timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%SZ'))") \
  --query 'AlarmHistoryItems[].{Name:AlarmName,Time:Timestamp,Reason:HistorySummary}' \
  --output table
```

### 8.2 Monthly

- Review `MaxMemoryUsed` trend. If it has been creeping up toward 900 MB, schedule
  a `MemorySize` increase before it becomes an alarm.
- Review quarantine bucket object count. If it is growing, investigate whether a
  category of files is being systematically rejected.
- Run `pip install --upgrade` on `src/requirements.txt` in a dev environment, run the
  test suite (`cd src && pytest test_cdr.py -v`), and schedule dependency updates if
  patches are available for `pikepdf`, `Pillow`, `pyxlsb`, or `openpyxl`.
- Confirm CloudWatch Logs retention is still set on `/aws/lambda/cdr-lambda`:

  ```bash
  aws logs describe-log-groups \
    --log-group-name-prefix /aws/lambda/cdr-lambda \
    --query 'logGroups[].{Name:logGroupName,RetentionDays:retentionInDays}' \
    --output table
  ```

  AWS does not automatically re-apply retention if the log group is recreated (e.g.
  after a stack teardown and redeploy). If `retentionInDays` is `null`, re-apply
  the policy per `docs/03-security-iam-review.md` §8.

- Confirm S3 lifecycle rules are still active on sanitised and quarantine buckets
  (see `docs/03-security-iam-review.md` §9.3). Lifecycle rules survive stack
  updates but are lost if a bucket is deleted and recreated.

### 8.3 After any AWS Lambda runtime update

AWS periodically deprecates Lambda runtimes. When `python3.12` is deprecated, you
must update `src/template.yaml` → `Runtime` and re-test:

```bash
# Check runtime deprecation status
aws lambda get-function-configuration \
  --function-name cdr-lambda \
  --query '{Runtime:Runtime,RuntimeVersionArn:RuntimeVersionConfig.RuntimeVersionArn}'
```

Run the full test suite and smoke test playbook after any runtime version change.

---

## 9. Emergency contacts and escalation

Fill in before go-live:

| Role | Name | Contact |
|---|---|---|
| CDR system owner | | |
| On-call engineer | | |
| AWS account owner | | |
| Security incident response | | |
| Downstream consumer team | | |

**SLA for CDR alarms:**

| Alarm | Response SLA | Resolution SLA |
|---|---|---|
| `cdr-lambda-errors` | 15 minutes | 2 hours |
| `cdr-lambda-dlq-depth` | 30 minutes | 4 hours |
| `cdr-lambda-duration-p99` | 1 hour | next business day |
| `cdr-lambda-throttles` | 30 minutes | 2 hours |
| `cdr-lambda-passthrough` | 1 business day | 1 week |

Fill in your organisation's actual SLAs. These values are illustrative.
