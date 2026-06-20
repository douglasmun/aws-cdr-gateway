# Alarm Demo — Subscribe to Notifications and Fire an Alarm

A reproducible walkthrough that wires an email to the CDR alarm topic, then deliberately
triggers the **ZIP-anomaly** alarm so you can see the full observability chain end-to-end
on the live stack:

```
malformed uploads → CDR Lambda hard-rejects → ZipAnomalies metric → CloudWatch alarm → SNS → email
```

This was run against the staging deployment in `ap-southeast-1` (account `<AWS_ACCOUNT_ID>`).
Substitute your own bucket/topic names if different.

---

## Prerequisites

Authenticate and export credentials for the AWS SDK / CLI (the `aws login` cache is not
read by tofu/SDK directly — export it as env vars):

```bash
aws login --profile admin                    # interactive console login (see reference)
eval "$(aws configure export-credentials --profile admin --format env)"
unset AWS_PROFILE
export AWS_REGION=ap-southeast-1
```

Stack identifiers used below (from `tofu output`):

| Resource | Value |
|---|---|
| Source bucket | `cdr-<env>-source` |
| Alarm SNS topic | `arn:aws:sns:ap-southeast-1:<AWS_ACCOUNT_ID>:cdr-alarm-topic` |
| Lambda | `cdr-lambda` |

---

## 1. Subscribe an email to the alarm topic

The pipeline has **two** SNS topics — subscribe to the **alarm** topic (`cdr-alarm-topic`),
not the result topic. The alarm topic carries operational notifications only; you do **not**
get a message per sanitised file.

```bash
aws sns subscribe \
  --topic-arn arn:aws:sns:ap-southeast-1:<AWS_ACCOUNT_ID>:cdr-alarm-topic \
  --protocol email \
  --notification-endpoint you@example.com
# → { "SubscriptionArn": "pending confirmation" }
```

**Confirm the subscription:** AWS emails a *"Subscription Confirmation"* to the address.
Click **Confirm subscription** in that email. Until confirmed, no alarms deliver — this
opt-in cannot be done via the API.

Verify it flipped from pending to a real ARN:

```bash
aws sns list-subscriptions-by-topic \
  --topic-arn arn:aws:sns:ap-southeast-1:<AWS_ACCOUNT_ID>:cdr-alarm-topic \
  --query 'Subscriptions[].{Endpoint:Endpoint,SubscriptionArn:SubscriptionArn}' --output table
# Endpoint = you@example.com, SubscriptionArn = arn:...:cdr-alarm-topic:<uuid>  (not "PendingConfirmation")
```

> **Note:** an email subscription added this way is a live console change, **not** in
> Terraform state. A `tofu destroy` + redeploy would require re-subscribing. To make it
> permanent/IaC-managed, add an `aws_sns_topic_subscription` resource (still needs email
> confirmation on apply).

---

## 2. The six alarms (all route to `cdr-alarm-topic`)

| Alarm | Metric | Namespace | Fires when | Period |
|---|---|---|---|---|
| `cdr-lambda-errors` | `Errors` | `AWS/Lambda` | ≥ 1 | 60 s |
| `cdr-lambda-duration-p99` | `Duration` (p99) | `AWS/Lambda` | > 250,000 ms | 300 s |
| `cdr-lambda-throttles` | `Throttles` | `AWS/Lambda` | ≥ 1 | 60 s |
| `cdr-lambda-dlq-depth` | `ApproximateNumberOfMessagesVisible` | `AWS/SQS` | ≥ 1 | 60 s |
| `cdr-lambda-passthrough` | `PassthroughFiles` | `CDR/Validation` | ≥ 1 | 300 s |
| **`cdr-lambda-zip-anomalies`** | **`ZipAnomalies`** | **`CDR/Validation`** | **≥ 5** | **300 s** |

The ZIP-anomaly alarm is the cleanest one to demo: a burst of structurally-malformed
uploads (zip-bomb / bad-compression / duplicate-entry attempts) is the real-world signal
of an attack campaign, and it is trivially reproducible.

---

## 3. Trigger the ZIP-anomaly alarm

Each malformed-ZIP upload is **hard-rejected** by `_validate_zip_structure`, which calls
`_emit_zip_anomaly_metric()` → `CDR/Validation/ZipAnomalies += 1`. The alarm fires at ≥ 5
within a 5-minute window, so upload **6** malformed ZIPs (from the test corpus):

```bash
SRC=cdr-<env>-source
for i in 1 2 3; do
  aws s3 cp docs/test-corpus/adversarial/duplicate_entry.docx        s3://$SRC/alarm-demo/dup_$i.docx
  aws s3 cp docs/test-corpus/adversarial/nonstandard_compression.docx s3://$SRC/alarm-demo/comp_$i.docx
done
```

(Generate the corpus first if needed: `python docs/fixtures/generate_test_corpus.py`.)

### Confirm the rejections + metric

```bash
# 6 hard-rejects in the logs:
aws logs tail /aws/lambda/cdr-lambda --since 2m --format short | grep -c "ZIP validation failed"
# → 6

# the metric for this 5-min window:
START=$(python3 -c "from datetime import datetime,timezone,timedelta;print((datetime.now(timezone.utc)-timedelta(minutes=8)).strftime('%Y-%m-%dT%H:%M:%SZ'))")
END=$(python3 -c "from datetime import datetime,timezone;print(datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))")
aws cloudwatch get-metric-statistics --namespace CDR/Validation --metric-name ZipAnomalies \
  --start-time $START --end-time $END --period 300 --statistics Sum --query 'Datapoints[].Sum' --output text
# → 6.0
```

---

## 4. Watch the alarm fire

CloudWatch evaluates the 300 s period; the state flips within a couple of minutes.

```bash
for i in $(seq 1 10); do
  STATE=$(aws cloudwatch describe-alarms --alarm-names cdr-lambda-zip-anomalies \
            --query 'MetricAlarms[0].StateValue' --output text)
  echo "$(date +%H:%M:%S)  $STATE"; [ "$STATE" = "ALARM" ] && break; sleep 30
done

aws cloudwatch describe-alarms --alarm-names cdr-lambda-zip-anomalies \
  --query 'MetricAlarms[0].{State:StateValue,Reason:StateReason}' --output json
```

Observed result:

```json
{
  "State": "ALARM",
  "Reason": "Threshold Crossed: 1 datapoint [6.0 (...)] was greater than or equal to the threshold (5.0)."
}
```

At this point an **email lands in the subscribed inbox**, subject roughly:
`ALARM: "cdr-lambda-zip-anomalies" in Asia Pacific (Singapore)`.

### End-to-end chain demonstrated

```
6 malformed ZIPs uploaded
  → CDR Lambda hard-rejects each      (ZIP validation failed)
  → _emit_zip_anomaly_metric()        (CDR/Validation/ZipAnomalies = 6)
  → CloudWatch alarm ≥ 5 / 5 min      (OK → ALARM)
  → SNS cdr-alarm-topic               (fan-out)
  → email to the subscriber
```

---

## 5. Recovery and cleanup

- **Auto-recovery:** with no further anomalies, the alarm returns to `OK` after ~5 minutes
  (you also receive an "OK" email — normal CloudWatch behaviour, demonstrating recovery).
- **The 6 malformed files** are quarantined under `rejected/alarm-demo/` in the quarantine
  bucket; their sources were deleted by the hard-reject path. Remove them when done:

  ```bash
  aws s3 rm s3://cdr-<env>-quarantine/rejected/alarm-demo/ --recursive
  ```

- **Unsubscribe** (if desired):

  ```bash
  aws sns unsubscribe --subscription-arn <the SubscriptionArn from step 1>
  ```

---

## Other alarms — quick demo recipes

| Alarm | How to trigger |
|---|---|
| `cdr-lambda-passthrough` | Upload one file with an unhandled extension (e.g. `docs/test-corpus/adversarial/xss.svg`) — fail-closed routing emits `PassthroughFiles`. Fires at ≥ 1. |
| `cdr-lambda-errors` | Any unhandled CDR error (e.g. a corrupt PDF) increments `Errors`. Fires at ≥ 1. |
| `cdr-lambda-dlq-depth` | Force repeated failures until EventBridge exhausts retries into the DLQ. Slow; not recommended for a live demo. |
| `cdr-lambda-duration-p99` / `throttles` | Require sustained load (see `docs/benchmark.py`); not a quick demo. |

---

## Troubleshooting — "the alarm fired but no email arrived"

First confirm the failure is **not** on the AWS side. SNS reports delivery success even
when the email is later filtered by the recipient, so check these in order:

```bash
# 1. Subscription confirmed (a real ARN, not "PendingConfirmation")?
aws sns list-subscriptions-by-topic --topic-arn <alarm-topic-arn> \
  --query 'Subscriptions[].{Endpoint:Endpoint,Arn:SubscriptionArn}' --output table

# 2. Did the alarm actually transition state? (CloudWatch only emails on OK<->ALARM edges.)
aws cloudwatch describe-alarm-history --alarm-name cdr-lambda-zip-anomalies \
  --history-item-type StateUpdate --max-items 4 \
  --query 'AlarmHistoryItems[].{Time:Timestamp,Summary:HistorySummary}' --output table

# 3. Is the topic an enabled action on the alarm?
aws cloudwatch describe-alarms --alarm-names cdr-lambda-zip-anomalies \
  --query 'MetricAlarms[0].{Actions:AlarmActions,ActionsEnabled:ActionsEnabled}'

# 4. SNS delivery metrics — did SNS hand it off successfully?
aws cloudwatch get-metric-statistics --namespace AWS/SNS \
  --metric-name NumberOfNotificationsFailed \
  --dimensions Name=TopicName,Value=cdr-alarm-topic \
  --start-time <iso> --end-time <iso> --period 3600 --statistics Sum

# 5. Bypass CloudWatch entirely — publish a direct test to the topic:
aws sns publish --topic-arn <alarm-topic-arn> \
  --subject "test" --message "delivery check"
```

If `NumberOfNotificationsDelivered` ≥ 1 and `...Failed` = 0, **the problem is the mailbox,
not AWS** — the message reached the recipient's mail server. Common causes:

- **Junk/Spam filtering.** SNS sends from `no-reply@sns.amazonaws.com`; search that sender
  and allowlist it.
- **First-sender greylisting (observed with iCloud).** A provider may temporarily defer or
  drop the *first* message from a never-before-seen sender. The very first alarm email
  (fired minutes after subscribing) can be lost this way; once any one SNS email reaches
  the inbox, the sender becomes trusted and subsequent alarms deliver normally. A direct
  `sns publish` test is the quickest way to "warm up" the sender and confirm delivery.

### Worked example — what we actually saw

During the first run of this demo the alarm fired but the email never arrived, yet every
AWS-side check was green. The timeline explained it:

| Time | Event |
|---|---|
| ~02:42 | Subscription confirmed (clicked the link in the confirmation email) |
| 02:44:42 | Alarm fired `OK → ALARM`; SNS published the alarm notification |
| 02:50 | A direct `sns publish` test message **arrived in the inbox** ✓ |

Diagnostics at the time:

```
NumberOfNotificationsDelivered: 1.0     # SNS handed it off successfully
NumberOfNotificationsFailed:    0.0     # no SNS-side failure
Alarm history:  Alarm updated from OK to ALARM   (02:44:42)
AlarmActions:   [cdr-alarm-topic]  ActionsEnabled: true
```

So AWS did everything right. The alarm email fired ~2 minutes after the subscription was
confirmed — the **first** message ever sent from `no-reply@sns.amazonaws.com` to that
iCloud inbox — and iCloud greylisted it. The direct test publish a few minutes later
landed cleanly (sender now "known"), confirming the SNS→email chain works end-to-end. No
config change was needed; the issue was self-correcting once one message got through.

**Takeaway for a live demo:** subscribe and then send one `sns publish` "warm-up" message
*before* the demo, so the first real alarm email is guaranteed to deliver.
