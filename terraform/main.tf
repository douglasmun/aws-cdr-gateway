# Terraform port of src/template.yaml (the AWS SAM template). Provisions the general
# CDR Lambda and all its infrastructure: source/sanitised/quarantine buckets, EventBridge
# wiring, DLQ, SNS topics, CloudWatch alarms, and least-privilege IAM.
#
# The Lambda zip is built OUT OF BAND by scripts/build.sh (Linux wheels + src/*.py); this
# config only consumes the resulting artifact via var.lambda_zip_path.

data "aws_caller_identity" "current" {}

locals {
  # Equivalent of the SAM `QuarantineEnabled` condition.
  quarantine_enabled = var.quarantine_bucket_name != ""
}

# ── Source bucket ──────────────────────────────────────────────────────────────
# Managed here so EventBridge notifications + encryption are enforced by IaC. If you
# use a pre-existing bucket, remove this resource and configure EventBridge manually.

resource "aws_s3_bucket" "source" {
  bucket = var.source_bucket_name
}

resource "aws_s3_bucket_server_side_encryption_configuration" "source" {
  bucket = aws_s3_bucket.source.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "source" {
  bucket = aws_s3_bucket.source.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "source" {
  bucket                  = aws_s3_bucket.source.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable EventBridge notifications on the source bucket (the SAM EventBridgeEnabled flag).
resource "aws_s3_bucket_notification" "source" {
  bucket      = aws_s3_bucket.source.id
  eventbridge = true
}

# ── Sanitised bucket ───────────────────────────────────────────────────────────

resource "aws_s3_bucket" "sanitised" {
  bucket = var.sanitised_bucket_name
}

resource "aws_s3_bucket_server_side_encryption_configuration" "sanitised" {
  bucket = aws_s3_bucket.sanitised.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "sanitised" {
  bucket = aws_s3_bucket.sanitised.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "sanitised" {
  bucket                  = aws_s3_bucket.sanitised.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ── Quarantine bucket (gated on quarantine_enabled) ────────────────────────────

resource "aws_s3_bucket" "quarantine" {
  count  = local.quarantine_enabled ? 1 : 0
  bucket = var.quarantine_bucket_name
}

resource "aws_s3_bucket_server_side_encryption_configuration" "quarantine" {
  count  = local.quarantine_enabled ? 1 : 0
  bucket = aws_s3_bucket.quarantine[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Versioning on the quarantine bucket too — it holds rejected/malicious evidence, so
# preserving overwritten/deleted objects matters at least as much as on the other buckets.
resource "aws_s3_bucket_versioning" "quarantine" {
  count  = local.quarantine_enabled ? 1 : 0
  bucket = aws_s3_bucket.quarantine[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "quarantine" {
  count                   = local.quarantine_enabled ? 1 : 0
  bucket                  = aws_s3_bucket.quarantine[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ── TLS-only bucket policies ───────────────────────────────────────────────────
# Deny any request not made over TLS (aws:SecureTransport = false). This is a non-public
# policy, so the public-access-block (block_public_policy) does not interfere with it.
#
# The policy is built inline per resource with jsonencode using that bucket's own arn.
# (A shared for_each data source keyed on the bucket ARNs fails at plan time because the
# ARNs are unknown until apply.)

locals {
  tls_only_statement = {
    Sid       = "DenyInsecureTransport"
    Effect    = "Deny"
    Principal = "*"
    Action    = "s3:*"
    Condition = { Bool = { "aws:SecureTransport" = "false" } }
  }
}

resource "aws_s3_bucket_policy" "source_tls" {
  bucket = aws_s3_bucket.source.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [merge(local.tls_only_statement, {
      Resource = [aws_s3_bucket.source.arn, "${aws_s3_bucket.source.arn}/*"]
    })]
  })
  # Apply after the public-access-block so the two settings don't race.
  depends_on = [aws_s3_bucket_public_access_block.source]
}

resource "aws_s3_bucket_policy" "sanitised_tls" {
  bucket = aws_s3_bucket.sanitised.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [merge(local.tls_only_statement, {
      Resource = [aws_s3_bucket.sanitised.arn, "${aws_s3_bucket.sanitised.arn}/*"]
    })]
  })
  depends_on = [aws_s3_bucket_public_access_block.sanitised]
}

resource "aws_s3_bucket_policy" "quarantine_tls" {
  count  = local.quarantine_enabled ? 1 : 0
  bucket = aws_s3_bucket.quarantine[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [merge(local.tls_only_statement, {
      Resource = [aws_s3_bucket.quarantine[0].arn, "${aws_s3_bucket.quarantine[0].arn}/*"]
    })]
  })
  depends_on = [aws_s3_bucket_public_access_block.quarantine]
}

# ── SNS topics ─────────────────────────────────────────────────────────────────

resource "aws_sns_topic" "result" {
  name = "cdr-result-topic"
  # SSE at rest with the AWS-managed key (free; no CMK to provision).
  kms_master_key_id = "alias/aws/sns"
}

# Separate alarm topic so CloudWatch alarms don't pollute CDR result consumers.
resource "aws_sns_topic" "alarm" {
  name              = "cdr-alarm-topic"
  kms_master_key_id = "alias/aws/sns"
}

# ── Dead-letter queue ──────────────────────────────────────────────────────────

resource "aws_sqs_queue" "dlq" {
  name                      = "cdr-lambda-dlq"
  message_retention_seconds = var.dlq_retention_seconds
  # SSE at rest with the SQS-managed key (free).
  sqs_managed_sse_enabled = true
}

# ── IAM role + least-privilege policy ──────────────────────────────────────────

resource "aws_iam_role" "lambda" {
  name = "cdr-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Managed policy for CloudWatch Logs (the basic execution role).
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "lambda" {
  # Read + delete the source object.
  statement {
    sid       = "SourceReadDelete"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:DeleteObject"]
    resources = ["arn:aws:s3:::${var.source_bucket_name}/*"]
  }

  # Write the sanitised output. PutObjectTagging is required because _upload() sets object
  # tags inline on put_object(Tagging=...) — PutObject alone does not authorise tagging.
  statement {
    sid       = "SanitisedWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:PutObjectTagging"]
    resources = ["arn:aws:s3:::${var.sanitised_bucket_name}/*"]
  }

  # Quarantine write (the copy path is GetObject on source + PutObject on quarantine;
  # GetObject on source is already granted above). Only when quarantine is enabled.
  # PutObjectTagging for the same inline-tag reason as the sanitised write.
  dynamic "statement" {
    for_each = local.quarantine_enabled ? [1] : []
    content {
      sid       = "QuarantineWrite"
      effect    = "Allow"
      actions   = ["s3:PutObject", "s3:PutObjectTagging"]
      resources = ["arn:aws:s3:::${var.quarantine_bucket_name}/*"]
    }
  }

  # Publish CDR result metadata to SNS.
  statement {
    sid       = "PublishResult"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.result.arn]
  }

  # Emit custom metrics, scoped to the CDR/Validation namespace.
  statement {
    sid       = "PutMetricData"
    effect    = "Allow"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["CDR/Validation"]
    }
  }

  # Send failed events to the DLQ.
  statement {
    sid       = "DlqSend"
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]
  }

  # X-Ray trace ingestion (only when tracing is enabled). These actions have no
  # resource-level scoping, so "*" is correct per the AWS X-Ray IAM reference.
  dynamic "statement" {
    for_each = var.enable_xray_tracing ? [1] : []
    content {
      sid       = "XRayTracing"
      effect    = "Allow"
      actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
      resources = ["*"]
    }
  }
}

resource "aws_iam_role_policy" "lambda" {
  name   = "cdr-lambda-policy"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda.json
}

# ── Lambda function ────────────────────────────────────────────────────────────

resource "aws_lambda_function" "cdr" {
  function_name = "cdr-lambda"
  description   = "Strip active content from Office, PDF, and image files"
  role          = aws_iam_role.lambda.arn
  handler       = "lambda_function.handler"
  runtime       = "python3.12"
  # Pinned explicitly (rather than relying on the x86_64 default) so it stays in lockstep
  # with the wheel platform in scripts/build.sh.
  architectures = [var.lambda_architecture]

  filename         = var.lambda_zip_path
  source_code_hash = filebase64sha256(var.lambda_zip_path)

  memory_size                    = var.lambda_memory_mb
  timeout                        = var.lambda_timeout_seconds
  reserved_concurrent_executions = var.reserved_concurrent_executions

  ephemeral_storage {
    size = var.lambda_ephemeral_storage_mb
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  dynamic "tracing_config" {
    for_each = var.enable_xray_tracing ? [1] : []
    content {
      mode = "Active"
    }
  }

  environment {
    variables = {
      SANITISED_BUCKET    = var.sanitised_bucket_name
      QUARANTINE_BUCKET   = local.quarantine_enabled ? var.quarantine_bucket_name : ""
      RESULT_TOPIC_ARN    = aws_sns_topic.result.arn
      CDR_MAX_FILE_BYTES  = tostring(var.cdr_max_file_bytes)
      CDR_MAX_ENTRY_BYTES = tostring(var.cdr_max_entry_bytes)
    }
  }

  depends_on = [aws_iam_role_policy.lambda]
}

# ── EventBridge rule + target ──────────────────────────────────────────────────
# Restricted to PutObject / CompleteMultipartUpload on the source bucket — excludes
# CopyObject events that could otherwise form a processing loop.

resource "aws_cloudwatch_event_rule" "s3_upload" {
  name        = "cdr-s3-object-created"
  description = "Trigger CDR Lambda on object creation in the source bucket"

  event_pattern = jsonencode({
    source        = ["aws.s3"]
    "detail-type" = ["Object Created"]
    detail = {
      bucket = { name = [var.source_bucket_name] }
      reason = ["PutObject", "CompleteMultipartUpload"]
    }
  })
}

resource "aws_cloudwatch_event_target" "cdr" {
  rule      = aws_cloudwatch_event_rule.s3_upload.name
  target_id = "cdr-lambda"
  arn       = aws_lambda_function.cdr.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cdr.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_upload.arn
}

# ── CloudWatch alarms (all route to the alarm topic) ──────────────────────────

resource "aws_cloudwatch_metric_alarm" "errors" {
  alarm_name          = "cdr-lambda-errors"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.cdr.function_name }
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.alarm.arn]
}

resource "aws_cloudwatch_metric_alarm" "duration_p99" {
  alarm_name          = "cdr-lambda-duration-p99"
  namespace           = "AWS/Lambda"
  metric_name         = "Duration"
  dimensions          = { FunctionName = aws_lambda_function.cdr.function_name }
  extended_statistic  = "p99"
  period              = 300
  evaluation_periods  = 1
  threshold           = 250000 # 250 s — alert before the 300 s timeout
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.alarm.arn]
}

resource "aws_cloudwatch_metric_alarm" "throttles" {
  alarm_name          = "cdr-lambda-throttles"
  namespace           = "AWS/Lambda"
  metric_name         = "Throttles"
  dimensions          = { FunctionName = aws_lambda_function.cdr.function_name }
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.alarm.arn]
}

resource "aws_cloudwatch_metric_alarm" "dlq_depth" {
  alarm_name          = "cdr-lambda-dlq-depth"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.dlq.name }
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.alarm.arn]
}

resource "aws_cloudwatch_metric_alarm" "passthrough" {
  alarm_name          = "cdr-lambda-passthrough"
  namespace           = "CDR/Validation"
  metric_name         = "PassthroughFiles"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarm.arn]
}

# Alerts on a spike of ZIP structural anomalies (malformed/zip-bomb/method-mismatch).
# The metric is emitted dimensionless, so no dimensions block here.
resource "aws_cloudwatch_metric_alarm" "zip_anomalies" {
  alarm_name          = "cdr-lambda-zip-anomalies"
  namespace           = "CDR/Validation"
  metric_name         = "ZipAnomalies"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarm.arn]
}
