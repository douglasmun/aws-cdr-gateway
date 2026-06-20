output "cdr_function_arn" {
  description = "ARN of the CDR Lambda function."
  value       = aws_lambda_function.cdr.arn
}

output "cdr_function_name" {
  description = "Name of the CDR Lambda function."
  value       = aws_lambda_function.cdr.function_name
}

output "source_bucket" {
  description = "Source bucket name (upload destination)."
  value       = aws_s3_bucket.source.bucket
}

output "sanitised_bucket" {
  description = "Sanitised bucket name (clean output)."
  value       = aws_s3_bucket.sanitised.bucket
}

output "quarantine_bucket" {
  description = "Quarantine bucket name, or empty if disabled."
  value       = local.quarantine_enabled ? aws_s3_bucket.quarantine[0].bucket : ""
}

output "result_topic_arn" {
  description = "SNS topic carrying CDR result metadata for downstream consumers."
  value       = aws_sns_topic.result.arn
}

output "alarm_topic_arn" {
  description = "SNS topic carrying CloudWatch alarm notifications (subscribe ops here)."
  value       = aws_sns_topic.alarm.arn
}

output "dlq_arn" {
  description = "Dead-letter queue ARN."
  value       = aws_sqs_queue.dlq.arn
}
