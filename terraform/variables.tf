variable "aws_region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "source_bucket_name" {
  description = "Name of the S3 source bucket (where files are uploaded). Created and managed here so EventBridge + encryption are enforced by IaC."
  type        = string
}

variable "sanitised_bucket_name" {
  description = "Name of the S3 destination bucket for clean files."
  type        = string
}

variable "quarantine_bucket_name" {
  description = "Name of the S3 bucket for rejected/errored/unsupported files. Leave empty to disable quarantine (the template deploys cleanly without it)."
  type        = string
  default     = ""
}

variable "cdr_max_file_bytes" {
  description = "Pre-download size limit in bytes; files larger than this are quarantined without CDR."
  type        = number
  default     = 104857600 # 100 MB
}

variable "cdr_max_entry_bytes" {
  description = "Per-ZIP-entry decompression-bomb limit in bytes."
  type        = number
  default     = 209715200 # 200 MB
}

variable "lambda_zip_path" {
  description = "Path to the pre-built Lambda deployment package. Produced by scripts/build.sh (which installs Linux wheels and zips src/*.py)."
  type        = string
  default     = "../build/lambda.zip"
}

variable "lambda_memory_mb" {
  description = "Lambda memory size in MB (image re-encode is memory-bound)."
  type        = number
  default     = 1024
}

variable "lambda_timeout_seconds" {
  description = "Lambda timeout in seconds (pikepdf on large PDFs can be slow)."
  type        = number
  default     = 300
}

variable "lambda_ephemeral_storage_mb" {
  description = "Lambda /tmp ephemeral storage in MB (pikepdf temp files)."
  type        = number
  default     = 1024
}

variable "reserved_concurrent_executions" {
  description = "Reserved concurrency cap (prevents OOM bursts; tune per throughput SLA)."
  type        = number
  default     = 20
}

variable "dlq_retention_seconds" {
  description = "DLQ message retention in seconds (default 14 days)."
  type        = number
  default     = 1209600
}

variable "lambda_architecture" {
  description = "Lambda instruction set. Must match the wheels built by scripts/build.sh (x86_64 → manylinux_2_28_x86_64; arm64 → manylinux_2_28_aarch64)."
  type        = string
  default     = "x86_64"
  validation {
    condition     = contains(["x86_64", "arm64"], var.lambda_architecture)
    error_message = "lambda_architecture must be \"x86_64\" or \"arm64\"."
  }
}

variable "enable_xray_tracing" {
  description = "Enable AWS X-Ray active tracing on the Lambda (adds a small per-invocation cost)."
  type        = bool
  default     = true
}
