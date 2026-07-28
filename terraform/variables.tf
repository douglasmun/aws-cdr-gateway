variable "aws_region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "resource_prefix" {
  description = "Prefix for the Lambda, IAM role/policy, SNS topics, DLQ, EventBridge rule and alarm names. These are account-and-region-scoped, so two deployments in one region collide unless this differs — and a cdr-* deployment may already exist in the account, managed by another tool. Absence from this state file does not mean unmanaged: check before assuming a name is free. Defaults to the historical names, so existing deployments are unchanged by an upgrade."
  type        = string
  default     = "cdr"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,24}$", var.resource_prefix))
    error_message = "resource_prefix must be 1-25 chars, lowercase alphanumeric or hyphen, starting with alphanumeric."
  }
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

variable "cdr_max_image_pixels" {
  description = "Decompression-bomb pixel cap for cdr_image, sized to lambda_memory_mb."
  type        = number
  default     = 40000000 # 40 MP
}

variable "cdr_max_total_bytes" {
  description = "Aggregate decompression budget across all entries of one package. cdr_max_entry_bytes bounds only a single entry, so many just-under-cap entries otherwise expand without limit (pitfall #46). Kept under lambda_memory_mb."
  type        = number
  default     = 536870912 # 512 MB
}

variable "cdr_max_zip_entries" {
  description = "Maximum ZIP entry count accepted by _validate_zip_structure."
  type        = number
  default     = 20000
}

variable "cdr_max_total_image_pixels" {
  description = "Aggregate pixel budget across all frames of one animated image. cdr_max_image_pixels bounds a single frame; cdr_image materialises every frame at once (pitfall #46)."
  type        = number
  default     = 80000000 # 80 MP
}

variable "cdr_max_image_frames" {
  description = "Maximum frame count accepted for an animated image."
  type        = number
  default     = 2000
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
