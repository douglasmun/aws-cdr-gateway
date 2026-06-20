terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # ── Remote state (recommended for shared/team use) ────────────────────────────
  # Local state is used by default so you can start without prerequisites. To move
  # state to S3 with DynamoDB locking, create the bucket + lock table first, then
  # uncomment this block and run `tofu init -migrate-state`.
  #
  # backend "s3" {
  #   bucket         = "my-terraform-state-bucket"
  #   key            = "aws-cdr-gateway/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "terraform-locks"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "aws-cdr-gateway"
      ManagedBy = "terraform"
    }
  }
}
