#############################################
# online_telemetry/main.tf
# Option A: 1 Firehose per project per env
# EKS/apps -> Firehose (PutRecord/PutRecordBatch) -> Lambda transform -> S3 -> Redshift COPY (via Firehose)
#############################################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

#############################################
# Inputs
#############################################

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

# e.g., dev / stage / prod
variable "environment" {
  type = string
}

# Map of projects. Each project gets its own Firehose stream.
# Example tfvars:
# projects = {
#   iris = { redshift_table = "telemetry_iris", s3_prefix = "iris/" }
#   churn = { redshift_table = "telemetry_churn", s3_prefix = "churn/" }
# }
variable "projects" {
  type = map(object({
    redshift_table = string
    s3_prefix      = optional(string)
  }))
}

# Shared S3 bucket for telemetry per environment (recommended).
# Firehose will write to s3://bucket/<environment>/<project>/...
variable "telemetry_bucket_name" {
  type = string
}

# Redshift info (assumes cluster already exists).
# You can swap to an aws_redshiftserverless_* setup later.
variable "redshift_jdbc_url" {
  type        = string
  description = "JDBC URL like: jdbc:redshift://<endpoint>:5439/<db>"
}

variable "redshift_username" {
  type      = string
  sensitive = true
}

variable "redshift_password" {
  type      = string
  sensitive = true
}

# IAM role ARN that Redshift uses for COPY from S3 (must be attached in Redshift)
# If you don't have one yet, you can create it separately and pass here.
variable "redshift_copy_role_arn" {
  type        = string
  description = "IAM role ARN that Redshift uses to COPY from S3"
}

# Lambda transform package you build and provide (zip).
# Handler must be transform.lambda_handler (or adjust below).
variable "lambda_zip_path" {
  type        = string
  description = "Path to a pre-built Lambda zip (e.g., lambda/build/transform.zip)"
}

variable "lambda_memory_mb" {
  type    = number
  default = 256
}

variable "lambda_timeout_seconds" {
  type    = number
  default = 60
}

# Optional: Restrict who can PUT records into Firehose (e.g., EKS node role(s) / IRSA role(s)).
# If empty, no resource policy is attached (apps must still have IAM permissions).
variable "producer_principal_arns" {
  type    = list(string)
  default = []
}

#############################################
# Locals
#############################################

locals {
  account_id   = data.aws_caller_identity.current.account_id
  env          = var.environment
  bucket_arn   = "arn:${data.aws_partition.current.partition}:s3:::${var.telemetry_bucket_name}"
  bucket_arn_wildcard = "arn:${data.aws_partition.current.partition}:s3:::${var.telemetry_bucket_name}/*"
}

#############################################
# S3 bucket (shared per env)
#############################################

resource "aws_s3_bucket" "telemetry" {
  bucket = var.telemetry_bucket_name
}

resource "aws_s3_bucket_versioning" "telemetry" {
  bucket = aws_s3_bucket.telemetry.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "telemetry" {
  bucket                  = aws_s3_bucket.telemetry.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

#############################################
# CloudWatch log groups
#############################################

resource "aws_cloudwatch_log_group" "firehose" {
  for_each          = var.projects
  name              = "/aws/kinesisfirehose/${local.env}-${each.key}-telemetry"
  retention_in_days = 14
}

resource "aws_cloudwatch_log_group" "lambda" {
  for_each          = var.projects
  name              = "/aws/lambda/${local.env}-${each.key}-telemetry-transform"
  retention_in_days = 14
}

#############################################
# Lambda transform (one per project)
#############################################

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    effect = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_exec" {
  for_each           = var.projects
  name               = "${local.env}-${each.key}-telemetry-lambda-exec"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  for_each   = var.projects
  role       = aws_iam_role.lambda_exec[each.key].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function" "transform" {
  for_each         = var.projects
  function_name    = "${local.env}-${each.key}-telemetry-transform"
  role             = aws_iam_role.lambda_exec[each.key].arn
  runtime          = "python3.11"
  handler          = "transform.lambda_handler"
  filename         = var.lambda_zip_path
  source_code_hash = filebase64sha256(var.lambda_zip_path)
  memory_size      = var.lambda_memory_mb
  timeout          = var.lambda_timeout_seconds

  environment {
    variables = {
      ENV          = local.env
      PROJECT      = each.key
      OUTPUT_FORMAT = "jsonl"
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda
  ]
}

#############################################
# Firehose IAM role (one per project)
#############################################

data "aws_iam_policy_document" "firehose_assume" {
  statement {
    effect = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["firehose.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "firehose_role" {
  for_each           = var.projects
  name               = "${local.env}-${each.key}-telemetry-firehose-role"
  assume_role_policy = data.aws_iam_policy_document.firehose_assume.json
}

data "aws_iam_policy_document" "firehose_policy" {
  for_each = var.projects

  # Write to S3 (primary + backup prefixes)
  statement {
    effect = "Allow"
    actions = [
      "s3:AbortMultipartUpload",
      "s3:GetBucketLocation",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:ListBucketMultipartUploads",
      "s3:PutObject"
    ]
    resources = [
      local.bucket_arn,
      local.bucket_arn_wildcard
    ]
  }

  # Invoke Lambda processor
  statement {
    effect = "Allow"
    actions = [
      "lambda:InvokeFunction",
      "lambda:GetFunctionConfiguration"
    ]
    resources = [
      aws_lambda_function.transform[each.key].arn,
      "${aws_lambda_function.transform[each.key].arn}:*"
    ]
  }

  # CloudWatch Logs
  statement {
    effect = "Allow"
    actions = [
      "logs:PutLogEvents"
    ]
    resources = [
      "${aws_cloudwatch_log_group.firehose[each.key].arn}:*"
    ]
  }

  # Redshift COPY via Firehose (Firehose talks to Redshift using credentials + role_arn below)
  statement {
    effect = "Allow"
    actions = [
      "redshift:DescribeClusters",
      "redshift:GetClusterCredentials"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "firehose_inline" {
  for_each = var.projects
  name     = "${local.env}-${each.key}-telemetry-firehose-policy"
  role     = aws_iam_role.firehose_role[each.key].id
  policy   = data.aws_iam_policy_document.firehose_policy[each.key].json
}

#############################################
# Optional: Firehose resource policy to limit producers
# (Apps still need IAM permissions to PutRecord/PutRecordBatch.)
#############################################

data "aws_iam_policy_document" "firehose_resource_policy" {
  for_each = length(var.producer_principal_arns) > 0 ? var.projects : {}

  statement {
    sid     = "AllowProducersPut"
    effect  = "Allow"
    actions = ["firehose:PutRecord", "firehose:PutRecordBatch"]
    resources = [
      "arn:${data.aws_partition.current.partition}:firehose:${var.aws_region}:${local.account_id}:deliverystream/${local.env}-${each.key}-telemetry"
    ]
    principals {
      type        = "AWS"
      identifiers = var.producer_principal_arns
    }
  }
}

# NOTE: Terraform support for Firehose resource policies is limited;
# many teams enforce producer access via IAM attached to workloads (IRSA roles) instead.
# If you use a central IAM pattern, you can omit this block entirely.

#############################################
# Firehose delivery streams (one per project)
#############################################

resource "aws_kinesis_firehose_delivery_stream" "telemetry" {
  for_each    = var.projects
  name        = "${local.env}-${each.key}-telemetry"
  destination = "redshift"

  redshift_configuration {
    role_arn           = aws_iam_role.firehose_role[each.key].arn
    cluster_jdbcurl    = var.redshift_jdbc_url
    username           = var.redshift_username
    password           = var.redshift_password
    data_table_name    = each.value.redshift_table

    # COPY options tuned for JSONL (adjust to your transform output)
    # Example if you output JSON: "json 'auto' timeformat 'auto' gzip"
    copy_options       = "json 'auto' timeformat 'auto'"

    s3_backup_mode     = "Enabled"

    # Firehose stages to S3 before COPY to Redshift
    s3_configuration {
      role_arn           = aws_iam_role.firehose_role[each.key].arn
      bucket_arn         = aws_s3_bucket.telemetry.arn
      prefix             = "${local.env}/${each.key}/${try(each.value.s3_prefix, "")}raw/"

      buffering_size     = 5
      buffering_interval = 60

      compression_format = "GZIP"

      cloudwatch_logging_options {
        enabled         = true
        log_group_name  = aws_cloudwatch_log_group.firehose[each.key].name
        log_stream_name = "S3Delivery"
      }
    }

    # Backup all records (including failed transforms/COPY failures)
    s3_backup_configuration {
      role_arn           = aws_iam_role.firehose_role[each.key].arn
      bucket_arn         = aws_s3_bucket.telemetry.arn
      prefix             = "${local.env}/${each.key}/${try(each.value.s3_prefix, "")}backup/"

      buffering_size     = 5
      buffering_interval = 60

      compression_format = "GZIP"

      cloudwatch_logging_options {
        enabled         = true
        log_group_name  = aws_cloudwatch_log_group.firehose[each.key].name
        log_stream_name = "S3Backup"
      }
    }

    processing_configuration {
      enabled = true

      processors {
        type = "Lambda"

        parameters {
          parameter_name  = "LambdaArn"
          parameter_value = aws_lambda_function.transform[each.key].arn
        }

        # Retry buffer for transform failures
        parameters {
          parameter_name  = "NumberOfRetries"
          parameter_value = "3"
        }
      }
    }

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.firehose[each.key].name
      log_stream_name = "RedshiftDelivery"
    }
  }

  depends_on = [
    aws_iam_role_policy.firehose_inline,
    aws_s3_bucket_public_access_block.telemetry
  ]
}

#############################################
# Outputs
#############################################

output "firehose_stream_names" {
  value = { for k, v in aws_kinesis_firehose_delivery_stream.telemetry : k => v.name }
}

output "telemetry_bucket" {
  value = aws_s3_bucket.telemetry.bucket
}

output "lambda_transform_names" {
  value = { for k, v in aws_lambda_function.transform : k => v.function_name }
}