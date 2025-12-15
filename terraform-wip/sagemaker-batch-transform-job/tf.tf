#############################################
# sagemaker_batch_transform/main.tf
#
# Per-project SageMaker Batch Transform template
# - Creates:
#   * IAM role for Batch Transform
#   * (Optional) S3 bucket for inputs/outputs
#   * SageMaker Model (container + model data)
#   * One Batch Transform Job per project (created on apply)
#
# NOTES
# - Batch Transform requires a SageMaker Model.
# - The model "primary_container.image" must be in ECR (or otherwise accessible).
# - model_data_url must point to your model artifact in S3 (e.g., output of training job).
#############################################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

#############################################
# Inputs
#############################################

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "environment" {
  type = string
}

# Reuse one bucket per env, store per-project prefixes inside.
variable "data_bucket_name" {
  type    = string
  default = "" # if empty, module creates <acct>-<env>-ml-batch
}

variable "create_data_bucket" {
  type    = bool
  default = true
}

# Per project config
variable "projects" {
  type = map(object({
    # Model container
    inference_image = string

    # Model artifact tar.gz in S3
    # Example: s3://<bucket>/outputs/<project>/model/model.tar.gz
    model_data_s3_uri = string

    # Batch input prefix/object in S3
    # Example: s3://<bucket>/batch_inputs/<project>/input.csv
    input_s3_uri = string

    # Output prefix in S3 bucket
    # Example: "batch_outputs/<project>"
    output_prefix = string

    # Transform instance config
    instance_type  = optional(string, "ml.m5.large")
    instance_count = optional(number, 1)

    # Payload settings
    max_concurrent_transforms = optional(number, 4)
    max_payload_mb            = optional(number, 6)

    # Data format (Text/CSV/JSONLines)
    input_content_type  = optional(string, "text/csv")
    output_accept       = optional(string, "text/csv")
    split_type          = optional(string, "Line") # Line | RecordIO | TFRecord | None

    # Optional environment variables for container
    container_env = optional(map(string), {})

    # Optional tags
    tags = optional(map(string), {})
  }))
}

#############################################
# S3 bucket (one per env)
#############################################

locals {
  default_bucket_name = "${data.aws_caller_identity.current.account_id}-${var.environment}-ml-batch"
  bucket_name         = var.data_bucket_name != "" ? var.data_bucket_name : local.default_bucket_name
}

resource "aws_s3_bucket" "data" {
  count  = var.create_data_bucket ? 1 : 0
  bucket = local.bucket_name
}

resource "aws_s3_bucket_versioning" "data" {
  count  = var.create_data_bucket ? 1 : 0
  bucket = aws_s3_bucket.data[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  count  = var.create_data_bucket ? 1 : 0
  bucket = aws_s3_bucket.data[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

#############################################
# IAM role for SageMaker Batch Transform
#############################################

data "aws_iam_policy_document" "sagemaker_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["sagemaker.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "sagemaker_role" {
  name               = "${var.environment}-sagemaker-batch-role"
  assume_role_policy = data.aws_iam_policy_document.sagemaker_assume.json
}

data "aws_iam_policy_document" "sagemaker_policy" {
  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:ListBucket"
    ]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:AbortMultipartUpload"
    ]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "ecr:GetAuthorizationToken",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchCheckLayerAvailability"
    ]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "sagemaker_inline" {
  name   = "${var.environment}-sagemaker-batch-inline"
  role   = aws_iam_role.sagemaker_role.id
  policy = data.aws_iam_policy_document.sagemaker_policy.json
}

#############################################
# SageMaker Model (per project)
#############################################

resource "aws_sagemaker_model" "model" {
  for_each = var.projects

  name               = "${var.environment}-${each.key}-batch-model"
  execution_role_arn  = aws_iam_role.sagemaker_role.arn

  primary_container {
    image          = each.value.inference_image
    model_data_url = each.value.model_data_s3_uri

    dynamic "environment" {
      for_each = length(try(each.value.container_env, {})) > 0 ? [1] : []
      content  = each.value.container_env
    }
  }

  tags = merge(
    {
      env     = var.environment
      project = each.key
      type    = "batch-transform-model"
    },
    try(each.value.tags, {})
  )
}

#############################################
# Batch Transform Job (per project)
#############################################

resource "random_id" "xform" {
  for_each    = var.projects
  byte_length = 4
}

resource "aws_sagemaker_transform_job" "job" {
  for_each = var.projects

  transform_job_name = "${var.environment}-${each.key}-xform-${random_id.xform[each.key].hex}"
  model_name         = aws_sagemaker_model.model[each.key].name

  transform_input {
    data_source {
      s3_data_source {
        s3_data_type = "S3Prefix"
        s3_uri       = each.value.input_s3_uri
      }
    }
    content_type = try(each.value.input_content_type, "text/csv")
    split_type   = try(each.value.split_type, "Line")
  }

  transform_output {
    s3_output_path = "s3://${local.bucket_name}/${trim(each.value.output_prefix, "/")}"
    accept         = try(each.value.output_accept, "text/csv")
  }

  transform_resources {
    instance_type  = try(each.value.instance_type, "ml.m5.large")
    instance_count = try(each.value.instance_count, 1)
  }

  max_concurrent_transforms = try(each.value.max_concurrent_transforms, 4)
  max_payload_in_mb         = try(each.value.max_payload_mb, 6)

  tags = [
    {
      key   = "env"
      value = var.environment
    },
    {
      key   = "project"
      value = each.key
    }
  ]

  depends_on = [aws_iam_role_policy.sagemaker_inline]
}

#############################################
# Outputs
#############################################

output "sagemaker_model_names" {
  value = { for k, v in aws_sagemaker_model.model : k => v.name }
}

output "transform_job_names" {
  value = { for k, v in aws_sagemaker_transform_job.job : k => v.transform_job_name }
}

output "data_bucket_name" {
  value = local.bucket_name
}

output "sagemaker_role_arn" {
  value = aws_iam_role.sagemaker_role.arn
}