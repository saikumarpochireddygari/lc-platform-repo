#############################################
# sagemaker_training_jobs/main.tf
#
# Per-project SageMaker Training Job template (Option A: one job definition per project+env)
# - Creates:
#   * S3 bucket (optional) for training inputs/outputs (per env)
#   * IAM role for SageMaker training
#   * CloudWatch log group
#   * (Optional) ECR repo for your training image
#   * One aws_sagemaker_training_job per project (can be triggered by TF apply)
#
# NOTES
# - This is a skeleton. You still need a training image + entrypoint inside it.
# - If you want jobs created ONLY on-demand (not every apply), move the training_job into a separate module
#   and run it explicitly (or use Airflow/Dagster/Lambda to call CreateTrainingJob).
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

variable "environment" {
  type = string
}

# Reuse one bucket per environment (recommended). Prefix per project inside the bucket.
variable "training_bucket_name" {
  type    = string
  default = "" # if empty, this module creates a bucket: <acct>-<env>-ml-training
}

# Turn on if you want the module to create the bucket
variable "create_training_bucket" {
  type    = bool
  default = true
}

# Per project: training job config
variable "projects" {
  type = map(object({
    # Where your training code runs:
    # Usually an ECR image like: <acct>.dkr.ecr.<region>.amazonaws.com/<repo>:tag
    training_image = string

    # Input data location (S3 prefix or manifest)
    # Example: s3://<bucket>/datasets/iris/v1/train/
    input_s3_uri = string

    # Output prefix inside bucket
    # Example: "outputs/iris_classifier"
    output_prefix = string

    # Optional: where to store model.tar.gz inside output
    # Example: "model"
    output_model_subdir = optional(string, "model")

    # Instance configuration
    instance_type  = optional(string, "ml.m5.large")
    instance_count = optional(number, 1)
    volume_size_gb = optional(number, 30)

    # Training runtime
    max_runtime_seconds = optional(number, 3600)

    # Algorithm / container entry configuration
    # Your image should use these env vars or arguments.
    hyperparameters = optional(map(string), {})

    # Optional: metric definitions (regex) for CW metrics
    metric_definitions = optional(list(object({
      name  = string
      regex = string
    })), [])

    # Optional: enable VPC for training
    subnet_ids         = optional(list(string), [])
    security_group_ids = optional(list(string), [])

    # Optional: job name suffix (TF will still add env+project+timestampish id)
    job_name_prefix = optional(string)

    # Optional: input content type (csv/json/parquet)
    content_type = optional(string, "text/csv")
  }))
}

#############################################
# S3 bucket (one per env)
#############################################

locals {
  default_bucket_name = "${data.aws_caller_identity.current.account_id}-${var.environment}-ml-training"
  bucket_name         = var.training_bucket_name != "" ? var.training_bucket_name : local.default_bucket_name
}

resource "aws_s3_bucket" "training" {
  count  = var.create_training_bucket ? 1 : 0
  bucket = local.bucket_name
}

resource "aws_s3_bucket_versioning" "training" {
  count  = var.create_training_bucket ? 1 : 0
  bucket = aws_s3_bucket.training[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "training" {
  count  = var.create_training_bucket ? 1 : 0
  bucket = aws_s3_bucket.training[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

#############################################
# IAM role for SageMaker training
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

resource "aws_iam_role" "training_role" {
  name               = "${var.environment}-sagemaker-training-role"
  assume_role_policy = data.aws_iam_policy_document.sagemaker_assume.json
}

data "aws_iam_policy_document" "training_policy" {
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
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams"
    ]
    resources = ["*"]
  }

  # If your training image is in ECR private
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

  # VPC training requires ENI permissions
  statement {
    effect = "Allow"
    actions = [
      "ec2:CreateNetworkInterface",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DeleteNetworkInterface",
      "ec2:DescribeSubnets",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeVpcs"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "training_inline" {
  name   = "${var.environment}-sagemaker-training-inline"
  role   = aws_iam_role.training_role.id
  policy = data.aws_iam_policy_document.training_policy.json
}

#############################################
# CloudWatch Log Groups (per project)
#############################################

resource "aws_cloudwatch_log_group" "training" {
  for_each          = var.projects
  name              = "/aws/sagemaker/TrainingJobs/${var.environment}/${each.key}"
  retention_in_days = 14
}

#############################################
# Training Jobs (per project)
#############################################

locals {
  # Ensure S3 output path is stable per env+project; job name must be unique, so we add a short random id.
  output_s3_base = "s3://${local.bucket_name}"
}

resource "random_id" "job" {
  for_each    = var.projects
  byte_length = 4
}

resource "aws_sagemaker_training_job" "job" {
  for_each = var.projects

  name = "${var.environment}-${each.key}-${random_id.job[each.key].hex}"

  role_arn = aws_iam_role.training_role.arn

  algorithm_specification {
    training_image     = each.value.training_image
    training_input_mode = "File"
  }

  output_data_config {
    s3_output_path = "${local.output_s3_base}/${trim(each.value.output_prefix, "/")}/${trim(try(each.value.output_model_subdir, "model"), "/")}"
  }

  resource_config {
    instance_type  = try(each.value.instance_type, "ml.m5.large")
    instance_count = try(each.value.instance_count, 1)
    volume_size_in_gb = try(each.value.volume_size_gb, 30)
  }

  stopping_condition {
    max_runtime_in_seconds = try(each.value.max_runtime_seconds, 3600)
  }

  # One channel input (extend if you need multiple channels: train/validation/test)
  input_data_config {
    channel_name = "train"
    data_source {
      s3_data_source {
        s3_data_type = "S3Prefix"
        s3_uri       = each.value.input_s3_uri
        s3_data_distribution_type = "FullyReplicated"
      }
    }
    content_type = try(each.value.content_type, "text/csv")
  }

  dynamic "hyperparameters" {
    for_each = length(try(each.value.hyperparameters, {})) > 0 ? [1] : []
    content  = each.value.hyperparameters
  }

  dynamic "metric_definitions" {
    for_each = try(each.value.metric_definitions, [])
    content {
      name  = metric_definitions.value.name
      regex = metric_definitions.value.regex
    }
  }

  # Optional VPC config
  dynamic "vpc_config" {
    for_each = (length(try(each.value.subnet_ids, [])) > 0 && length(try(each.value.security_group_ids, [])) > 0) ? [1] : []
    content {
      subnets            = each.value.subnet_ids
      security_group_ids = each.value.security_group_ids
    }
  }

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

  depends_on = [
    aws_iam_role_policy.training_inline,
    aws_cloudwatch_log_group.training
  ]
}

#############################################
# Outputs
#############################################

output "training_job_names" {
  value = { for k, v in aws_sagemaker_training_job.job : k => v.name }
}

output "training_output_s3_paths" {
  value = {
    for k, p in var.projects :
    k => "${local.output_s3_base}/${trim(p.output_prefix, "/")}/${trim(try(p.output_model_subdir, "model"), "/")}"
  }
}

output "training_role_arn" {
  value = aws_iam_role.training_role.arn
}

output "training_bucket_name" {
  value = local.bucket_name
}