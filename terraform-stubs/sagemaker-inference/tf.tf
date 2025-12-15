#############################################
# sagemaker_inference/main.tf
# Per-project SageMaker Real-Time Inference:
#   ECR image + S3 model artifacts -> Model -> EndpointConfig -> Endpoint
#
# Usage idea:
#   projects = {
#     iris = {
#       image_uri              = "123456789012.dkr.ecr.us-east-1.amazonaws.com/iris-infer:latest"
#       model_data_url         = "s3://mlflow-artifacts/iris/models/Production/model.tar.gz"
#       instance_type          = "ml.m5.large"
#       initial_instance_count = 1
#       endpoint_public_name   = "iris"
#     }
#   }
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

# If you want the endpoint in a VPC, set these; otherwise leave null/empty.
variable "vpc_subnet_ids" {
  type    = list(string)
  default = []
}

variable "vpc_security_group_ids" {
  type    = list(string)
  default = []
}

# Optional KMS key for model artifacts / volumes (not required)
variable "kms_key_id" {
  type    = string
  default = null
}

# Per project configuration
variable "projects" {
  type = map(object({
    image_uri              = string
    model_data_url         = string
    instance_type          = string
    initial_instance_count = number

    # optional names
    endpoint_public_name = optional(string) # used to build final endpoint name
    model_name           = optional(string)
    endpoint_name        = optional(string)

    # optional routing/versioning knobs
    variant_name   = optional(string, "AllTraffic")
    model_version  = optional(string) # tag only
    enable_capture = optional(bool, false)

    # optional data capture settings
    capture_s3_uri        = optional(string) # e.g., s3://your-bucket/capture/
    capture_sampling_pct  = optional(number, 5)
    capture_content_types = optional(list(string), ["application/json"])
  }))
}

#############################################
# IAM Role for SageMaker (per project)
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

resource "aws_iam_role" "sagemaker_exec" {
  for_each           = var.projects
  name               = "${var.environment}-${each.key}-sm-exec"
  assume_role_policy = data.aws_iam_policy_document.sagemaker_assume.json
}

data "aws_iam_policy_document" "sagemaker_inline" {
  for_each = var.projects

  # Allow reading model artifacts from S3 (scope down in prod to exact bucket/prefix)
  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:ListBucket"
    ]
    resources = [
      "arn:${data.aws_partition.current.partition}:s3:::*",
      "arn:${data.aws_partition.current.partition}:s3:::*/*"
    ]
  }

  # Allow pulling container from ECR
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

  # CloudWatch Logs
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

  # Optional: data capture to S3 (if enabled)
  dynamic "statement" {
    for_each = try(each.value.enable_capture, false) ? [1] : []
    content {
      effect = "Allow"
      actions = [
        "s3:PutObject",
        "s3:AbortMultipartUpload"
      ]
      resources = [
        "arn:${data.aws_partition.current.partition}:s3:::*/*"
      ]
    }
  }

  # Optional: KMS decrypt if you use KMS on artifacts
  dynamic "statement" {
    for_each = var.kms_key_id != null ? [1] : []
    content {
      effect = "Allow"
      actions = [
        "kms:Decrypt",
        "kms:Encrypt",
        "kms:GenerateDataKey"
      ]
      resources = [var.kms_key_id]
    }
  }
}

resource "aws_iam_role_policy" "sagemaker_policy" {
  for_each = var.projects
  name     = "${var.environment}-${each.key}-sm-policy"
  role     = aws_iam_role.sagemaker_exec[each.key].id
  policy   = data.aws_iam_policy_document.sagemaker_inline[each.key].json
}

#############################################
# SageMaker Model (per project)
#############################################

resource "aws_sagemaker_model" "model" {
  for_each          = var.projects
  name              = coalesce(try(each.value.model_name, null), "${var.environment}-${each.key}-model")
  execution_role_arn = aws_iam_role.sagemaker_exec[each.key].arn

  primary_container {
    image          = each.value.image_uri
    model_data_url = each.value.model_data_url

    environment = {
      ENV           = var.environment
      PROJECT       = each.key
      MODEL_VERSION = coalesce(try(each.value.model_version, null), "na")
    }
  }

  dynamic "vpc_config" {
    for_each = (length(var.vpc_subnet_ids) > 0 && length(var.vpc_security_group_ids) > 0) ? [1] : []
    content {
      subnets            = var.vpc_subnet_ids
      security_group_ids = var.vpc_security_group_ids
    }
  }

  tags = {
    env     = var.environment
    project = each.key
  }

  depends_on = [aws_iam_role_policy.sagemaker_policy]
}

#############################################
# Endpoint Configuration (per project)
#############################################

resource "aws_sagemaker_endpoint_configuration" "cfg" {
  for_each = var.projects
  name     = "${var.environment}-${each.key}-epc"

  production_variants {
    variant_name           = try(each.value.variant_name, "AllTraffic")
    model_name             = aws_sagemaker_model.model[each.key].name
    initial_instance_count = each.value.initial_instance_count
    instance_type          = each.value.instance_type
  }

  # Optional Data Capture
  dynamic "data_capture_config" {
    for_each = try(each.value.enable_capture, false) ? [1] : []
    content {
      enable_capture              = true
      initial_sampling_percentage = try(each.value.capture_sampling_pct, 5)
      destination_s3_uri          = coalesce(try(each.value.capture_s3_uri, null), "s3://CHANGE_ME_CAPTURE_BUCKET/${var.environment}/${each.key}/")

      capture_options {
        capture_mode = "Input"
      }
      capture_options {
        capture_mode = "Output"
      }

      dynamic "capture_content_type_header" {
        for_each = [1]
        content {
          json_content_types = try(each.value.capture_content_types, ["application/json"])
        }
      }
    }
  }

  dynamic "kms_key_arn" {
    for_each = var.kms_key_id != null ? [1] : []
    content  = var.kms_key_id
  }

  tags = {
    env     = var.environment
    project = each.key
  }
}

#############################################
# Endpoint (per project)
#############################################

resource "aws_sagemaker_endpoint" "endpoint" {
  for_each = var.projects

  name = coalesce(
    try(each.value.endpoint_name, null),
    "${var.environment}-${coalesce(try(each.value.endpoint_public_name, null), each.key)}"
  )

  endpoint_config_name = aws_sagemaker_endpoint_configuration.cfg[each.key].name

  tags = {
    env     = var.environment
    project = each.key
  }
}

#############################################
# Outputs
#############################################

output "endpoint_names" {
  value = { for k, v in aws_sagemaker_endpoint.endpoint : k => v.name }
}

output "model_names" {
  value = { for k, v in aws_sagemaker_model.model : k => v.name }
}