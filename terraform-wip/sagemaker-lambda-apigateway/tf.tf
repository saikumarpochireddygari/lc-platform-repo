#############################################
# api_lambda_sagemaker/main.tf
# Flow:
#   API Gateway (HTTP API) -> Lambda -> SageMaker Endpoint
#
# Per-project template using for_each.
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

# Optional VPC settings for Lambda (leave empty for public Lambda)
variable "lambda_subnet_ids" {
  type    = list(string)
  default = []
}

variable "lambda_security_group_ids" {
  type    = list(string)
  default = []
}

variable "lambda_memory_mb" {
  type    = number
  default = 512
}

variable "lambda_timeout_seconds" {
  type    = number
  default = 15
}

# Per project setup
# You must provide:
#  - sagemaker_endpoint_name (created elsewhere)
#  - lambda_zip_path (path to packaged zip on local machine running TF)
variable "projects" {
  type = map(object({
    sagemaker_endpoint_name = string
    lambda_zip_path         = string

    # optional
    api_name         = optional(string)
    route_key        = optional(string, "POST /invocations")
    function_name    = optional(string)
    enable_cors      = optional(bool, true)
    throttling_rps   = optional(number) # optional (not used for HTTP API v2 here)
    stage_name       = optional(string, "live")

    # payload format version for Lambda integration (2.0 recommended)
    payload_format_version = optional(string, "2.0")
  }))
}

#############################################
# IAM for Lambda (invoke SageMaker + logs)
#############################################

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_role" {
  for_each           = var.projects
  name               = "${var.environment}-${each.key}-apism-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "lambda_inline" {
  for_each = var.projects

  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["*"]
  }

  # Invoke SageMaker endpoint
  statement {
    effect = "Allow"
    actions = [
      "sagemaker:InvokeEndpoint",
      "sagemaker:InvokeEndpointAsync"
    ]
    resources = [
      "arn:${data.aws_partition.current.partition}:sagemaker:${var.aws_region}:${data.aws_caller_identity.current.account_id}:endpoint/${each.value.sagemaker_endpoint_name}"
    ]
  }

  # If Lambda is VPC-attached, it needs ENI permissions
  dynamic "statement" {
    for_each = (length(var.lambda_subnet_ids) > 0 && length(var.lambda_security_group_ids) > 0) ? [1] : []
    content {
      effect = "Allow"
      actions = [
        "ec2:CreateNetworkInterface",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DeleteNetworkInterface"
      ]
      resources = ["*"]
    }
  }
}

resource "aws_iam_role_policy" "lambda_policy" {
  for_each = var.projects
  name     = "${var.environment}-${each.key}-apism-lambda-policy"
  role     = aws_iam_role.lambda_role[each.key].id
  policy   = data.aws_iam_policy_document.lambda_inline[each.key].json
}

#############################################
# Lambda Function (per project)
#############################################

# NOTE: Package your lambda code as a zip yourself (e.g., ./lambda/build/<project>.zip)
# The handler should:
#   - accept API Gateway event
#   - call SageMaker runtime InvokeEndpoint
#
# Example handler name expected: app.handler
resource "aws_lambda_function" "invoke_sm" {
  for_each = var.projects

  function_name = coalesce(try(each.value.function_name, null), "${var.environment}-${each.key}-invoke-sm")
  role          = aws_iam_role.lambda_role[each.key].arn
  runtime       = "python3.11"
  handler       = "app.handler"

  filename         = each.value.lambda_zip_path
  source_code_hash = filebase64sha256(each.value.lambda_zip_path)

  memory_size = var.lambda_memory_mb
  timeout     = var.lambda_timeout_seconds

  environment {
    variables = {
      ENV                     = var.environment
      PROJECT                 = each.key
      SAGEMAKER_ENDPOINT_NAME = each.value.sagemaker_endpoint_name
      # If you want to set content-type, your code can read this var:
      SAGEMAKER_CONTENT_TYPE  = "application/json"
      SAGEMAKER_ACCEPT        = "application/json"
    }
  }

  dynamic "vpc_config" {
    for_each = (length(var.lambda_subnet_ids) > 0 && length(var.lambda_security_group_ids) > 0) ? [1] : []
    content {
      subnet_ids         = var.lambda_subnet_ids
      security_group_ids = var.lambda_security_group_ids
    }
  }

  depends_on = [aws_iam_role_policy.lambda_policy]
}

#############################################
# API Gateway HTTP API (per project)
#############################################

resource "aws_apigatewayv2_api" "http_api" {
  for_each = var.projects

  name          = coalesce(try(each.value.api_name, null), "${var.environment}-${each.key}-inference-api")
  protocol_type = "HTTP"

  dynamic "cors_configuration" {
    for_each = try(each.value.enable_cors, true) ? [1] : []
    content {
      allow_origins = ["*"]
      allow_methods = ["POST", "OPTIONS"]
      allow_headers = ["content-type", "authorization", "x-request-id"]
      max_age       = 3600
    }
  }

  tags = {
    env     = var.environment
    project = each.key
  }
}

resource "aws_apigatewayv2_integration" "lambda_proxy" {
  for_each = var.projects

  api_id                 = aws_apigatewayv2_api.http_api[each.key].id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.invoke_sm[each.key].arn
  payload_format_version = try(each.value.payload_format_version, "2.0")
  timeout_milliseconds   = 29000
}

resource "aws_apigatewayv2_route" "route" {
  for_each = var.projects

  api_id    = aws_apigatewayv2_api.http_api[each.key].id
  route_key = try(each.value.route_key, "POST /invocations")
  target    = "integrations/${aws_apigatewayv2_integration.lambda_proxy[each.key].id}"
}

resource "aws_apigatewayv2_stage" "stage" {
  for_each = var.projects

  api_id      = aws_apigatewayv2_api.http_api[each.key].id
  name        = try(each.value.stage_name, "live")
  auto_deploy = true

  tags = {
    env     = var.environment
    project = each.key
  }
}

#############################################
# Permission: API Gateway -> Lambda
#############################################

resource "aws_lambda_permission" "allow_apigw" {
  for_each = var.projects

  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.invoke_sm[each.key].function_name
  principal     = "apigateway.amazonaws.com"

  source_arn = "${aws_apigatewayv2_api.http_api[each.key].execution_arn}/*/*"
}

#############################################
# Outputs
#############################################

output "api_invoke_urls" {
  value = {
    for k, api in aws_apigatewayv2_api.http_api :
    k => "${api.api_endpoint}/${aws_apigatewayv2_stage.stage[k].name}"
  }
}

output "lambda_function_names" {
  value = { for k, fn in aws_lambda_function.invoke_sm : k => fn.function_name }
}