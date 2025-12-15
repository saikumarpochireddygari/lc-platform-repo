#############################################
# online_drift_alerting/main.tf
# Per-project scheduled drift check:
# EventBridge schedule -> Lambda (runs Redshift query) -> SNS (email)
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

# Example:
# projects = {
#   iris = {
#     schedule_expression = "rate(15 minutes)"
#     alert_email         = "ml-ops-iris@example.com"
#     redshift_sql        = "select case when max(drift_score) > 0.8 then 1 else 0 end as alert, max(drift_score) as score from telemetry_iris_drift where ts > dateadd(minute,-30,getdate());"
#   }
# }
variable "projects" {
  type = map(object({
    schedule_expression = string   # e.g., "rate(15 minutes)" or "cron(0/15 * * * ? *)"
    alert_email         = string
    redshift_sql        = string   # SQL should return at least: alert (0/1) and optionally score/message
  }))
}

# Redshift access via Redshift Data API (recommended for Lambda)
# For provisioned Redshift use cluster_identifier + database + db_user OR Secrets Manager
# For serverless use workgroup_name + database + secret_arn (preferred)

variable "redshift_database" {
  type = string
}

# One of these must be set depending on your Redshift type.
variable "redshift_cluster_identifier" {
  type    = string
  default = null
}

variable "redshift_workgroup_name" {
  type    = string
  default = null
}

# Preferred: use Secrets Manager for credentials (works with Data API)
variable "redshift_secret_arn" {
  type    = string
  default = null
}

# Optional (if you don’t use secret_arn; less ideal)
variable "redshift_db_user" {
  type    = string
  default = null
}

# Lambda code package zip you build and provide.
# Handler must be drift_check.lambda_handler (or adjust below).
variable "lambda_zip_path" {
  type        = string
  description = "Path to a pre-built Lambda zip (e.g., lambda/build/drift_check.zip)"
}

variable "lambda_memory_mb" {
  type    = number
  default = 256
}

variable "lambda_timeout_seconds" {
  type    = number
  default = 60
}

#############################################
# SNS (topic + email subscription) per project
#############################################

resource "aws_sns_topic" "drift_alerts" {
  for_each = var.projects
  name     = "${var.environment}-${each.key}-drift-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  for_each  = var.projects
  topic_arn = aws_sns_topic.drift_alerts[each.key].arn
  protocol  = "email"
  endpoint  = each.value.alert_email
}

#############################################
# Lambda execution role (per project)
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

resource "aws_iam_role" "lambda_exec" {
  for_each           = var.projects
  name               = "${var.environment}-${each.key}-driftcheck-lambda-exec"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  for_each   = var.projects
  role       = aws_iam_role.lambda_exec[each.key].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "lambda_inline" {
  for_each = var.projects

  # Redshift Data API
  statement {
    effect = "Allow"
    actions = [
      "redshift-data:ExecuteStatement",
      "redshift-data:DescribeStatement",
      "redshift-data:GetStatementResult",
      "redshift-data:CancelStatement"
    ]
    resources = ["*"]
  }

  # If using Secrets Manager for Redshift creds
  dynamic "statement" {
    for_each = var.redshift_secret_arn != null ? [1] : []
    content {
      effect    = "Allow"
      actions   = ["secretsmanager:GetSecretValue"]
      resources = [var.redshift_secret_arn]
    }
  }

  # Publish to SNS
  statement {
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.drift_alerts[each.key].arn]
  }
}

resource "aws_iam_role_policy" "lambda_policy" {
  for_each = var.projects
  name     = "${var.environment}-${each.key}-driftcheck-policy"
  role     = aws_iam_role.lambda_exec[each.key].id
  policy   = data.aws_iam_policy_document.lambda_inline[each.key].json
}

#############################################
# Lambda function (per project)
#############################################

resource "aws_lambda_function" "drift_check" {
  for_each         = var.projects
  function_name    = "${var.environment}-${each.key}-drift-check"
  role             = aws_iam_role.lambda_exec[each.key].arn
  runtime          = "python3.11"
  handler          = "drift_check.lambda_handler"
  filename         = var.lambda_zip_path
  source_code_hash = filebase64sha256(var.lambda_zip_path)
  memory_size      = var.lambda_memory_mb
  timeout          = var.lambda_timeout_seconds

  environment {
    variables = {
      ENV         = var.environment
      PROJECT     = each.key
      SQL         = each.value.redshift_sql
      SNS_TOPIC   = aws_sns_topic.drift_alerts[each.key].arn
      DATABASE    = var.redshift_database

      # Data API target selection
      CLUSTER_ID  = var.redshift_cluster_identifier != null ? var.redshift_cluster_identifier : ""
      WORKGROUP   = var.redshift_workgroup_name != null ? var.redshift_workgroup_name : ""
      SECRET_ARN  = var.redshift_secret_arn != null ? var.redshift_secret_arn : ""
      DB_USER     = var.redshift_db_user != null ? var.redshift_db_user : ""

      # Simple thresholding inside Lambda is also possible:
      # DRIFT_THRESHOLD = "0.8"
    }
  }

  depends_on = [
    aws_iam_role_policy.lambda_policy
  ]
}

#############################################
# EventBridge schedule (rule + target) per project
#############################################

resource "aws_cloudwatch_event_rule" "schedule" {
  for_each            = var.projects
  name                = "${var.environment}-${each.key}-drift-schedule"
  schedule_expression = each.value.schedule_expression
}

resource "aws_cloudwatch_event_target" "lambda" {
  for_each = var.projects
  rule     = aws_cloudwatch_event_rule.schedule[each.key].name
  arn      = aws_lambda_function.drift_check[each.key].arn

  input = jsonencode({
    env     = var.environment
    project = each.key
  })
}

resource "aws_lambda_permission" "allow_eventbridge" {
  for_each      = var.projects
  statement_id  = "AllowExecutionFromEventBridge-${var.environment}-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.drift_check[each.key].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule[each.key].arn
}

#############################################
# Outputs
#############################################

output "drift_lambda_names" {
  value = { for k, v in aws_lambda_function.drift_check : k => v.function_name }
}

output "sns_topic_arns" {
  value = { for k, v in aws_sns_topic.drift_alerts : k => v.arn }
}

output "eventbridge_rules" {
  value = { for k, v in aws_cloudwatch_event_rule.schedule : k => v.name }
}