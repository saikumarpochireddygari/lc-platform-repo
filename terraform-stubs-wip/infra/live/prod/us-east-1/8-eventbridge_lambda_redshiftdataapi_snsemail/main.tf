terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 5.0" }
    archive = { source = "hashicorp/archive", version = "~> 2.4" }
  }
}

provider "aws" { region = var.aws_region }

resource "aws_sns_topic" "alerts" { name = "${var.env}-redshift-alerts" }

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_iam_role" "lambda" {
  name = "${var.env}-redshift-notifier-lambda"
  assume_role_policy = jsonencode({
    Version="2012-10-17",
    Statement=[{ Effect="Allow", Principal={Service="lambda.amazonaws.com"}, Action="sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "lambda" {
  role = aws_iam_role.lambda.id
  policy = jsonencode({
    Version="2012-10-17",
    Statement=[
      { Effect="Allow", Action=["redshift-data:ExecuteStatement","redshift-data:DescribeStatement","redshift-data:GetStatementResult"], Resource="*" },
      { Effect="Allow", Action=["secretsmanager:GetSecretValue"], Resource=var.redshift_secret_arn },
      { Effect="Allow", Action=["sns:Publish"], Resource=aws_sns_topic.alerts.arn },
      { Effect="Allow", Action=["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"], Resource="*" }
    ]
  })
}

data "archive_file" "zip" {
  type        = "zip"
  source_dir  = "${path.module}/lambda"
  output_path = "${path.module}/lambda.zip"
}

resource "aws_lambda_function" "fn" {
  function_name = "${var.env}-redshift-notifier"
  role          = aws_iam_role.lambda.arn
  runtime       = "python3.11"
  handler       = "handler.lambda_handler"
  timeout       = 60
  memory_size   = 512

  filename         = data.archive_file.zip.output_path
  source_code_hash = data.archive_file.zip.output_base64sha256

  environment {
    variables = {
      WORKGROUP_NAME = var.redshift_workgroup_name
      DATABASE       = var.redshift_database
      SECRET_ARN     = var.redshift_secret_arn
      SQL            = var.sql_query
      SNS_TOPIC_ARN  = aws_sns_topic.alerts.arn
    }
  }
}

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${var.env}-redshift-notifier-schedule"
  schedule_expression = var.schedule_expression
}

resource "aws_cloudwatch_event_target" "target" {
  rule = aws_cloudwatch_event_rule.schedule.name
  arn  = aws_lambda_function.fn.arn
}

resource "aws_lambda_permission" "allow_events" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.fn.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}