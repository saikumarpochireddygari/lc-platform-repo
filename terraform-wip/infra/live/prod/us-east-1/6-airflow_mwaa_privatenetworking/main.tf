terraform {
  required_version = ">= 1.6.0"
  required_providers { aws = { source = "hashicorp/aws", version = "~> 5.0" } }
}

provider "aws" { region = var.aws_region }

variable "aws_region" { type = string, default = "us-east-1" }
variable "env"        { type = string, default = "prod" }

data "terraform_remote_state" "foundation" {
  backend = "s3"
  config = {
    bucket = "REPLACE_ME_TFSTATE_BUCKET"
    key    = "prod/us-east-1/foundation/terraform.tfstate"
    region = "us-east-1"
  }
}

data "aws_caller_identity" "me" {}

resource "aws_s3_bucket" "mwaa" {
  bucket = "${var.env}-mwaa-${data.aws_caller_identity.me.account_id}"
}

resource "aws_s3_bucket_public_access_block" "mwaa" {
  bucket                  = aws_s3_bucket.mwaa.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_iam_role" "mwaa" {
  name               = "${var.env}-mwaa-execution"
  assume_role_policy = jsonencode({
    Version="2012-10-17",
    Statement=[{
      Effect="Allow",
      Principal={ Service=["airflow.amazonaws.com","airflow-env.amazonaws.com"] },
      Action="sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "mwaa" {
  role = aws_iam_role.mwaa.id
  policy = jsonencode({
    Version="2012-10-17",
    Statement=[
      { Effect="Allow", Action=["s3:*"], Resource=[aws_s3_bucket.mwaa.arn, "${aws_s3_bucket.mwaa.arn}/*"] },
      { Effect="Allow", Action=["logs:*","cloudwatch:PutMetricData"], Resource="*" }
    ]
  })
}

resource "aws_security_group" "mwaa" {
  name   = "${var.env}-mwaa-sg"
  vpc_id = data.terraform_remote_state.foundation.outputs.vpc_id
  egress { from_port=0, to_port=0, protocol="-1", cidr_blocks=["0.0.0.0/0"] }
}

resource "aws_mwaa_environment" "this" {
  name              = "${var.env}-airflow"
  airflow_version   = "2.9.2"
  environment_class = "mw1.medium"

  execution_role_arn = aws_iam_role.mwaa.arn

  source_bucket_arn     = aws_s3_bucket.mwaa.arn
  dag_s3_path           = "dags"
  requirements_s3_path  = "requirements/requirements.txt"

  network_configuration {
    subnet_ids         = data.terraform_remote_state.foundation.outputs.private_subnet_ids
    security_group_ids = [aws_security_group.mwaa.id]
  }

  logging_configuration {
    dag_processing_logs { enabled=true, log_level="INFO" }
    scheduler_logs      { enabled=true, log_level="INFO" }
    task_logs           { enabled=true, log_level="INFO" }
    webserver_logs      { enabled=true, log_level="INFO" }
    worker_logs         { enabled=true, log_level="INFO" }
  }
}

output "mwaa_bucket" { value = aws_s3_bucket.mwaa.bucket }