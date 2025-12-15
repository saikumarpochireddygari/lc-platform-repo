terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 5.0" }
    archive = { source = "hashicorp/archive", version = "~> 2.4" }
  }
}

provider "aws" { region = var.aws_region }

data "terraform_remote_state" "foundation" {
  backend = "s3"
  config = {
    bucket = "REPLACE_ME_TFSTATE_BUCKET"
    key    = "prod/us-east-1/foundation/terraform.tfstate"
    region = "us-east-1"
  }
}

# --- VPC Endpoint for execute-api (PRIVATE API Gateway) ---
resource "aws_security_group" "execute_api_vpce" {
  name   = "${var.env}-execute-api-vpce"
  vpc_id = data.terraform_remote_state.foundation.outputs.vpc_id
  ingress { from_port=443, to_port=443, protocol="tcp", cidr_blocks=[data.terraform_remote_state.foundation.outputs.vpc_cidr] }
  egress  { from_port=0, to_port=0, protocol="-1", cidr_blocks=["0.0.0.0/0"] }
}

resource "aws_vpc_endpoint" "execute_api" {
  vpc_id              = data.terraform_remote_state.foundation.outputs.vpc_id
  service_name        = "com.amazonaws.${var.aws_region}.execute-api"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = data.terraform_remote_state.foundation.outputs.private_subnet_ids
  security_group_ids  = [aws_security_group.execute_api_vpce.id]
  private_dns_enabled = true
}

# --- SageMaker model/endpoint ---
resource "aws_iam_role" "sagemaker_exec" {
  name = "${var.env}-sagemaker-exec"
  assume_role_policy = jsonencode({
    Version="2012-10-17",
    Statement=[{ Effect="Allow", Principal={Service="sagemaker.amazonaws.com"}, Action="sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "sagemaker_basic" {
  role      = aws_iam_role.sagemaker_exec.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
}

resource "aws_sagemaker_model" "this" {
  name               = "${var.env}-model"
  execution_role_arn = aws_iam_role.sagemaker_exec.arn
  primary_container { image = var.inference_ecr_image }
}

resource "aws_sagemaker_endpoint_configuration" "this" {
  name = "${var.env}-endpoint-config"
  production_variants {
    variant_name           = "AllTraffic"
    model_name             = aws_sagemaker_model.this.name
    initial_instance_count = 2
    instance_type          = "ml.m5.large"
  }
}

resource "aws_sagemaker_endpoint" "this" {
  name                 = "${var.env}-endpoint"
  endpoint_config_name = aws_sagemaker_endpoint_configuration.this.name
}

# --- Lambda (invoke endpoint) ---
resource "aws_iam_role" "lambda" {
  name = "${var.env}-invoke-sagemaker-lambda"
  assume_role_policy = jsonencode({
    Version="2012-10-17",
    Statement=[{ Effect="Allow", Principal={Service="lambda.amazonaws.com"}, Action="sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  role = aws_iam_role.lambda.id
  policy = jsonencode({
    Version="2012-10-17",
    Statement=[
      { Effect="Allow", Action=["sagemaker:InvokeEndpoint"], Resource=aws_sagemaker_endpoint.this.arn },
      { Effect="Allow", Action=["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"], Resource="*" }
    ]
  })
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/lambda"
  output_path = "${path.module}/lambda.zip"
}

resource "aws_lambda_function" "invoke" {
  function_name = "${var.env}-invoke-sagemaker"
  role          = aws_iam_role.lambda.arn
  runtime       = "python3.11"
  handler       = "handler.lambda_handler"
  timeout       = 30
  memory_size   = 512

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = { ENDPOINT_NAME = aws_sagemaker_endpoint.this.name }
  }
}

# --- Private REST API Gateway ---
resource "aws_api_gateway_rest_api" "api" {
  name = "${var.env}-${var.api_name}"

  endpoint_configuration {
    types            = ["PRIVATE"]
    vpc_endpoint_ids = [aws_vpc_endpoint.execute_api.id]
  }

  policy = jsonencode({
    Version="2012-10-17",
    Statement=[
      {
        Effect="Allow",
        Principal="*",
        Action="execute-api:Invoke",
        Resource="execute-api:/*"
      },
      {
        Effect="Deny",
        Principal="*",
        Action="execute-api:Invoke",
        Resource="execute-api:/*",
        Condition={ StringNotEquals={ "aws:SourceVpce"=aws_vpc_endpoint.execute_api.id } }
      }
    ]
  })
}

resource "aws_api_gateway_resource" "infer" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  parent_id   = aws_api_gateway_rest_api.api.root_resource_id
  path_part   = "infer"
}

resource "aws_api_gateway_method" "post" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  resource_id   = aws_api_gateway_resource.infer.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "lambda" {
  rest_api_id             = aws_api_gateway_rest_api.api.id
  resource_id             = aws_api_gateway_resource.infer.id
  http_method             = aws_api_gateway_method.post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.invoke.invoke_arn
}

resource "aws_api_gateway_deployment" "deploy" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  triggers = { redeploy = sha1(jsonencode([aws_api_gateway_integration.lambda.id])) }
  depends_on = [aws_api_gateway_integration.lambda]
}

resource "aws_api_gateway_stage" "prod" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  deployment_id = aws_api_gateway_deployment.deploy.id
  stage_name    = "prod"
}

resource "aws_lambda_permission" "allow_apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.invoke.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.api.execution_arn}/*/*"
}

output "private_api_invoke_arn" { value = aws_api_gateway_rest_api.api.execution_arn }