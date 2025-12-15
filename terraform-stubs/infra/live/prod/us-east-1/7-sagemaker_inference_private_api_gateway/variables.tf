variable "aws_region" { type = string, default = "us-east-1" }
variable "env"        { type = string, default = "prod" }

# Your inference container in ECR (immutable tag)
variable "inference_ecr_image" { type = string }

# Optional: name the private API
variable "api_name" { type = string, default = "inference-private-api" }