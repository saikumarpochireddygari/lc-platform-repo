variable "aws_region" { type = string, default = "us-east-1" }
variable "env"        { type = string, default = "prod" }
variable "owner"      { type = string, default = "platform" }

variable "vpc_cidr" { type = string, default = "10.20.0.0/16" }

# PRIVATE DNS zone for internal ingress (change to your real internal domain)
variable "private_domain_name" { type = string, default = "corp.internal" }

# MLflow Postgres
variable "mlflow_db_name"     { type = string, default = "mlflow" }
variable "mlflow_db_username" { type = string, default = "mlflow" }
variable "mlflow_db_password" { type = string, sensitive = true }

variable "eks_version" { type = string, default = "1.30" }