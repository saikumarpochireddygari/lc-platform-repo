variable "aws_region" { type = string, default = "us-east-1" }
variable "env"        { type = string, default = "prod" }

variable "mlflow_db_name"     { type = string, default = "mlflow" }
variable "mlflow_db_username" { type = string, default = "mlflow" }
variable "mlflow_db_password" { type = string, sensitive = true }