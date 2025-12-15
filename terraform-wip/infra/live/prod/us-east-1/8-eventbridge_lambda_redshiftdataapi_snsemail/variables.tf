variable "aws_region" { type = string, default = "us-east-1" }
variable "env"        { type = string, default = "prod" }

variable "alert_email" { type = string }

# Redshift Serverless Data API
variable "redshift_workgroup_name" { type = string }
variable "redshift_database"       { type = string }
variable "redshift_secret_arn"     { type = string }

variable "sql_query" { type = string }
variable "schedule_expression" { type = string, default = "rate(15 minutes)" }