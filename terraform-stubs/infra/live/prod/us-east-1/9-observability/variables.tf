variable "aws_region" { type = string, default = "us-east-1" }
variable "env"        { type = string, default = "prod" }

# must match your nodegroup key in 10-foundation (we used "core")
variable "node_group_name" { type = string, default = "core" }

# log retention for Container Insights log groups
variable "container_insights_log_retention_days" { type = number, default = 30 }

# optional: get alarm emails without wiring anything else
variable "alarm_email" { type = string, default = "" }