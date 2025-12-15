variable "aws_region" { type = string, default = "us-east-1" }
variable "env"        { type = string, default = "prod" }

# Audit log retention
variable "cloudtrail_log_retention_days" { type = number, default = 365 }
variable "flowlogs_retention_days"       { type = number, default = 90 }

# Optional: associate WAF with specific ALBs (internal ALB supported too)
variable "enable_waf" { type = bool, default = false }
variable "alb_arns"   { type = list(string), default = [] }