variable "aws_region" { type = string, default = "us-east-1" }
variable "env"        { type = string, default = "prod" }

variable "state_bucket_name" { type = string }
variable "lock_table_name"   { type = string, default = "terraform-locks" }