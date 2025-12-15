provider "aws" {
  region = var.aws_region
  default_tags { tags = { Environment = var.env, ManagedBy = "terraform", Owner = var.owner } }
}