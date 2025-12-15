provider "aws" {
  region = var.aws_region
  default_tags {
    tags = { Environment = var.env, ManagedBy = "terraform" }
  }
}

data "terraform_remote_state" "foundation" {
  backend = "s3"
  config = {
    bucket = "REPLACE_ME_TFSTATE_BUCKET"
    key    = "prod/us-east-1/foundation/terraform.tfstate"
    region = "us-east-1"
  }
}

data "aws_caller_identity" "me" {}