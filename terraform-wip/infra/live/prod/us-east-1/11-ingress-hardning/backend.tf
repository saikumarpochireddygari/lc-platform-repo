terraform {
  backend "s3" {
    bucket         = "REPLACE_ME_TFSTATE_BUCKET"
    key            = "prod/us-east-1/ingress-hardening/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "terraform-locks"
    encrypt        = true
  }
}