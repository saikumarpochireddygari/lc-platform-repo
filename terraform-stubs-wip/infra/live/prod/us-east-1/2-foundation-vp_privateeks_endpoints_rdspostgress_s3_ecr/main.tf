data "aws_availability_zones" "azs" {}
data "aws_caller_identity" "me" {}

# ---- VPC (public subnets only for NAT; EKS + ALB internal in private subnets) ----
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "${var.env}-vpc"
  cidr = var.vpc_cidr

  azs            = slice(data.aws_availability_zones.azs.names, 0, 3)
  private_subnets = ["10.20.1.0/24", "10.20.2.0/24", "10.20.3.0/24"]
  public_subnets  = ["10.20.101.0/24", "10.20.102.0/24", "10.20.103.0/24"]

  enable_nat_gateway = true
  single_nat_gateway = false

  enable_dns_support   = true
  enable_dns_hostnames = true

  # Tags so ALB controller can place INTERNAL load balancers on private subnets
  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = "1"
  }
}

# ---- Private Route53 zone for internal hostnames (optional but recommended) ----
resource "aws_route53_zone" "private" {
  name = var.private_domain_name
  vpc { vpc_id = module.vpc.vpc_id }
}

# ---- KMS for EKS secrets encryption ----
resource "aws_kms_key" "eks" {
  description             = "EKS secrets encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

# ---- EKS (PRIVATE endpoint only) ----
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.0"

  cluster_name    = "${var.env}-eks"
  cluster_version = var.eks_version

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  cluster_endpoint_public_access  = false
  cluster_endpoint_private_access = true

  enable_irsa = true

  cluster_encryption_config = {
    resources        = ["secrets"]
    provider_key_arn = aws_kms_key.eks.arn
  }

  cluster_enabled_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  eks_managed_node_groups = {
    core = {
      instance_types = ["m6i.large"]
      min_size       = 2
      max_size       = 6
      desired_size   = 3
    }
  }
}

# ---- VPC endpoints (reduce NAT reliance; keeps “private” posture) ----
resource "aws_vpc_endpoint" "s3" {
  vpc_id       = module.vpc.vpc_id
  service_name = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = module.vpc.private_route_table_ids
}

resource "aws_security_group" "vpce" {
  name   = "${var.env}-vpce-sg"
  vpc_id = module.vpc.vpc_id
  ingress { from_port = 443, to_port = 443, protocol = "tcp", cidr_blocks = [module.vpc.vpc_cidr_block] }
  egress  { from_port = 0,   to_port = 0,   protocol = "-1",  cidr_blocks = ["0.0.0.0/0"] }
}

locals {
  interface_endpoints = [
    "ecr.api", "ecr.dkr", "logs", "sts", "ssm", "ec2"
  ]
}

resource "aws_vpc_endpoint" "iface" {
  for_each = toset(local.interface_endpoints)

  vpc_id            = module.vpc.vpc_id
  vpc_endpoint_type = "Interface"
  service_name      = "com.amazonaws.${var.aws_region}.${each.value}"

  subnet_ids         = module.vpc.private_subnets
  security_group_ids = [aws_security_group.vpce.id]
  private_dns_enabled = true
}

# ---- S3 bucket for MLflow artifacts ----
resource "aws_s3_bucket" "mlflow_artifacts" {
  bucket = "${var.env}-mlflow-artifacts-${data.aws_caller_identity.me.account_id}"
}

resource "aws_s3_bucket_public_access_block" "mlflow_artifacts" {
  bucket                  = aws_s3_bucket.mlflow_artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "mlflow_artifacts" {
  bucket = aws_s3_bucket.mlflow_artifacts.id
  rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } }
}

resource "aws_s3_bucket_versioning" "mlflow_artifacts" {
  bucket = aws_s3_bucket.mlflow_artifacts.id
  versioning_configuration { status = "Enabled" }
}

# ---- RDS Postgres for MLflow (Multi-AZ, backups, encrypted) ----
resource "aws_security_group" "rds" {
  name   = "${var.env}-rds-sg"
  vpc_id = module.vpc.vpc_id

  ingress { from_port = 5432, to_port = 5432, protocol = "tcp", cidr_blocks = [module.vpc.vpc_cidr_block] }
  egress  { from_port = 0, to_port = 0, protocol = "-1", cidr_blocks = ["0.0.0.0/0"] }
}

resource "aws_db_subnet_group" "rds" {
  name       = "${var.env}-rds-subnets"
  subnet_ids = module.vpc.private_subnets
}

resource "aws_db_instance" "mlflow" {
  identifier              = "${var.env}-mlflow-postgres"
  engine                  = "postgres"
  engine_version          = "16.3"
  instance_class          = "db.t4g.medium"
  allocated_storage       = 50
  max_allocated_storage   = 200

  db_name  = var.mlflow_db_name
  username = var.mlflow_db_username
  password = var.mlflow_db_password

  multi_az                = true
  storage_encrypted       = true
  backup_retention_period = 14
  deletion_protection     = true
  skip_final_snapshot     = false

  vpc_security_group_ids  = [aws_security_group.rds.id]
  db_subnet_group_name    = aws_db_subnet_group.rds.name

  performance_insights_enabled = true
}

# ---- ECR repos ----
resource "aws_ecr_repository" "inference" {
  name                 = "${var.env}/inference"
  image_tag_mutability = "IMMUTABLE"
  encryption_configuration { encryption_type = "AES256" }
}

resource "aws_ecr_repository" "training" {
  name                 = "${var.env}/training"
  image_tag_mutability = "IMMUTABLE"
  encryption_configuration { encryption_type = "AES256" }
}