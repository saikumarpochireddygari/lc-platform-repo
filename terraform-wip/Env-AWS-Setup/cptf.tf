############################################
# FILE: versions.tf
############################################
terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.12"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.25"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6"
    }
    tls = {
      source  = "hashicorp/tls"
      version = ">= 4.0"
    }
  }

  # OPTIONAL: remote state (create bucket + dynamodb first, or keep local for assignment)
  # backend "s3" {
  #   bucket         = "CHANGE_ME-tfstate"
  #   key            = "ml-platform/prod/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "CHANGE_ME-tflock"
  #   encrypt        = true
  # }
}

############################################
# FILE: providers.tf
############################################
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Platform   = var.platform_name
      ManagedBy  = "terraform"
      Env        = var.env
      CostCenter = var.cost_center
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

############################################
# FILE: variables.tf
############################################
variable "platform_name" {
  type    = string
  default = "ml-platform"
}

variable "env" {
  type    = string
  default = "prod"
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "cost_center" {
  type    = string
  default = "mlops"
}

variable "vpc_cidr" {
  type    = string
  default = "10.40.0.0/16"
}

variable "az_count" {
  type    = number
  default = 2
}

variable "eks_cluster_version" {
  type    = string
  default = "1.29"
}

variable "eks_node_instance_types" {
  type    = list(string)
  default = ["m6i.large"]
}

variable "eks_node_min" {
  type    = number
  default = 2
}

variable "eks_node_max" {
  type    = number
  default = 6
}

variable "eks_node_desired" {
  type    = number
  default = 2
}

variable "admin_cidrs" {
  # who can reach private endpoints via VPN/DirectConnect; for strict prod, keep empty and rely on private access
  type    = list(string)
  default = []
}

variable "projects" {
  # Multi-project template: one entry = one DS team/project. Resources per env per project are created via for_each.
  # You can add more projects without copy/paste.
  type = map(object({
    owner_email            = string
    redshift_db_name       = optional(string, "telemetry")
    redshift_namespace     = optional(string, null) # if null, created per project
    telemetry_prefix       = optional(string, "telemetry")
    drift_query_sql        = optional(string, "select 1 as ok;")
    drift_alarm_threshold  = optional(number, 1)
    enable_realtime_api    = optional(bool, true)
    enable_telemetry_pipe  = optional(bool, true)
    enable_drift_scheduler = optional(bool, true)
  }))

  default = {
    iris = {
      owner_email           = "owner@example.com"
      drift_query_sql       = "select count(*) as cnt from telemetry.drift_events where severity='HIGH' and event_ts > dateadd(minute,-15,getdate());"
      drift_alarm_threshold = 1
    }
  }
}

############################################
# FILE: locals.tf
############################################
locals {
  name_prefix = "${var.platform_name}-${var.env}"

  # derive AZs
  azs = slice(data.aws_availability_zones.available.names, 0, var.az_count)

  # one template per project-env
  project_envs = {
    for k, v in var.projects :
    k => merge(v, {
      project = k
      env     = var.env
    })
  }
}

data "aws_availability_zones" "available" {}

############################################
# FILE: network.tf (strict prod: private subnets + NAT + VPC endpoints)
############################################
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
}

resource "aws_subnet" "public" {
  for_each = { for i, az in local.azs : az => i }

  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, each.value)
  availability_zone       = each.key
  map_public_ip_on_launch = true
}

resource "aws_subnet" "private" {
  for_each = { for i, az in local.azs : az => i }

  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 100 + each.value)
  availability_zone       = each.key
  map_public_ip_on_launch = false
}

resource "aws_eip" "nat" {
  for_each = aws_subnet.public
  domain   = "vpc"
}

resource "aws_nat_gateway" "nat" {
  for_each      = aws_subnet.public
  allocation_id = aws_eip.nat[each.key].id
  subnet_id     = each.value.id
  depends_on    = [aws_internet_gateway.igw]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
}

resource "aws_route" "public_default" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

resource "aws_route_table_association" "public" {
  for_each       = aws_subnet.public
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  for_each = aws_subnet.private
  vpc_id   = aws_vpc.main.id
}

resource "aws_route" "private_default" {
  for_each               = aws_subnet.private
  route_table_id         = aws_route_table.private[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat[each.key].id
}

resource "aws_route_table_association" "private" {
  for_each       = aws_subnet.private
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private[each.key].id
}

# VPC endpoints to reduce NAT dependency (strict prod baseline)
resource "aws_security_group" "vpce" {
  name        = "${local.name_prefix}-vpce-sg"
  description = "VPC endpoint SG"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id          = aws_vpc.main.id
  service_name    = "com.amazonaws.${var.aws_region}.s3"
  route_table_ids = concat([aws_route_table.public.id], [for rt in aws_route_table.private : rt.id])
}

resource "aws_vpc_endpoint" "sts" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.sts"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [for s in aws_subnet.private : s.id]
  private_dns_enabled = true
  security_group_ids  = [aws_security_group.vpce.id]
}

resource "aws_vpc_endpoint" "logs" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.logs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [for s in aws_subnet.private : s.id]
  private_dns_enabled = true
  security_group_ids  = [aws_security_group.vpce.id]
}

############################################
# FILE: kms.tf (strict prod: separate keys)
############################################
resource "aws_kms_key" "s3" {
  description             = "KMS for S3 data (artifacts, telemetry, MWAA source)"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "s3" {
  name          = "alias/${local.name_prefix}/s3"
  target_key_id = aws_kms_key.s3.key_id
}

resource "aws_kms_key" "rds" {
  description             = "KMS for RDS (MLflow backend Postgres)"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "rds" {
  name          = "alias/${local.name_prefix}/rds"
  target_key_id = aws_kms_key.rds.key_id
}

resource "aws_kms_key" "ebs" {
  description             = "KMS for EBS volumes (EKS PVCs)"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "ebs" {
  name          = "alias/${local.name_prefix}/ebs"
  target_key_id = aws_kms_key.ebs.key_id
}

############################################
# FILE: s3.tf (artifacts + telemetry + MWAA source; strict prod hardening)
############################################
resource "aws_s3_bucket" "mlflow_artifacts" {
  bucket        = "${local.name_prefix}-mlflow-artifacts-${data.aws_caller_identity.current.account_id}"
  force_destroy = false
}

resource "aws_s3_bucket_versioning" "mlflow_artifacts" {
  bucket = aws_s3_bucket.mlflow_artifacts.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "mlflow_artifacts" {
  bucket = aws_s3_bucket.mlflow_artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "mlflow_artifacts" {
  bucket                  = aws_s3_bucket.mlflow_artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "mlflow_artifacts" {
  bucket = aws_s3_bucket.mlflow_artifacts.id

  rule {
    id     = "abort-mpu"
    status = "Enabled"
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }

  rule {
    id     = "noncurrent-expire"
    status = "Enabled"
    noncurrent_version_expiration { noncurrent_days = 90 }
  }
}

resource "aws_s3_bucket_policy" "mlflow_artifacts_tls_only" {
  bucket = aws_s3_bucket.mlflow_artifacts.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyInsecureTransport"
        Effect   = "Deny"
        Principal= "*"
        Action   = "s3:*"
        Resource = [
          aws_s3_bucket.mlflow_artifacts.arn,
          "${aws_s3_bucket.mlflow_artifacts.arn}/*"
        ]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}

resource "aws_s3_bucket" "mwaa_source" {
  bucket        = "${local.name_prefix}-mwaa-source-${data.aws_caller_identity.current.account_id}"
  force_destroy = false
}

resource "aws_s3_bucket_versioning" "mwaa_source" {
  bucket = aws_s3_bucket.mwaa_source.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "mwaa_source" {
  bucket = aws_s3_bucket.mwaa_source.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "mwaa_source" {
  bucket                  = aws_s3_bucket.mwaa_source.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "mwaa_source_tls_only" {
  bucket = aws_s3_bucket.mwaa_source.id
  policy = aws_s3_bucket_policy.mlflow_artifacts_tls_only.policy
}

# telemetry buckets per project (optional; defaults ON for drift/monitoring)
resource "aws_s3_bucket" "telemetry" {
  for_each     = { for k, v in local.project_envs : k => v if v.enable_telemetry_pipe }
  bucket       = "${local.name_prefix}-${each.key}-telemetry-${data.aws_caller_identity.current.account_id}"
  force_destroy = false
}

resource "aws_s3_bucket_server_side_encryption_configuration" "telemetry" {
  for_each = aws_s3_bucket.telemetry
  bucket   = each.value.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "telemetry" {
  for_each                = aws_s3_bucket.telemetry
  bucket                  = each.value.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "telemetry" {
  for_each = aws_s3_bucket.telemetry
  bucket   = each.value.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_policy" "telemetry_tls_only" {
  for_each = aws_s3_bucket.telemetry
  bucket   = each.value.id
  policy   = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyInsecureTransport"
        Effect   = "Deny"
        Principal= "*"
        Action   = "s3:*"
        Resource = [each.value.arn, "${each.value.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}

############################################
# FILE: rds_mlflow.tf (strict prod MLflow backend)
############################################
resource "random_password" "mlflow_db" {
  length  = 28
  special = true
}

resource "aws_security_group" "rds" {
  name   = "${local.name_prefix}-rds-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    description = "Postgres from VPC"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_subnet_group" "rds" {
  name       = "${local.name_prefix}-rds-subnets"
  subnet_ids = [for s in aws_subnet.private : s.id]
}

resource "aws_db_parameter_group" "postgres13" {
  name   = "${local.name_prefix}-pg13"
  family = "postgres13"

  parameter {
    name  = "log_min_duration_statement"
    value = "500" # ms
  }

  parameter {
    name  = "log_statement"
    value = "none"
  }
}

resource "aws_db_instance" "mlflow" {
  identifier              = "${local.name_prefix}-mlflow"
  engine                  = "postgres"
  engine_version          = "13.15"
  instance_class          = "db.m6g.large"
  allocated_storage       = 100
  max_allocated_storage   = 500
  storage_type            = "gp3"
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.rds.arn
  multi_az                = true
  publicly_accessible     = false

  db_subnet_group_name    = aws_db_subnet_group.rds.name
  vpc_security_group_ids  = [aws_security_group.rds.id]

  name                    = "mlflow"
  username                = "mlflow_admin"
  password                = random_password.mlflow_db.result

  backup_retention_period = 14
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:05:00-sun:06:00"

  performance_insights_enabled = true
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  deletion_protection     = true
  skip_final_snapshot     = false
  final_snapshot_identifier = "${local.name_prefix}-mlflow-final-${replace(timestamp(), "[:TZ-]", "")}"

  parameter_group_name    = aws_db_parameter_group.postgres13.name
}

############################################
# FILE: eks.tf (strict prod baseline)
############################################
data "aws_iam_policy_document" "eks_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals { type = "Service", identifiers = ["eks.amazonaws.com"] }
  }
}

resource "aws_iam_role" "eks_cluster" {
  name               = "${local.name_prefix}-eks-cluster-role"
  assume_role_policy = data.aws_iam_policy_document.eks_assume.json
}

resource "aws_iam_role_policy_attachment" "eks_cluster_AmazonEKSClusterPolicy" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_security_group" "eks_cluster" {
  name   = "${local.name_prefix}-eks-cluster-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_eks_cluster" "this" {
  name     = "${local.name_prefix}-eks"
  role_arn = aws_iam_role.eks_cluster.arn
  version  = var.eks_cluster_version

  vpc_config {
    subnet_ids              = [for s in aws_subnet.private : s.id]
    security_group_ids      = [aws_security_group.eks_cluster.id]
    endpoint_private_access = true
    endpoint_public_access  = false
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_AmazonEKSClusterPolicy
  ]
}

data "aws_iam_policy_document" "eks_node_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals { type = "Service", identifiers = ["ec2.amazonaws.com"] }
  }
}

resource "aws_iam_role" "eks_node" {
  name               = "${local.name_prefix}-eks-node-role"
  assume_role_policy = data.aws_iam_policy_document.eks_node_assume.json
}

resource "aws_iam_role_policy_attachment" "eks_node_AmazonEKSWorkerNodePolicy" {
  role       = aws_iam_role.eks_node.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "eks_node_AmazonEKS_CNI_Policy" {
  role       = aws_iam_role.eks_node.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "eks_node_AmazonEC2ContainerRegistryReadOnly" {
  role       = aws_iam_role.eks_node.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_eks_node_group" "default" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "${local.name_prefix}-default-ng"
  node_role_arn   = aws_iam_role.eks_node.arn
  subnet_ids      = [for s in aws_subnet.private : s.id]

  scaling_config {
    min_size     = var.eks_node_min
    max_size     = var.eks_node_max
    desired_size = var.eks_node_desired
  }

  instance_types = var.eks_node_instance_types
  capacity_type  = "ON_DEMAND"

  update_config { max_unavailable = 1 }
}

data "aws_eks_cluster" "eks" {
  name = aws_eks_cluster.this.name
}

data "aws_eks_cluster_auth" "eks" {
  name = aws_eks_cluster.this.name
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.eks.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.eks.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.eks.token
}

provider "helm" {
  kubernetes {
    host                   = data.aws_eks_cluster.eks.endpoint
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.eks.certificate_authority[0].data)
    token                  = data.aws_eks_cluster_auth.eks.token
  }
}

############################################
# FILE: eks_storage_ebs_csi.tf (IRSA + default encrypted StorageClass)
############################################
data "tls_certificate" "eks_oidc" {
  url = aws_eks_cluster.this.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "eks" {
  url             = aws_eks_cluster.this.identity[0].oidc[0].issuer
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks_oidc.certificates[0].sha1_fingerprint]
}

data "aws_iam_policy_document" "ebs_csi_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals { type = "Federated", identifiers = [aws_iam_openid_connect_provider.eks.arn] }

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_eks_cluster.this.identity[0].oidc[0].issuer, "https://", "")}:sub"
      values   = ["system:serviceaccount:kube-system:ebs-csi-controller-sa"]
    }
  }
}

resource "aws_iam_role" "ebs_csi" {
  name               = "${local.name_prefix}-ebs-csi-irsa"
  assume_role_policy = data.aws_iam_policy_document.ebs_csi_assume.json
}

resource "aws_iam_role_policy_attachment" "ebs_csi_attach" {
  role       = aws_iam_role.ebs_csi.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
}

resource "aws_eks_addon" "ebs_csi" {
  cluster_name             = aws_eks_cluster.this.name
  addon_name               = "aws-ebs-csi-driver"
  service_account_role_arn = aws_iam_role.ebs_csi.arn
  resolve_conflicts_on_update = "OVERWRITE"
  depends_on               = [aws_eks_node_group.default]
}

resource "kubernetes_storage_class" "gp3_encrypted_default" {
  metadata {
    name = "gp3-encrypted"
    annotations = {
      "storageclass.kubernetes.io/is-default-class" = "true"
    }
  }

  storage_provisioner = "ebs.csi.aws.com"
  reclaim_policy      = "Retain"
  volume_binding_mode = "WaitForFirstConsumer"
  allow_volume_expansion = true

  parameters = {
    type      = "gp3"
    encrypted = "true"
    kmsKeyId  = aws_kms_key.ebs.arn
    fsType    = "ext4"
  }

  depends_on = [aws_eks_addon.ebs_csi]
}

############################################
# FILE: jenkins_on_eks.tf (strict prod: persistent PVC + IRSA for AWS access)
############################################
resource "kubernetes_namespace" "jenkins" {
  metadata { name = "jenkins" }
}

data "aws_iam_policy_document" "jenkins_irsa_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals { type = "Federated", identifiers = [aws_iam_openid_connect_provider.eks.arn] }

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_eks_cluster.this.identity[0].oidc[0].issuer, "https://", "")}:sub"
      values   = ["system:serviceaccount:jenkins:jenkins"]
    }
  }
}

resource "aws_iam_role" "jenkins" {
  name               = "${local.name_prefix}-jenkins-irsa"
  assume_role_policy = data.aws_iam_policy_document.jenkins_irsa_assume.json
}

# Jenkins permissions: upload MWAA DAGs, read/write MLflow artifacts, interact with ECR, invoke Terraform in CI, etc.
data "aws_iam_policy_document" "jenkins_policy" {
  statement {
    effect = "Allow"
    actions = [
      "s3:PutObject", "s3:GetObject", "s3:ListBucket", "s3:DeleteObject",
      "s3:GetBucketLocation"
    ]
    resources = concat(
      [
        aws_s3_bucket.mwaa_source.arn,
        "${aws_s3_bucket.mwaa_source.arn}/*",
        aws_s3_bucket.mlflow_artifacts.arn,
        "${aws_s3_bucket.mlflow_artifacts.arn}/*",
      ],
      flatten([
        for b in aws_s3_bucket.telemetry : [
          b.arn,
          "${b.arn}/*"
        ]
      ])
    )
  }

  statement {
    effect = "Allow"
    actions = [
      "ecr:GetAuthorizationToken",
      "ecr:BatchGetImage",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:DescribeRepositories",
      "ecr:DescribeImages",
      "ecr:ListImages"
    ]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "mwaa:CreateCliToken",
      "mwaa:GetEnvironment",
      "mwaa:ListEnvironments"
    ]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "kms:Encrypt","kms:Decrypt","kms:GenerateDataKey","kms:DescribeKey"
    ]
    resources = [aws_kms_key.s3.arn, aws_kms_key.ebs.arn, aws_kms_key.rds.arn]
  }
}

resource "aws_iam_policy" "jenkins" {
  name   = "${local.name_prefix}-jenkins-policy"
  policy = data.aws_iam_policy_document.jenkins_policy.json
}

resource "aws_iam_role_policy_attachment" "jenkins_attach" {
  role       = aws_iam_role.jenkins.name
  policy_arn = aws_iam_policy.jenkins.arn
}

resource "helm_release" "jenkins" {
  name       = "jenkins"
  namespace  = kubernetes_namespace.jenkins.metadata[0].name
  repository = "https://charts.jenkins.io"
  chart      = "jenkins"
  version    = "5.7.1"

  values = [
    yamlencode({
      controller = {
        serviceType = "ClusterIP"
        servicePort = 8080
        admin = {
          createSecret = true
        }
        installPlugins = [
          "workflow-aggregator:600.vb_57cdd26fdd7",
          "git:5.7.0",
          "github:1.40.0",
          "credentials-binding:680.vb_a_2a_5a_4a_c6d8",
          "pipeline-utility-steps:2.18.0"
        ]
        # persistence
        persistence = {
          enabled      = true
          storageClass = kubernetes_storage_class.gp3_encrypted_default.metadata[0].name
          size         = "50Gi"
        }
        serviceAccount = {
          create = true
          name   = "jenkins"
          annotations = {
            "eks.amazonaws.com/role-arn" = aws_iam_role.jenkins.arn
          }
        }
      }
      agent = {
        enabled = true
      }
    })
  ]

  depends_on = [kubernetes_storage_class.gp3_encrypted_default]
}

############################################
# FILE: mwaa.tf (AWS Managed Airflow)
############################################
resource "aws_security_group" "mwaa" {
  name   = "${local.name_prefix}-mwaa-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    description = "Airflow webserver in-VPC access"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  # MWAA workers/scheduler in private subnets need egress to AWS APIs + MLflow internal endpoint
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

data "aws_iam_policy_document" "mwaa_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals { type = "Service", identifiers = ["airflow.amazonaws.com", "airflow-env.amazonaws.com"] }
  }
}

resource "aws_iam_role" "mwaa" {
  name               = "${local.name_prefix}-mwaa-role"
  assume_role_policy = data.aws_iam_policy_document.mwaa_assume.json
}

# Minimal MWAA role policy: S3 access for DAGs + logs
data "aws_iam_policy_document" "mwaa_policy" {
  statement {
    effect = "Allow"
    actions = ["s3:GetObject", "s3:ListBucket"]
    resources = [
      aws_s3_bucket.mwaa_source.arn,
      "${aws_s3_bucket.mwaa_source.arn}/*"
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents","logs:GetLogEvents","logs:DescribeLogGroups","logs:DescribeLogStreams"
    ]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = ["kms:Decrypt","kms:Encrypt","kms:GenerateDataKey","kms:DescribeKey"]
    resources = [aws_kms_key.s3.arn]
  }
}

resource "aws_iam_policy" "mwaa" {
  name   = "${local.name_prefix}-mwaa-policy"
  policy = data.aws_iam_policy_document.mwaa_policy.json
}

resource "aws_iam_role_policy_attachment" "mwaa_attach" {
  role       = aws_iam_role.mwaa.name
  policy_arn = aws_iam_policy.mwaa.arn
}

resource "aws_mwaa_environment" "this" {
  name               = "${local.name_prefix}-mwaa"
  airflow_version    = "2.8.1"
  environment_class  = "mw1.small"
  execution_role_arn = aws_iam_role.mwaa.arn

  source_bucket_arn  = aws_s3_bucket.mwaa_source.arn
  dag_s3_path        = "dags"
  requirements_s3_path = "requirements/requirements.txt"

  network_configuration {
    security_group_ids = [aws_security_group.mwaa.id]
    subnet_ids         = [for s in aws_subnet.private : s.id]
  }

  logging_configuration {
    dag_processing_logs { enabled = true, log_level = "INFO" }
    scheduler_logs      { enabled = true, log_level = "INFO" }
    task_logs           { enabled = true, log_level = "INFO" }
    webserver_logs      { enabled = true, log_level = "INFO" }
    worker_logs         { enabled = true, log_level = "INFO" }
  }

  webserver_access_mode = "PRIVATE_ONLY"
}

############################################
# FILE: mlflow_on_ecs.tf (AWS MLflow service on ECS Fargate behind INTERNAL ALB; artifacts in S3; backend in RDS)
############################################
resource "aws_ecs_cluster" "mlflow" {
  name = "${local.name_prefix}-mlflow-ecs"
}

resource "aws_cloudwatch_log_group" "mlflow" {
  name              = "/${local.name_prefix}/mlflow"
  retention_in_days = 30
}

data "aws_iam_policy_document" "ecs_task_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals { type = "Service", identifiers = ["ecs-tasks.amazonaws.com"] }
  }
}

resource "aws_iam_role" "mlflow_task" {
  name               = "${local.name_prefix}-mlflow-task-role"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume.json
}

data "aws_iam_policy_document" "mlflow_task_policy" {
  statement {
    effect = "Allow"
    actions = ["s3:GetObject","s3:PutObject","s3:DeleteObject","s3:ListBucket"]
    resources = [
      aws_s3_bucket.mlflow_artifacts.arn,
      "${aws_s3_bucket.mlflow_artifacts.arn}/*"
    ]
  }

  statement {
    effect = "Allow"
    actions = ["kms:Decrypt","kms:Encrypt","kms:GenerateDataKey","kms:DescribeKey"]
    resources = [aws_kms_key.s3.arn]
  }
}

resource "aws_iam_policy" "mlflow_task" {
  name   = "${local.name_prefix}-mlflow-task-policy"
  policy = data.aws_iam_policy_document.mlflow_task_policy.json
}

resource "aws_iam_role_policy_attachment" "mlflow_task_attach" {
  role       = aws_iam_role.mlflow_task.name
  policy_arn = aws_iam_policy.mlflow_task.arn
}

resource "aws_iam_role" "mlflow_exec" {
  name               = "${local.name_prefix}-mlflow-exec-role"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume.json
}

resource "aws_iam_role_policy_attachment" "mlflow_exec_attach" {
  role       = aws_iam_role.mlflow_exec.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_security_group" "mlflow_alb" {
  name   = "${local.name_prefix}-mlflow-alb-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "mlflow_svc" {
  name   = "${local.name_prefix}-mlflow-svc-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port       = 5000
    to_port         = 5000
    protocol        = "tcp"
    security_groups = [aws_security_group.mlflow_alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_lb" "mlflow" {
  name               = "${local.name_prefix}-mlflow"
  internal           = true
  load_balancer_type = "application"
  security_groups    = [aws_security_group.mlflow_alb.id]
  subnets            = [for s in aws_subnet.private : s.id]
}

resource "aws_lb_target_group" "mlflow" {
  name        = "${local.name_prefix}-mlflow-tg"
  port        = 5000
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    path                = "/"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 15
    timeout             = 5
    matcher             = "200-399"
  }
}

resource "aws_lb_listener" "mlflow" {
  load_balancer_arn = aws_lb.mlflow.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.mlflow.arn
  }
}

resource "aws_ecs_task_definition" "mlflow" {
  family                   = "${local.name_prefix}-mlflow"
  cpu                      = "512"
  memory                   = "1024"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  execution_role_arn       = aws_iam_role.mlflow_exec.arn
  task_role_arn            = aws_iam_role.mlflow_task.arn

  container_definitions = jsonencode([
    {
      name      = "mlflow"
      image     = "python:3.11-slim"
      essential = true
      portMappings = [{ containerPort = 5000, hostPort = 5000, protocol = "tcp" }]
      environment = [
        { name = "MLFLOW_S3_ENDPOINT_URL",      value = "https://s3.${var.aws_region}.amazonaws.com" },
        { name = "AWS_DEFAULT_REGION",          value = var.aws_region },
        { name = "MLFLOW_BACKEND_STORE_URI",    value = "postgresql+psycopg2://mlflow_admin:${random_password.mlflow_db.result}@${aws_db_instance.mlflow.address}:5432/mlflow" },
        { name = "MLFLOW_DEFAULT_ARTIFACT_ROOT",value = "s3://${aws_s3_bucket.mlflow_artifacts.bucket}" }
      ]
      command = [
        "bash","-lc",
        join("\n", [
          "set -euo pipefail",
          "apt-get update && apt-get install -y --no-install-recommends ca-certificates gcc libpq-dev && rm -rf /var/lib/apt/lists/*",
          "pip install --no-cache-dir 'mlflow>=2.0.0,<3.0.0' psycopg2-binary boto3",
          "mlflow server --host 0.0.0.0 --port 5000 --backend-store-uri \"$MLFLOW_BACKEND_STORE_URI\" --default-artifact-root \"$MLFLOW_DEFAULT_ARTIFACT_ROOT\""
        ])
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.mlflow.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "mlflow"
        }
      }
    }
  ])
}

resource "aws_ecs_service" "mlflow" {
  name            = "${local.name_prefix}-mlflow"
  cluster         = aws_ecs_cluster.mlflow.id
  task_definition = aws_ecs_task_definition.mlflow.arn
  desired_count   = 2
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = [for s in aws_subnet.private : s.id]
    security_groups  = [aws_security_group.mlflow_svc.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.mlflow.arn
    container_name   = "mlflow"
    container_port   = 5000
  }

  deployment_minimum_healthy_percent = 50
  deployment_maximum_percent         = 200
}

############################################
# FILE: telemetry_firehose_lambda_s3_redshift.tf (OPTION A template per project)
# Flow: EKS (apps) -> Firehose -> Lambda (enrich/aggregate) -> S3 -> Lambda COPY -> Redshift Serverless
############################################
resource "aws_redshiftserverless_namespace" "ns" {
  for_each = { for k, v in local.project_envs : k => v if v.enable_telemetry_pipe }

  namespace_name = "${local.name_prefix}-${each.key}"
  db_name        = each.value.redshift_db_name
  iam_roles      = []
  log_exports    = ["userlog", "connectionlog", "useractivitylog"]
}

resource "aws_security_group" "redshift" {
  for_each = aws_redshiftserverless_namespace.ns
  name     = "${local.name_prefix}-${each.key}-redshift-sg"
  vpc_id   = aws_vpc.main.id

  ingress {
    from_port   = 5439
    to_port     = 5439
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_redshiftserverless_workgroup" "wg" {
  for_each = aws_redshiftserverless_namespace.ns

  workgroup_name       = "${local.name_prefix}-${each.key}"
  namespace_name       = each.value.namespace_name
  base_capacity        = 32
  publicly_accessible  = false

  subnet_ids           = [for s in aws_subnet.private : s.id]
  security_group_ids   = [aws_security_group.redshift[each.key].id]
}

# IAM for Firehose + Lambda + Redshift COPY
data "aws_iam_policy_document" "firehose_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals { type = "Service", identifiers = ["firehose.amazonaws.com"] }
  }
}

resource "aws_iam_role" "firehose" {
  for_each           = aws_s3_bucket.telemetry
  name               = "${local.name_prefix}-${each.key}-firehose-role"
  assume_role_policy = data.aws_iam_policy_document.firehose_assume.json
}

data "aws_iam_policy_document" "firehose_policy" {
  for_each = aws_s3_bucket.telemetry

  statement {
    effect = "Allow"
    actions = [
      "s3:AbortMultipartUpload","s3:GetBucketLocation","s3:GetObject","s3:ListBucket","s3:ListBucketMultipartUploads",
      "s3:PutObject"
    ]
    resources = [
      each.value.arn,
      "${each.value.arn}/*"
    ]
  }

  statement {
    effect = "Allow"
    actions = ["kms:Encrypt","kms:Decrypt","kms:GenerateDataKey","kms:DescribeKey"]
    resources = [aws_kms_key.s3.arn]
  }

  statement {
    effect = "Allow"
    actions = ["lambda:InvokeFunction","lambda:GetFunctionConfiguration"]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = ["logs:PutLogEvents"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "firehose" {
  for_each = aws_s3_bucket.telemetry
  name     = "${local.name_prefix}-${each.key}-firehose-policy"
  policy   = data.aws_iam_policy_document.firehose_policy[each.key].json
}

resource "aws_iam_role_policy_attachment" "firehose_attach" {
  for_each   = aws_s3_bucket.telemetry
  role       = aws_iam_role.firehose[each.key].name
  policy_arn = aws_iam_policy.firehose[each.key].arn
}

# Firehose processing Lambda (stub). In strict prod, deploy real code via CI to S3 + lambda update.
resource "aws_cloudwatch_log_group" "telemetry_enrich" {
  for_each          = aws_s3_bucket.telemetry
  name              = "/${local.name_prefix}/${each.key}/telemetry-enrich"
  retention_in_days = 30
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals { type = "Service", identifiers = ["lambda.amazonaws.com"] }
  }
}

resource "aws_iam_role" "telemetry_enrich" {
  for_each           = aws_s3_bucket.telemetry
  name               = "${local.name_prefix}-${each.key}-telemetry-enrich-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  for_each   = aws_s3_bucket.telemetry
  role       = aws_iam_role.telemetry_enrich[each.key].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Placeholder Lambda package (inline zip via archive_file is omitted to keep this single-file template clean)
# Provide your own lambda zip in CI/CD and set s3_bucket + s3_key instead.
resource "aws_lambda_function" "telemetry_enrich" {
  for_each      = aws_s3_bucket.telemetry
  function_name = "${local.name_prefix}-${each.key}-telemetry-enrich"
  role          = aws_iam_role.telemetry_enrich[each.key].arn
  runtime       = "python3.11"
  handler       = "handler.lambda_handler"
  timeout       = 30
  memory_size   = 512

  filename         = "lambda_stub.zip" # put a tiny zip at repo root for terraform apply
  source_code_hash = filebase64sha256("lambda_stub.zip")

  environment {
    variables = {
      PROJECT = each.key
      ENV     = var.env
    }
  }

  depends_on = [aws_iam_role_policy_attachment.lambda_basic]
}

# Firehose -> S3 with Lambda processing
resource "aws_kinesis_firehose_delivery_stream" "telemetry" {
  for_each = aws_s3_bucket.telemetry

  name        = "${local.name_prefix}-${each.key}-telemetry"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn           = aws_iam_role.firehose[each.key].arn
    bucket_arn         = each.value.arn
    prefix             = "${local.project_envs[each.key].telemetry_prefix}/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/hour=!{timestamp:HH}/"
    error_output_prefix = "errors/"

    buffering_size     = 64
    buffering_interval = 60

    compression_format = "GZIP"

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = "/aws/kinesisfirehose/${local.name_prefix}-${each.key}-telemetry"
      log_stream_name = "S3Delivery"
    }

    processing_configuration {
      enabled = true

      processors {
        type = "Lambda"
        parameters {
          parameter_name  = "LambdaArn"
          parameter_value = aws_lambda_function.telemetry_enrich[each.key].arn
        }
        parameters {
          parameter_name  = "NumberOfRetries"
          parameter_value = "3"
        }
      }
    }

    encryption_configuration {
      kms_key_arn = aws_kms_key.s3.arn
    }
  }
}

# S3 -> COPY to Redshift Serverless Lambda (triggered on new objects)
resource "aws_cloudwatch_log_group" "redshift_copy" {
  for_each          = aws_s3_bucket.telemetry
  name              = "/${local.name_prefix}/${each.key}/redshift-copy"
  retention_in_days = 30
}

resource "aws_iam_role" "redshift_copy" {
  for_each           = aws_s3_bucket.telemetry
  name               = "${local.name_prefix}-${each.key}-redshift-copy-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "redshift_copy_basic" {
  for_each   = aws_s3_bucket.telemetry
  role       = aws_iam_role.redshift_copy[each.key].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "redshift_copy_policy" {
  for_each = aws_s3_bucket.telemetry

  statement {
    effect = "Allow"
    actions = ["redshift-data:ExecuteStatement","redshift-data:DescribeStatement","redshift-data:GetStatementResult"]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = ["s3:GetObject","s3:ListBucket"]
    resources = [each.value.arn, "${each.value.arn}/*"]
  }

  statement {
    effect = "Allow"
    actions = ["kms:Decrypt","kms:Encrypt","kms:GenerateDataKey","kms:DescribeKey"]
    resources = [aws_kms_key.s3.arn]
  }
}

resource "aws_iam_policy" "redshift_copy" {
  for_each = aws_s3_bucket.telemetry
  name     = "${local.name_prefix}-${each.key}-redshift-copy-policy"
  policy   = data.aws_iam_policy_document.redshift_copy_policy[each.key].json
}

resource "aws_iam_role_policy_attachment" "redshift_copy_attach" {
  for_each   = aws_s3_bucket.telemetry
  role       = aws_iam_role.redshift_copy[each.key].name
  policy_arn = aws_iam_policy.redshift_copy[each.key].arn
}

resource "aws_lambda_function" "redshift_copy" {
  for_each      = aws_s3_bucket.telemetry
  function_name = "${local.name_prefix}-${each.key}-redshift-copy"
  role          = aws_iam_role.redshift_copy[each.key].arn
  runtime       = "python3.11"
  handler       = "handler.lambda_handler"
  timeout       = 60
  memory_size   = 512

  filename         = "lambda_stub.zip" # replace with real COPY logic package
  source_code_hash = filebase64sha256("lambda_stub.zip")

  environment {
    variables = {
      PROJECT        = each.key
      ENV            = var.env
      WORKGROUP_NAME = aws_redshiftserverless_workgroup.wg[each.key].workgroup_name
      DATABASE       = aws_redshiftserverless_namespace.ns[each.key].db_name
      TARGET_SCHEMA  = "telemetry"
      TARGET_TABLE   = "raw_events"
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.redshift_copy_basic,
    aws_iam_role_policy_attachment.redshift_copy_attach
  ]
}

resource "aws_lambda_permission" "allow_s3_invoke_copy" {
  for_each      = aws_s3_bucket.telemetry
  statement_id  = "AllowExecutionFromS3-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.redshift_copy[each.key].function_name
  principal     = "s3.amazonaws.com"
  source_arn    = each.value.arn
}

resource "aws_s3_bucket_notification" "telemetry_to_copy" {
  for_each = aws_s3_bucket.telemetry
  bucket   = each.value.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.redshift_copy[each.key].arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "${local.project_envs[each.key].telemetry_prefix}/"
  }

  depends_on = [aws_lambda_permission.allow_s3_invoke_copy]
}

############################################
# FILE: scheduled_redshift_drift_alerts.tf (EventBridge -> Lambda -> Redshift -> SNS)
############################################
resource "aws_sns_topic" "drift_alerts" {
  for_each = { for k, v in local.project_envs : k => v if v.enable_drift_scheduler }
  name     = "${local.name_prefix}-${each.key}-drift-alerts"
}

resource "aws_sns_topic_subscription" "drift_email" {
  for_each  = aws_sns_topic.drift_alerts
  topic_arn = each.value.arn
  protocol  = "email"
  endpoint  = local.project_envs[each.key].owner_email
}

resource "aws_cloudwatch_log_group" "drift_check" {
  for_each          = aws_sns_topic.drift_alerts
  name              = "/${local.name_prefix}/${each.key}/drift-check"
  retention_in_days = 30
}

resource "aws_iam_role" "drift_check" {
  for_each           = aws_sns_topic.drift_alerts
  name               = "${local.name_prefix}-${each.key}-drift-check-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "drift_basic" {
  for_each   = aws_sns_topic.drift_alerts
  role       = aws_iam_role.drift_check[each.key].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "drift_policy" {
  for_each = aws_sns_topic.drift_alerts

  statement {
    effect = "Allow"
    actions = ["redshift-data:ExecuteStatement","redshift-data:DescribeStatement","redshift-data:GetStatementResult"]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = ["sns:Publish"]
    resources = [each.value.arn]
  }
}

resource "aws_iam_policy" "drift_check" {
  for_each = aws_sns_topic.drift_alerts
  name     = "${local.name_prefix}-${each.key}-drift-check-policy"
  policy   = data.aws_iam_policy_document.drift_policy[each.key].json
}

resource "aws_iam_role_policy_attachment" "drift_attach" {
  for_each   = aws_sns_topic.drift_alerts
  role       = aws_iam_role.drift_check[each.key].name
  policy_arn = aws_iam_policy.drift_check[each.key].arn
}

resource "aws_lambda_function" "drift_check" {
  for_each      = aws_sns_topic.drift_alerts
  function_name = "${local.name_prefix}-${each.key}-drift-check"
  role          = aws_iam_role.drift_check[each.key].arn
  runtime       = "python3.11"
  handler       = "handler.lambda_handler"
  timeout       = 60
  memory_size   = 512

  filename         = "lambda_stub.zip" # replace with real Redshift Data API + SNS logic
  source_code_hash = filebase64sha256("lambda_stub.zip")

  environment {
    variables = {
      PROJECT        = each.key
      ENV            = var.env
      WORKGROUP_NAME = try(aws_redshiftserverless_workgroup.wg[each.key].workgroup_name, "")
      DATABASE       = try(aws_redshiftserverless_namespace.ns[each.key].db_name, "")
      DRIFT_SQL      = local.project_envs[each.key].drift_query_sql
      THRESHOLD      = tostring(local.project_envs[each.key].drift_alarm_threshold)
      SNS_TOPIC_ARN  = each.value.arn
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.drift_basic,
    aws_iam_role_policy_attachment.drift_attach
  ]
}

resource "aws_cloudwatch_event_rule" "drift_schedule" {
  for_each = aws_sns_topic.drift_alerts
  name     = "${local.name_prefix}-${each.key}-drift-schedule"
  schedule_expression = "rate(15 minutes)"
}

resource "aws_cloudwatch_event_target" "drift_target" {
  for_each = aws_sns_topic.drift_alerts
  rule     = aws_cloudwatch_event_rule.drift_schedule[each.key].name
  arn      = aws_lambda_function.drift_check[each.key].arn
}

resource "aws_lambda_permission" "allow_events_invoke_drift" {
  for_each      = aws_sns_topic.drift_alerts
  statement_id  = "AllowExecutionFromEventBridge-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.drift_check[each.key].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.drift_schedule[each.key].arn
}

############################################
# FILE: sagemaker_realtime_api.tf (API Gateway -> Lambda -> SageMaker Endpoint)
############################################
resource "aws_iam_role" "sm_invoke_lambda" {
  for_each           = { for k, v in local.project_envs : k => v if v.enable_realtime_api }
  name               = "${local.name_prefix}-${each.key}-sm-invoke-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "sm_invoke_basic" {
  for_each   = aws_iam_role.sm_invoke_lambda
  role       = each.value.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "sm_invoke_policy" {
  for_each = aws_iam_role.sm_invoke_lambda

  statement {
    effect = "Allow"
    actions = ["sagemaker:InvokeEndpoint"]
    resources = ["*"] # tighten to specific endpoint ARN after creation
  }
}

resource "aws_iam_policy" "sm_invoke" {
  for_each = aws_iam_role.sm_invoke_lambda
  name     = "${local.name_prefix}-${each.key}-sm-invoke-policy"
  policy   = data.aws_iam_policy_document.sm_invoke_policy[each.key].json
}

resource "aws_iam_role_policy_attachment" "sm_invoke_attach" {
  for_each   = aws_iam_role.sm_invoke_lambda
  role       = aws_iam_role.sm_invoke_lambda[each.key].name
  policy_arn = aws_iam_policy.sm_invoke[each.key].arn
}

resource "aws_lambda_function" "sm_invoke" {
  for_each      = aws_iam_role.sm_invoke_lambda
  function_name = "${local.name_prefix}-${each.key}-invoke-endpoint"
  role          = each.value.arn
  runtime       = "python3.11"
  handler       = "handler.lambda_handler"
  timeout       = 30
  memory_size   = 512

  filename         = "lambda_stub.zip" # replace with real invoke endpoint logic
  source_code_hash = filebase64sha256("lambda_stub.zip")

  environment {
    variables = {
      PROJECT = each.key
      ENV     = var.env
      ENDPOINT_NAME = "${local.name_prefix}-${each.key}-endpoint" # must match actual endpoint below
    }
  }
}

resource "aws_apigatewayv2_api" "inference" {
  for_each      = aws_lambda_function.sm_invoke
  name          = "${local.name_prefix}-${each.key}-inference-api"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "inference" {
  for_each           = aws_lambda_function.sm_invoke
  api_id             = aws_apigatewayv2_api.inference[each.key].id
  integration_type   = "AWS_PROXY"
  integration_uri    = aws_lambda_function.sm_invoke[each.key].arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "inference" {
  for_each  = aws_lambda_function.sm_invoke
  api_id    = aws_apigatewayv2_api.inference[each.key].id
  route_key = "POST /invocations"
  target    = "integrations/${aws_apigatewayv2_integration.inference[each.key].id}"
}

resource "aws_apigatewayv2_stage" "inference" {
  for_each    = aws_lambda_function.sm_invoke
  api_id      = aws_apigatewayv2_api.inference[each.key].id
  name        = "$default"
  auto_deploy = true
}

resource "aws_lambda_permission" "allow_apigw_invoke" {
  for_each      = aws_lambda_function.sm_invoke
  statement_id  = "AllowAPIGWInvoke-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sm_invoke[each.key].function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.inference[each.key].execution_arn}/*/*"
}

############################################
# FILE: sagemaker_training_batch_plan.tf (prod plan: roles + buckets + outputs; run jobs via CI)
############################################
resource "aws_iam_role" "sagemaker_exec" {
  name               = "${local.name_prefix}-sagemaker-exec-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "sagemaker.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
}

data "aws_iam_policy_document" "sagemaker_exec_policy" {
  statement {
    effect = "Allow"
    actions = ["s3:GetObject","s3:PutObject","s3:ListBucket"]
    resources = [
      aws_s3_bucket.mlflow_artifacts.arn,
      "${aws_s3_bucket.mlflow_artifacts.arn}/*"
    ]
  }

  statement {
    effect = "Allow"
    actions = ["kms:Decrypt","kms:Encrypt","kms:GenerateDataKey","kms:DescribeKey"]
    resources = [aws_kms_key.s3.arn]
  }

  statement {
    effect = "Allow"
    actions = ["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "sagemaker_exec" {
  name   = "${local.name_prefix}-sagemaker-exec-policy"
  policy = data.aws_iam_policy_document.sagemaker_exec_policy.json
}

resource "aws_iam_role_policy_attachment" "sagemaker_exec_attach" {
  role       = aws_iam_role.sagemaker_exec.name
  policy_arn = aws_iam_policy.sagemaker_exec.arn
}

############################################
# FILE: outputs.tf (use in Jenkins/MWAA configs)
############################################
output "vpc_id" {
  value = aws_vpc.main.id
}

output "eks_cluster_name" {
  value = aws_eks_cluster.this.name
}

output "mwaa_environment_name" {
  value = aws_mwaa_environment.this.name
}

output "mwaa_source_bucket" {
  value = aws_s3_bucket.mwaa_source.bucket
}

output "mlflow_tracking_internal_url" {
  value = "http://${aws_lb.mlflow.dns_name}"
}

output "mlflow_artifacts_bucket" {
  value = aws_s3_bucket.mlflow_artifacts.bucket
}

output "mlflow_rds_endpoint" {
  value = aws_db_instance.mlflow.address
}

output "project_inference_api_urls" {
  value = { for k, api in aws_apigatewayv2_api.inference : k => api.api_endpoint }
}

output "project_firehose_names" {
  value = { for k, fh in aws_kinesis_firehose_delivery_stream.telemetry : k => fh.name }
}

output "project_redshift_workgroups" {
  value = { for k, wg in aws_redshiftserverless_workgroup.wg : k => wg.workgroup_name }
}

output "sagemaker_execution_role_arn" {
  value = aws_iam_role.sagemaker_exec.arn
}