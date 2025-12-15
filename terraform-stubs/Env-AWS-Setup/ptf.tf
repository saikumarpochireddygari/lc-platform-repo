############################################
# prod_persistence.tf
# Strict prod-grade persistence hardening for:
# - EKS (EBS CSI + gp3 default StorageClass w/ KMS)
# - Jenkins (Helm) persistent home on encrypted gp3
# - MLflow backend (RDS Postgres) hardened (backups, snapshots, deletion protection, KMS)
# - S3 buckets (MLflow artifacts + MWAA source) hardened (block public, TLS-only, SSE-KMS, versioning, lifecycle)
############################################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.26.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.13.0"
    }
  }
}

############################
# Variables
############################

variable "region" {
  type = string
}

variable "tags" {
  type    = map(string)
  default = {}
}

# EKS
variable "eks_cluster_name" {
  type = string
}

variable "eks_oidc_provider_arn" {
  type = string
}

variable "eks_oidc_provider_url" {
  type = string
  # Example: https://oidc.eks.us-east-1.amazonaws.com/id/XXXXXXXXXXXXXX
}

# Network for RDS
variable "vpc_id" {
  type = string
}

variable "private_subnet_ids" {
  type = list(string)
}

# RDS (MLflow backend store)
variable "mlflow_db_name" {
  type    = string
  default = "mlflow"
}

variable "mlflow_db_username" {
  type    = string
  default = "mlflow"
}

variable "mlflow_db_password" {
  type      = string
  sensitive = true
}

variable "mlflow_db_engine_version" {
  type    = string
  default = "15.7"
}

variable "mlflow_db_instance_class" {
  type    = string
  default = "db.m6g.large"
}

variable "mlflow_db_allocated_storage_gb" {
  type    = number
  default = 200
}

variable "mlflow_db_backup_retention_days" {
  type    = number
  default = 35
}

variable "mlflow_db_maintenance_window" {
  type    = string
  default = "sun:05:00-sun:06:00"
}

variable "mlflow_db_backup_window" {
  type    = string
  default = "03:00-04:00"
}

# S3 buckets
variable "mlflow_artifacts_bucket_name" {
  type = string
}

variable "mwaa_source_bucket_name" {
  type = string
}

# Optional: principals that need access to buckets
variable "mlflow_service_role_arn" {
  type    = string
  default = null
}

variable "mwaa_execution_role_arn" {
  type    = string
  default = null
}

# Jenkins (Helm)
variable "jenkins_namespace" {
  type    = string
  default = "jenkins"
}

variable "jenkins_release_name" {
  type    = string
  default = "jenkins"
}

variable "jenkins_chart_version" {
  type    = string
  default = "5.6.5"
}

variable "jenkins_storage_size" {
  type    = string
  default = "50Gi"
}

variable "jenkins_admin_password" {
  type      = string
  sensitive = true
}

############################
# Providers
############################

provider "aws" {
  region = var.region
}

data "aws_eks_cluster" "this" {
  name = var.eks_cluster_name
}

data "aws_eks_cluster_auth" "this" {
  name = var.eks_cluster_name
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.this.endpoint
  cluster_ca_certificate  = base64decode(data.aws_eks_cluster.this.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.this.token
}

provider "helm" {
  kubernetes {
    host                   = data.aws_eks_cluster.this.endpoint
    cluster_ca_certificate  = base64decode(data.aws_eks_cluster.this.certificate_authority[0].data)
    token                  = data.aws_eks_cluster_auth.this.token
  }
}

############################
# KMS Keys (strict prod)
############################

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "kms_default" {
  statement {
    sid    = "EnableRootPermissions"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }
}

resource "aws_kms_key" "s3" {
  description             = "KMS CMK for S3 bucket encryption (ML platform)"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_default.json
  tags                    = var.tags
}

resource "aws_kms_alias" "s3" {
  name          = "alias/ml-platform/s3"
  target_key_id = aws_kms_key.s3.key_id
}

resource "aws_kms_key" "rds" {
  description             = "KMS CMK for RDS encryption (MLflow backend)"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_default.json
  tags                    = var.tags
}

resource "aws_kms_alias" "rds" {
  name          = "alias/ml-platform/rds"
  target_key_id = aws_kms_key.rds.key_id
}

resource "aws_kms_key" "ebs" {
  description             = "KMS CMK for EBS encryption (EKS PVCs / Jenkins home)"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_default.json
  tags                    = var.tags
}

resource "aws_kms_alias" "ebs" {
  name          = "alias/ml-platform/ebs"
  target_key_id = aws_kms_key.ebs.key_id
}

############################
# S3 buckets (strict prod)
############################

locals {
  s3_force_tls_policy = function(bucket_arn) => jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyInsecureTransport"
        Effect   = "Deny"
        Principal = "*"
        Action   = "s3:*"
        Resource = [bucket_arn, "${bucket_arn}/*"]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# MLflow artifacts bucket
resource "aws_s3_bucket" "mlflow_artifacts" {
  bucket        = var.mlflow_artifacts_bucket_name
  force_destroy = false
  tags          = var.tags
}

resource "aws_s3_bucket_public_access_block" "mlflow_artifacts" {
  bucket                  = aws_s3_bucket.mlflow_artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "mlflow_artifacts" {
  bucket = aws_s3_bucket.mlflow_artifacts.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "mlflow_artifacts" {
  bucket = aws_s3_bucket.mlflow_artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
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

resource "aws_s3_bucket_lifecycle_configuration" "mlflow_artifacts" {
  bucket = aws_s3_bucket.mlflow_artifacts.id

  rule {
    id     = "tiering-and-cleanup"
    status = "Enabled"

    noncurrent_version_expiration {
      noncurrent_days = 365
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    transition {
      days          = 30
      storage_class = "INTELLIGENT_TIERING"
    }
  }
}

resource "aws_s3_bucket_policy" "mlflow_artifacts_tls" {
  bucket = aws_s3_bucket.mlflow_artifacts.id
  policy = local.s3_force_tls_policy(aws_s3_bucket.mlflow_artifacts.arn)
}

# MWAA source bucket (DAGs/plugins/requirements)
resource "aws_s3_bucket" "mwaa_source" {
  bucket        = var.mwaa_source_bucket_name
  force_destroy = false
  tags          = var.tags
}

resource "aws_s3_bucket_public_access_block" "mwaa_source" {
  bucket                  = aws_s3_bucket.mwaa_source.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "mwaa_source" {
  bucket = aws_s3_bucket.mwaa_source.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "mwaa_source" {
  bucket = aws_s3_bucket.mwaa_source.id
  versioning_configuration {
    status = "Enabled"
  }
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

resource "aws_s3_bucket_lifecycle_configuration" "mwaa_source" {
  bucket = aws_s3_bucket.mwaa_source.id

  rule {
    id     = "cleanup"
    status = "Enabled"

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_policy" "mwaa_source_tls" {
  bucket = aws_s3_bucket.mwaa_source.id
  policy = local.s3_force_tls_policy(aws_s3_bucket.mwaa_source.arn)
}

############################
# RDS Postgres (MLflow backend) strict prod
############################

resource "aws_security_group" "mlflow_rds" {
  name        = "${var.eks_cluster_name}-mlflow-rds-sg"
  description = "RDS SG for MLflow backend (allow from VPC CIDR / EKS nodes / app SGs in your stack)"
  vpc_id      = var.vpc_id
  tags        = var.tags

  # STRICT: do not open to 0.0.0.0/0.
  # Replace the cidr_blocks with your private CIDRs or SG-based rules in your stack.
  ingress {
    description = "Postgres from VPC (tighten to specific SGs in real prod)"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    description = "All egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_subnet_group" "mlflow" {
  name       = "${var.eks_cluster_name}-mlflow-db-subnets"
  subnet_ids = var.private_subnet_ids
  tags       = var.tags
}

resource "aws_db_parameter_group" "mlflow" {
  name   = "${var.eks_cluster_name}-mlflow-pg"
  family = "postgres15"
  tags   = var.tags

  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }

  parameter {
    name  = "log_statement"
    value = "none"
  }
}

resource "aws_db_instance" "mlflow" {
  identifier                  = "${var.eks_cluster_name}-mlflow-db"
  engine                      = "postgres"
  engine_version              = var.mlflow_db_engine_version
  instance_class              = var.mlflow_db_instance_class
  allocated_storage           = var.mlflow_db_allocated_storage_gb
  storage_type                = "gp3"
  storage_encrypted           = true
  kms_key_id                  = aws_kms_key.rds.arn
  multi_az                    = true
  publicly_accessible         = false

  db_name                     = var.mlflow_db_name
  username                    = var.mlflow_db_username
  password                    = var.mlflow_db_password

  db_subnet_group_name        = aws_db_subnet_group.mlflow.name
  vpc_security_group_ids      = [aws_security_group.mlflow_rds.id]
  parameter_group_name        = aws_db_parameter_group.mlflow.name

  backup_retention_period     = var.mlflow_db_backup_retention_days
  backup_window               = var.mlflow_db_backup_window
  maintenance_window          = var.mlflow_db_maintenance_window
  copy_tags_to_snapshot       = true

  deletion_protection         = true
  skip_final_snapshot         = false
  final_snapshot_identifier   = "${var.eks_cluster_name}-mlflow-db-final-${replace(timestamp(), "[: TZ-]", "")}"

  performance_insights_enabled          = true
  performance_insights_kms_key_id       = aws_kms_key.rds.arn
  enabled_cloudwatch_logs_exports       = ["postgresql", "upgrade"]
  auto_minor_version_upgrade            = true
  apply_immediately                     = false

  tags = var.tags
}

############################
# EKS: EBS CSI Driver + gp3 default StorageClass (encrypted w/ KMS)
############################

# IAM role for aws-ebs-csi-driver via IRSA
data "aws_iam_policy_document" "ebs_csi_assume_role" {
  statement {
    effect = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [var.eks_oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${replace(var.eks_oidc_provider_url, "https://", "")}:sub"
      values   = ["system:serviceaccount:kube-system:ebs-csi-controller-sa"]
    }

    condition {
      test     = "StringEquals"
      variable = "${replace(var.eks_oidc_provider_url, "https://", "")}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ebs_csi" {
  name               = "${var.eks_cluster_name}-ebs-csi-irsa"
  assume_role_policy = data.aws_iam_policy_document.ebs_csi_assume_role.json
  tags               = var.tags
}

# AWS managed policy for CSI driver
resource "aws_iam_role_policy_attachment" "ebs_csi_managed" {
  role       = aws_iam_role.ebs_csi.name
  policy_arn  = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
}

# Extra KMS permissions so CSI can create encrypted volumes with your CMK
data "aws_iam_policy_document" "ebs_csi_kms" {
  statement {
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
      "kms:CreateGrant"
    ]
    resources = [aws_kms_key.ebs.arn]
  }
}

resource "aws_iam_policy" "ebs_csi_kms" {
  name   = "${var.eks_cluster_name}-ebs-csi-kms"
  policy = data.aws_iam_policy_document.ebs_csi_kms.json
  tags   = var.tags
}

resource "aws_iam_role_policy_attachment" "ebs_csi_kms" {
  role      = aws_iam_role.ebs_csi.name
  policy_arn = aws_iam_policy.ebs_csi_kms.arn
}

# Install EBS CSI addon (strict prod: pin version if you want)
resource "aws_eks_addon" "ebs_csi" {
  cluster_name             = var.eks_cluster_name
  addon_name               = "aws-ebs-csi-driver"
  service_account_role_arn = aws_iam_role.ebs_csi.arn
  resolve_conflicts_on_update = "PRESERVE"
  tags                     = var.tags
}

# gp3 default StorageClass via Kubernetes provider
resource "kubernetes_storage_class" "gp3_encrypted" {
  metadata {
    name = "gp3-encrypted"
    annotations = {
      "storageclass.kubernetes.io/is-default-class" = "true"
    }
  }

  storage_provisioner = "ebs.csi.aws.com"

  parameters = {
    type      = "gp3"
    encrypted = "true"
    kmsKeyId  = aws_kms_key.ebs.arn
    fsType    = "ext4"
  }

  reclaim_policy        = "Delete"
  volume_binding_mode   = "WaitForFirstConsumer"
  allow_volume_expansion = true

  depends_on = [aws_eks_addon.ebs_csi]
}

############################
# Jenkins on EKS (persistent controller home)
############################

resource "kubernetes_namespace" "jenkins" {
  metadata {
    name = var.jenkins_namespace
    labels = {
      "name" = var.jenkins_namespace
    }
  }
}

resource "helm_release" "jenkins" {
  name       = var.jenkins_release_name
  namespace  = kubernetes_namespace.jenkins.metadata[0].name
  repository = "https://charts.jenkins.io"
  chart      = "jenkins"
  version    = var.jenkins_chart_version

  # Strict-ish: force persistence, define storage class, size, avoid ephemeral
  set {
    name  = "controller.persistence.enabled"
    value = "true"
  }

  set {
    name  = "controller.persistence.storageClass"
    value = kubernetes_storage_class.gp3_encrypted.metadata[0].name
  }

  set {
    name  = "controller.persistence.size"
    value = var.jenkins_storage_size
  }

  set {
    name  = "controller.adminPassword"
    value = var.jenkins_admin_password
  }

  # Recommended hardening toggles (still keep simple)
  set {
    name  = "controller.serviceType"
    value = "ClusterIP"
  }

  # If you expose Jenkins, do it via Ingress + auth + TLS (not via NodePort)
  set {
    name  = "controller.ingress.enabled"
    value = "false"
  }

  # Reduce blast radius
  set {
    name  = "controller.runAsUser"
    value = "1000"
  }

  set {
    name  = "controller.fsGroup"
    value = "1000"
  }

  depends_on = [
    kubernetes_storage_class.gp3_encrypted
  ]
}

############################
# Outputs (useful wiring)
############################

output "mlflow_rds_endpoint" {
  value = aws_db_instance.mlflow.address
}

output "mlflow_rds_port" {
  value = aws_db_instance.mlflow.port
}

output "mlflow_artifacts_bucket" {
  value = aws_s3_bucket.mlflow_artifacts.bucket
}

output "mwaa_source_bucket" {
  value = aws_s3_bucket.mwaa_source.bucket
}

output "ebs_storageclass_name" {
  value = kubernetes_storage_class.gp3_encrypted.metadata[0].name
}