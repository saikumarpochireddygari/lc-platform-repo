#############################################
# main.tf — Terraform plan (skeleton) for:
# 1) Jenkins on EKS
# 2) AWS MWAA (Airflow) + integration with Jenkins
# 3) AWS-hosted MLflow + integration with MWAA
# 4) Jenkins IAM to talk to other AWS services
#
# This is a production-ish template starter:
# - VPC
# - EKS (with IRSA)
# - Jenkins via Helm (serviceAccount annotated with IAM role)
# - MWAA env (private, S3 DAG bucket)
# - MLflow on ECS Fargate + ALB + RDS + S3 artifacts
#############################################

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
  }
}

#############################################
# Providers
#############################################

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" {}

#############################################
# VPC (shared by EKS, MWAA, ECS, RDS)
#############################################

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.7.0"

  name = "${var.platform_name}-${var.environment}"
  cidr = var.vpc_cidr

  azs             = slice(data.aws_availability_zones.available.names, 0, 3)
  private_subnets = var.private_subnets
  public_subnets  = var.public_subnets

  enable_nat_gateway     = true
  single_nat_gateway     = false
  one_nat_gateway_per_az = true

  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = var.tags
}

#############################################
# EKS (Jenkins runs on EKS)
#############################################

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "20.11.0"

  cluster_name    = "${var.platform_name}-${var.environment}-eks"
  cluster_version = var.eks_cluster_version

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  enable_irsa = true

  eks_managed_node_groups = {
    jenkins = {
      instance_types = var.eks_node_instance_types
      min_size       = var.eks_node_min
      max_size       = var.eks_node_max
      desired_size   = var.eks_node_desired
      capacity_type  = "ON_DEMAND"
    }
  }

  tags = var.tags
}

data "aws_eks_cluster" "this" {
  name = module.eks.cluster_name
}

data "aws_eks_cluster_auth" "this" {
  name = module.eks.cluster_name
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.this.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.this.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.this.token
}

provider "helm" {
  kubernetes {
    host                   = data.aws_eks_cluster.this.endpoint
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.this.certificate_authority[0].data)
    token                  = data.aws_eks_cluster_auth.this.token
  }
}

#############################################
# Jenkins IRSA Role (Jenkins -> AWS)
#############################################

resource "kubernetes_namespace" "jenkins" {
  metadata {
    name = "jenkins"
  }
}

data "aws_iam_policy_document" "jenkins_irsa_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [module.eks.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${replace(module.eks.oidc_provider, "https://", "")}:sub"
      values   = ["system:serviceaccount:jenkins:jenkins"]
    }

    condition {
      test     = "StringEquals"
      variable = "${replace(module.eks.oidc_provider, "https://", "")}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "jenkins_irsa" {
  name               = "${var.platform_name}-${var.environment}-jenkins-irsa"
  assume_role_policy = data.aws_iam_policy_document.jenkins_irsa_assume.json
  tags               = var.tags
}

#############################################
# MWAA S3 bucket (DAGs/plugins/requirements)
# Jenkins syncs DAGs to this bucket (integration 1->2)
#############################################

resource "aws_s3_bucket" "mwaa_source" {
  bucket = "${var.platform_name}-${var.environment}-mwaa-source-${data.aws_caller_identity.current.account_id}"
  tags   = var.tags
}

resource "aws_s3_bucket_versioning" "mwaa_source" {
  bucket = aws_s3_bucket.mwaa_source.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "mwaa_source" {
  bucket = aws_s3_bucket.mwaa_source.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

#############################################
# MLflow artifacts bucket (S3)
#############################################

resource "aws_s3_bucket" "mlflow_artifacts" {
  bucket = "${var.platform_name}-${var.environment}-mlflow-artifacts-${data.aws_caller_identity.current.account_id}"
  tags   = var.tags
}

resource "aws_s3_bucket_versioning" "mlflow_artifacts" {
  bucket = aws_s3_bucket.mlflow_artifacts.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "mlflow_artifacts" {
  bucket = aws_s3_bucket.mlflow_artifacts.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

#############################################
# Jenkins permissions (4. Jenkins -> AWS services)
# - S3 (MWAA source + MLflow artifacts if needed)
# - MWAA token APIs to trigger DAGs (CreateCliToken / CreateWebLoginToken)
# - Optional: ECR, ECS, EKS, SageMaker, CloudWatch, etc.
#############################################

data "aws_iam_policy_document" "jenkins_policy" {
  statement {
    sid     = "S3SyncMWAASource"
    effect  = "Allow"
    actions = ["s3:PutObject", "s3:GetObject", "s3:DeleteObject", "s3:ListBucket"]
    resources = [
      aws_s3_bucket.mwaa_source.arn,
      "${aws_s3_bucket.mwaa_source.arn}/*"
    ]
  }

  statement {
    sid     = "MWAATokensAndInvoke"
    effect  = "Allow"
    actions = [
      "mwaa:CreateCliToken",
      "mwaa:CreateWebLoginToken",
      "mwaa:GetEnvironment"
    ]
    resources = ["*"]
  }

  # Optional common platform permissions for Jenkins:
  statement {
    sid    = "ECRPushPull"
    effect = "Allow"
    actions = [
      "ecr:GetAuthorizationToken",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
      "ecr:PutImage",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
      "ecr:DescribeRepositories",
      "ecr:CreateRepository"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "ECSDeploy"
    effect = "Allow"
    actions = [
      "ecs:Describe*",
      "ecs:UpdateService",
      "ecs:RegisterTaskDefinition",
      "ecs:List*"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "EKSAccessForDeploy"
    effect = "Allow"
    actions = [
      "eks:DescribeCluster",
      "eks:ListClusters"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "SageMakerBasic"
    effect = "Allow"
    actions = [
      "sagemaker:CreateTrainingJob",
      "sagemaker:CreateTransformJob",
      "sagemaker:CreateModel",
      "sagemaker:CreateEndpointConfig",
      "sagemaker:CreateEndpoint",
      "sagemaker:UpdateEndpoint",
      "sagemaker:Describe*",
      "sagemaker:List*"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "CloudWatchLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "jenkins_inline" {
  name   = "${var.platform_name}-${var.environment}-jenkins-inline"
  role   = aws_iam_role.jenkins_irsa.id
  policy = data.aws_iam_policy_document.jenkins_policy.json
}

#############################################
# Jenkins (Helm)
#############################################

resource "helm_release" "jenkins" {
  name       = "jenkins"
  namespace  = kubernetes_namespace.jenkins.metadata[0].name
  repository = "https://charts.jenkins.io"
  chart      = "jenkins"
  version    = var.jenkins_chart_version

  set {
    name  = "controller.serviceAccount.create"
    value = "true"
  }
  set {
    name  = "controller.serviceAccount.name"
    value = "jenkins"
  }
  set {
    name  = "controller.serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = aws_iam_role.jenkins_irsa.arn
  }

  set {
    name  = "controller.adminUser"
    value = var.jenkins_admin_user
  }
  set_sensitive {
    name  = "controller.adminPassword"
    value = var.jenkins_admin_password
  }

  set {
    name  = "controller.serviceType"
    value = var.jenkins_service_type
  }

  # (Optional) Persistence
  set {
    name  = "persistence.enabled"
    value = "true"
  }
  set {
    name  = "persistence.size"
    value = var.jenkins_pvc_size
  }
}

#############################################
# MWAA (Airflow) (2. AWS Airflow + integration with Jenkins)
#############################################

data "aws_iam_policy_document" "mwaa_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["airflow.amazonaws.com", "airflow-env.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "mwaa_execution" {
  name               = "${var.platform_name}-${var.environment}-mwaa-exec"
  assume_role_policy = data.aws_iam_policy_document.mwaa_assume.json
  tags               = var.tags
}

data "aws_iam_policy_document" "mwaa_execution_policy" {
  # Required MWAA baseline: S3 + logs
  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:ListBucket"
    ]
    resources = [
      aws_s3_bucket.mwaa_source.arn,
      "${aws_s3_bucket.mwaa_source.arn}/*"
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:GetLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams"
    ]
    resources = ["*"]
  }

  # Optional: if Airflow tasks need to read/write artifacts or datasets
  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket"
    ]
    resources = [
      aws_s3_bucket.mlflow_artifacts.arn,
      "${aws_s3_bucket.mlflow_artifacts.arn}/*"
    ]
  }
}

resource "aws_iam_role_policy" "mwaa_execution_inline" {
  name   = "${var.platform_name}-${var.environment}-mwaa-exec-inline"
  role   = aws_iam_role.mwaa_execution.id
  policy = data.aws_iam_policy_document.mwaa_execution_policy.json
}

resource "aws_security_group" "mwaa_sg" {
  name        = "${var.platform_name}-${var.environment}-mwaa-sg"
  description = "MWAA security group"
  vpc_id      = module.vpc.vpc_id
  tags        = var.tags
}

#############################################
# MLflow on ECS needs an SG too; MWAA must reach it (integration 2->3)
#############################################

resource "aws_security_group" "mlflow_sg" {
  name        = "${var.platform_name}-${var.environment}-mlflow-sg"
  description = "MLflow ECS service SG"
  vpc_id      = module.vpc.vpc_id
  tags        = var.tags

  ingress {
    description     = "Allow MWAA to MLflow"
    from_port       = 5000
    to_port         = 5000
    protocol        = "tcp"
    security_groups = [aws_security_group.mwaa_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_mwaa_environment" "this" {
  name                = "${var.platform_name}-${var.environment}-mwaa"
  airflow_version     = var.mwaa_airflow_version
  environment_class   = var.mwaa_environment_class
  execution_role_arn  = aws_iam_role.mwaa_execution.arn
  source_bucket_arn   = aws_s3_bucket.mwaa_source.arn
  dag_s3_path         = var.mwaa_dag_s3_path
  plugins_s3_path     = var.mwaa_plugins_s3_path
  requirements_s3_path = var.mwaa_requirements_s3_path

  min_workers = var.mwaa_min_workers
  max_workers = var.mwaa_max_workers
  schedulers  = var.mwaa_schedulers

  webserver_access_mode = "PRIVATE_ONLY"

  network_configuration {
    security_group_ids = [aws_security_group.mwaa_sg.id]
    subnet_ids         = module.vpc.private_subnets
  }

  logging_configuration {
    dag_processing_logs {
      enabled   = true
      log_level = "INFO"
    }
    scheduler_logs {
      enabled   = true
      log_level = "INFO"
    }
    task_logs {
      enabled   = true
      log_level = "INFO"
    }
    webserver_logs {
      enabled   = true
      log_level = "INFO"
    }
    worker_logs {
      enabled   = true
      log_level = "INFO"
    }
  }

  airflow_configuration_options = {
    "core.load_examples" = "False"

    # Let MWAA tasks hit MLflow via internal ALB DNS (set below)
    "core.default_task_retries" = "1"
  }

  environment_variables = {
    ENV                  = var.environment
    MLFLOW_TRACKING_URI  = "http://${aws_lb.mlflow.dns_name}:5000"
    MLFLOW_ARTIFACT_S3_BUCKET = aws_s3_bucket.mlflow_artifacts.bucket
  }

  tags = var.tags
}

#############################################
# MLflow on ECS Fargate (3. AWS MLflow + integration with MWAA)
#############################################

resource "aws_db_subnet_group" "mlflow" {
  name       = "${var.platform_name}-${var.environment}-mlflow-db-subnets"
  subnet_ids = module.vpc.private_subnets
  tags       = var.tags
}

resource "aws_security_group" "mlflow_db_sg" {
  name        = "${var.platform_name}-${var.environment}-mlflow-db-sg"
  description = "RDS SG for MLflow"
  vpc_id      = module.vpc.vpc_id
  tags        = var.tags

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.mlflow_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "mlflow" {
  identifier              = "${var.platform_name}-${var.environment}-mlflow-db"
  engine                  = "postgres"
  engine_version          = var.mlflow_db_engine_version
  instance_class          = var.mlflow_db_instance_class
  allocated_storage       = var.mlflow_db_allocated_storage
  username                = var.mlflow_db_username
  password                = var.mlflow_db_password
  db_name                 = var.mlflow_db_name
  port                    = 5432
  publicly_accessible     = false
  multi_az                = false
  storage_encrypted       = true
  skip_final_snapshot     = true
  deletion_protection     = false
  db_subnet_group_name    = aws_db_subnet_group.mlflow.name
  vpc_security_group_ids  = [aws_security_group.mlflow_db_sg.id]

  tags = var.tags
}

resource "aws_ecs_cluster" "mlflow" {
  name = "${var.platform_name}-${var.environment}-mlflow-ecs"
  tags = var.tags
}

data "aws_iam_policy_document" "ecs_task_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "mlflow_task_execution" {
  name               = "${var.platform_name}-${var.environment}-mlflow-task-exec"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "mlflow_task_exec_attach" {
  role       = aws_iam_role.mlflow_task_execution.name
  policy_arn  = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role" "mlflow_task_role" {
  name               = "${var.platform_name}-${var.environment}-mlflow-task-role"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume.json
  tags               = var.tags
}

data "aws_iam_policy_document" "mlflow_task_policy" {
  statement {
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:DeleteObject"
    ]
    resources = [
      aws_s3_bucket.mlflow_artifacts.arn,
      "${aws_s3_bucket.mlflow_artifacts.arn}/*"
    ]
  }
}

resource "aws_iam_role_policy" "mlflow_task_inline" {
  name   = "${var.platform_name}-${var.environment}-mlflow-task-inline"
  role   = aws_iam_role.mlflow_task_role.id
  policy = data.aws_iam_policy_document.mlflow_task_policy.json
}

resource "aws_cloudwatch_log_group" "mlflow" {
  name              = "/${var.platform_name}/${var.environment}/mlflow"
  retention_in_days = 14
  tags              = var.tags
}

resource "aws_lb" "mlflow" {
  name               = "${var.platform_name}-${var.environment}-mlflow-alb"
  internal           = true
  load_balancer_type = "application"
  subnets            = module.vpc.private_subnets
  security_groups    = [aws_security_group.mlflow_sg.id]
  tags               = var.tags
}

resource "aws_lb_target_group" "mlflow" {
  name        = "${var.platform_name}-${var.environment}-mlflow-tg"
  port        = 5000
  protocol    = "HTTP"
  vpc_id      = module.vpc.vpc_id
  target_type = "ip"

  health_check {
    path                = "/"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 15
    matcher             = "200-399"
  }

  tags = var.tags
}

resource "aws_lb_listener" "mlflow" {
  load_balancer_arn = aws_lb.mlflow.arn
  port              = 5000
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.mlflow.arn
  }
}

locals {
  mlflow_backend_store_uri = "postgresql://${var.mlflow_db_username}:${var.mlflow_db_password}@${aws_db_instance.mlflow.address}:5432/${var.mlflow_db_name}"
  mlflow_default_artifact_root = "s3://${aws_s3_bucket.mlflow_artifacts.bucket}"
}

resource "aws_ecs_task_definition" "mlflow" {
  family                   = "${var.platform_name}-${var.environment}-mlflow"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.mlflow_task_cpu
  memory                   = var.mlflow_task_memory
  execution_role_arn       = aws_iam_role.mlflow_task_execution.arn
  task_role_arn            = aws_iam_role.mlflow_task_role.arn

  container_definitions = jsonencode([
    {
      name      = "mlflow"
      image     = var.mlflow_image
      essential = true
      portMappings = [
        { containerPort = 5000, hostPort = 5000, protocol = "tcp" }
      ]
      environment = [
        { name = "MLFLOW_BACKEND_STORE_URI",    value = local.mlflow_backend_store_uri },
        { name = "MLFLOW_DEFAULT_ARTIFACT_ROOT", value = local.mlflow_default_artifact_root },
        { name = "AWS_REGION",                  value = var.aws_region }
      ]
      command = [
        "mlflow",
        "server",
        "--host", "0.0.0.0",
        "--port", "5000",
        "--backend-store-uri", local.mlflow_backend_store_uri,
        "--default-artifact-root", local.mlflow_default_artifact_root
      ]
      logConfiguration = {
        logDriver = "awslogs",
        options = {
          awslogs-group         = aws_cloudwatch_log_group.mlflow.name,
          awslogs-region        = var.aws_region,
          awslogs-stream-prefix = "mlflow"
        }
      }
    }
  ])

  tags = var.tags
}

resource "aws_ecs_service" "mlflow" {
  name            = "${var.platform_name}-${var.environment}-mlflow-svc"
  cluster         = aws_ecs_cluster.mlflow.id
  task_definition = aws_ecs_task_definition.mlflow.arn
  launch_type     = "FARGATE"
  desired_count   = var.mlflow_desired_count

  network_configuration {
    subnets         = module.vpc.private_subnets
    security_groups = [aws_security_group.mlflow_sg.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.mlflow.arn
    container_name   = "mlflow"
    container_port   = 5000
  }

  depends_on = [aws_lb_listener.mlflow]
  tags       = var.tags
}

#############################################
# Variables
#############################################

variable "aws_region" { type = string default = "us-east-1" }

variable "platform_name" { type = string default = "ml-platform" }
variable "environment"   { type = string default = "dev" }

variable "vpc_cidr" { type = string default = "10.50.0.0/16" }

# Provide exact subnet CIDRs (example values)
variable "private_subnets" {
  type    = list(string)
  default = ["10.50.0.0/20", "10.50.16.0/20", "10.50.32.0/20"]
}

variable "public_subnets" {
  type    = list(string)
  default = ["10.50.128.0/20", "10.50.144.0/20", "10.50.160.0/20"]
}

variable "eks_cluster_version" {
  type    = string
  default = "1.29"
}

variable "eks_node_instance_types" {
  type    = list(string)
  default = ["m6i.large"]
}

variable "eks_node_min"     { type = number default = 1 }
variable "eks_node_max"     { type = number default = 3 }
variable "eks_node_desired" { type = number default = 1 }

variable "jenkins_chart_version" {
  type    = string
  default = "5.7.12"
}

variable "jenkins_admin_user" {
  type    = string
  default = "admin"
}

variable "jenkins_admin_password" {
  type      = string
  sensitive = true
}

variable "jenkins_service_type" {
  type    = string
  default = "LoadBalancer"
}

variable "jenkins_pvc_size" {
  type    = string
  default = "20Gi"
}

# MWAA
variable "mwaa_airflow_version" {
  type    = string
  default = "2.8.1"
}

variable "mwaa_environment_class" {
  type    = string
  default = "mw1.small"
}

variable "mwaa_dag_s3_path" {
  type    = string
  default = "dags"
}

variable "mwaa_plugins_s3_path" {
  type    = string
  default = "plugins/plugins.zip"
}

variable "mwaa_requirements_s3_path" {
  type    = string
  default = "requirements/requirements.txt"
}

variable "mwaa_min_workers" { type = number default = 1 }
variable "mwaa_max_workers" { type = number default = 5 }
variable "mwaa_schedulers"  { type = number default = 2 }

# MLflow
variable "mlflow_image" {
  type    = string
  default = "ghcr.io/mlflow/mlflow:v2.12.2"
}

variable "mlflow_desired_count" { type = number default = 1 }
variable "mlflow_task_cpu"      { type = number default = 512 }
variable "mlflow_task_memory"   { type = number default = 1024 }

variable "mlflow_db_engine_version"   { type = string default = "15.5" }
variable "mlflow_db_instance_class"   { type = string default = "db.t4g.micro" }
variable "mlflow_db_allocated_storage" { type = number default = 20 }
variable "mlflow_db_username"         { type = string default = "mlflow" }
variable "mlflow_db_password"         { type = string sensitive = true }
variable "mlflow_db_name"             { type = string default = "mlflow" }

variable "tags" {
  type = map(string)
  default = {
    owner = "platform"
    repo  = "ml-platform"
  }
}

#############################################
# Outputs
#############################################

output "jenkins_irsa_role_arn" {
  value = aws_iam_role.jenkins_irsa.arn
}

output "mwaa_name" {
  value = aws_mwaa_environment.this.name
}

output "mwaa_source_bucket" {
  value = aws_s3_bucket.mwaa_source.bucket
}

output "mlflow_internal_url" {
  value = "http://${aws_lb.mlflow.dns_name}:5000"
}

output "mlflow_artifacts_bucket" {
  value = aws_s3_bucket.mlflow_artifacts.bucket
}