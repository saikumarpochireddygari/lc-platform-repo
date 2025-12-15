# (reuse providers.tf from 20-eks-addons)

data "terraform_remote_state" "foundation" {
  backend = "s3"
  config = {
    bucket = "REPLACE_ME_TFSTATE_BUCKET"
    key    = "prod/us-east-1/foundation/terraform.tfstate"
    region = "us-east-1"
  }
}

resource "kubernetes_namespace" "mlflow" {
  metadata { name = "mlflow" }
}

# IRSA for S3 artifacts
resource "aws_iam_policy" "mlflow_s3" {
  name = "${var.env}-mlflow-s3-artifacts"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:ListBucket"]
      Resource = ["arn:aws:s3:::${data.terraform_remote_state.foundation.outputs.mlflow_artifacts_bucket}"]
    },{
      Effect   = "Allow"
      Action   = ["s3:GetObject","s3:PutObject","s3:DeleteObject"]
      Resource = ["arn:aws:s3:::${data.terraform_remote_state.foundation.outputs.mlflow_artifacts_bucket}/*"]
    }]
  })
}

module "mlflow_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.0"

  role_name = "${var.env}-mlflow"

  oidc_providers = {
    main = {
      provider_arn               = data.terraform_remote_state.foundation.outputs.eks_oidc_provider_arn
      namespace_service_accounts = ["mlflow:mlflow"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "mlflow_s3_attach" {
  role      = module.mlflow_irsa.iam_role_name
  policy_arn = aws_iam_policy.mlflow_s3.arn
}

resource "kubernetes_service_account" "mlflow" {
  metadata {
    name      = "mlflow"
    namespace = kubernetes_namespace.mlflow.metadata[0].name
    annotations = { "eks.amazonaws.com/role-arn" = module.mlflow_irsa.iam_role_arn }
  }
}

locals {
  mlflow_host = "mlflow.${trim(data.terraform_remote_state.foundation.outputs.private_domain, ".")}"
  backend_uri = "postgresql://${var.mlflow_db_username}:${var.mlflow_db_password}@${data.terraform_remote_state.foundation.outputs.mlflow_db_host}:${data.terraform_remote_state.foundation.outputs.mlflow_db_port}/${var.mlflow_db_name}"
}

resource "helm_release" "mlflow" {
  name       = "mlflow"
  namespace  = kubernetes_namespace.mlflow.metadata[0].name
  repository = "https://community-charts.github.io/helm-charts"
  chart      = "mlflow"
  version    = "0.16.2"

  set { name = "serviceAccount.create", value = "false" }
  set { name = "serviceAccount.name",   value = kubernetes_service_account.mlflow.metadata[0].name }

  set { name = "extraEnvVars[0].name", value = "MLFLOW_BACKEND_STORE_URI" }
  set { name = "extraEnvVars[0].value", value = local.backend_uri }

  set { name = "extraEnvVars[1].name", value = "MLFLOW_DEFAULT_ARTIFACT_ROOT" }
  set { name = "extraEnvVars[1].value", value = "s3://${data.terraform_remote_state.foundation.outputs.mlflow_artifacts_bucket}" }

  # INTERNAL ALB
  set { name = "ingress.enabled", value = "true" }
  set { name = "ingress.ingressClassName", value = "alb" }
  set { name = "ingress.annotations.alb\\.ingress\\.kubernetes\\.io/scheme", value = "internal" }
  set { name = "ingress.annotations.alb\\.ingress\\.kubernetes\\.io/target-type", value = "ip" }
  set { name = "ingress.annotations.external-dns\\.alpha\\.kubernetes\\.io/hostname", value = local.mlflow_host }
}