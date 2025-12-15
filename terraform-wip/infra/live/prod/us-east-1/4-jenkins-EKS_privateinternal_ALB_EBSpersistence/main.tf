data "terraform_remote_state" "foundation" {
  backend = "s3"
  config = {
    bucket = "REPLACE_ME_TFSTATE_BUCKET"
    key    = "prod/us-east-1/foundation/terraform.tfstate"
    region = "us-east-1"
  }
}

resource "kubernetes_namespace" "jenkins" {
  metadata { name = "jenkins" }
}

locals {
  jenkins_host = "jenkins.${trim(data.terraform_remote_state.foundation.outputs.private_domain, ".")}"
}

locals {
  jenkins_host    = "jenkins.${trim(data.terraform_remote_state.foundation.outputs.private_domain, ".")}"

  # ALB name must be <= 32 chars, unique per region/account
  jenkins_alb_name = "prod-jenkins-int"
}

locals {
  mlflow_host     = "mlflow.${trim(data.terraform_remote_state.foundation.outputs.private_domain, ".")}"

  # ALB name must be <= 32 chars, unique per region/account
  mlflow_alb_name = "prod-mlflow-int"

  backend_uri = "postgresql://${var.mlflow_db_username}:${var.mlflow_db_password}@${data.terraform_remote_state.foundation.outputs.mlflow_db_host}:${data.terraform_remote_state.foundation.outputs.mlflow_db_port}/${var.mlflow_db_name}"
}

resource "helm_release" "jenkins" {
  name       = "jenkins"
  namespace  = kubernetes_namespace.jenkins.metadata[0].name
  repository = "https://charts.jenkins.io"
  chart      = "jenkins"
  version    = "5.7.10"

  set { name = "controller.persistence.enabled", value = "true" }
  set { name = "controller.persistence.storageClass", value = "gp3" }
  set { name = "controller.persistence.size", value = "50Gi" }

  # Ingress (INTERNAL ALB)
  set { name = "controller.ingress.enabled", value = "true" }
  set { name = "controller.ingress.ingressClassName", value = "alb" }

  set { name = "controller.ingress.annotations.alb\\.ingress\\.kubernetes\\.io/scheme", value = "internal" }
  set { name = "controller.ingress.annotations.alb\\.ingress\\.kubernetes\\.io/target-type", value = "ip" }

  # ExternalDNS will create private record
  set { name = "controller.ingress.annotations.external-dns\\.alpha\\.kubernetes\\.io/hostname", value = local.jenkins_host }
  set {
  name  = "controller.ingress.annotations.alb\\.ingress\\.kubernetes\\.io/load-balancer-name"
  value = local.jenkins_alb_name
}
set {
  name  = "ingress.annotations.alb\\.ingress\\.kubernetes\\.io/load-balancer-name"
  value = local.mlflow_alb_name
}
}