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
}