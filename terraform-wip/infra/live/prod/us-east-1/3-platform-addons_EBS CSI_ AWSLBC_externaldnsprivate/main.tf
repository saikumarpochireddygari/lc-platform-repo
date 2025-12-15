# ---- EBS CSI Driver (for PVs: Jenkins, etc) ----
module "ebs_csi_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.0"

  role_name                      = "${var.env}-ebs-csi"
  attach_ebs_csi_policy          = true

  oidc_providers = {
    main = {
      provider_arn               = data.terraform_remote_state.foundation.outputs.eks_oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa"]
    }
  }
}

resource "helm_release" "ebs_csi" {
  name       = "aws-ebs-csi-driver"
  namespace  = "kube-system"
  repository = "https://kubernetes-sigs.github.io/aws-ebs-csi-driver"
  chart      = "aws-ebs-csi-driver"
  version    = "2.36.0"

  set { name = "controller.serviceAccount.create", value = "true" }
  set { name = "controller.serviceAccount.name",   value = "ebs-csi-controller-sa" }
  set { name = "controller.serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn", value = module.ebs_csi_irsa.iam_role_arn }
}

# ---- AWS Load Balancer Controller (internal ALBs) ----
module "lbc_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.0"

  role_name                             = "${var.env}-aws-load-balancer-controller"
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    main = {
      provider_arn               = data.terraform_remote_state.foundation.outputs.eks_oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }
}

resource "kubernetes_service_account" "lbc" {
  metadata {
    name      = "aws-load-balancer-controller"
    namespace = "kube-system"
    annotations = { "eks.amazonaws.com/role-arn" = module.lbc_irsa.iam_role_arn }
  }
}

resource "helm_release" "lbc" {
  name       = "aws-load-balancer-controller"
  namespace  = "kube-system"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  version    = "1.8.1"

  set { name = "clusterName", value = data.terraform_remote_state.foundation.outputs.eks_cluster_name }
  set { name = "serviceAccount.create", value = "false" }
  set { name = "serviceAccount.name",   value = kubernetes_service_account.lbc.metadata[0].name }
}

# ---- ExternalDNS (writes records into the private hosted zone) ----
resource "aws_iam_policy" "externaldns" {
  name = "${var.env}-externaldns-private"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Action = ["route53:ChangeResourceRecordSets"],
      Resource = ["arn:aws:route53:::hostedzone/${data.terraform_remote_state.foundation.outputs.private_zone_id}"]
    },{
      Effect = "Allow",
      Action = ["route53:ListHostedZones", "route53:ListResourceRecordSets"],
      Resource = ["*"]
    }]
  })
}

module "externaldns_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.0"

  role_name = "${var.env}-externaldns"

  oidc_providers = {
    main = {
      provider_arn               = data.terraform_remote_state.foundation.outputs.eks_oidc_provider_arn
      namespace_service_accounts = ["kube-system:external-dns"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "externaldns_attach" {
  role       = module.externaldns_irsa.iam_role_name
  policy_arn  = aws_iam_policy.externaldns.arn
}

resource "kubernetes_service_account" "externaldns" {
  metadata {
    name      = "external-dns"
    namespace = "kube-system"
    annotations = { "eks.amazonaws.com/role-arn" = module.externaldns_irsa.iam_role_arn }
  }
}

resource "helm_release" "externaldns" {
  name       = "external-dns"
  namespace  = "kube-system"
  repository = "https://kubernetes-sigs.github.io/external-dns/"
  chart      = "external-dns"
  version    = "1.15.0"

  set { name = "serviceAccount.create", value = "false" }
  set { name = "serviceAccount.name", value = kubernetes_service_account.externaldns.metadata[0].name }

  set { name = "provider", value = "aws" }
  set { name = "policy", value = "sync" }

  # only manage the private zone domain
  set { name = "domainFilters[0]", value = trim(data.terraform_remote_state.foundation.outputs.private_domain, ".") }
  set { name = "txtOwnerId", value = data.terraform_remote_state.foundation.outputs.private_zone_id }
}