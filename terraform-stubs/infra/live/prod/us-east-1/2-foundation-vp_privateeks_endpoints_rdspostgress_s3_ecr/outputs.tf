output "vpc_id"             { value = module.vpc.vpc_id }
output "vpc_cidr"           { value = module.vpc.vpc_cidr_block }
output "private_subnet_ids" { value = module.vpc.private_subnets }

output "private_zone_id"    { value = aws_route53_zone.private.zone_id }
output "private_domain"     { value = aws_route53_zone.private.name }

output "eks_cluster_name"   { value = module.eks.cluster_name }
output "eks_oidc_provider_arn" { value = module.eks.oidc_provider_arn }
output "eks_cluster_endpoint"  { value = module.eks.cluster_endpoint }
output "eks_ca"                { value = module.eks.cluster_certificate_authority_data }

output "mlflow_artifacts_bucket" { value = aws_s3_bucket.mlflow_artifacts.bucket }
output "mlflow_db_host"          { value = aws_db_instance.mlflow.address }
output "mlflow_db_port"          { value = aws_db_instance.mlflow.port }

output "ecr_inference_repo_url"  { value = aws_ecr_repository.inference.repository_url }
output "ecr_training_repo_url"   { value = aws_ecr_repository.training.repository_url }