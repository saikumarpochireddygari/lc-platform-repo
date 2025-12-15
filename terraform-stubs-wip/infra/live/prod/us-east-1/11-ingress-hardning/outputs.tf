output "jenkins_alb_arn" { value = data.aws_lb.jenkins.arn }
output "mlflow_alb_arn"  { value = data.aws_lb.mlflow.arn }

output "alb_arns" {
  value = [
    data.aws_lb.jenkins.arn,
    data.aws_lb.mlflow.arn
  ]
}