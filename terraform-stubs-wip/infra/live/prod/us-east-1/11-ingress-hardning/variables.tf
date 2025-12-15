variable "aws_region" { type = string, default = "us-east-1" }
variable "env"        { type = string, default = "prod" }

# Must match what you set in Jenkins/MLflow stacks
variable "jenkins_alb_name" { type = string, default = "prod-jenkins-int" }
variable "mlflow_alb_name"  { type = string, default = "prod-mlflow-int" }

# Wait for the controller to create ALBs (first-time deploys)
variable "discovery_wait_seconds" { type = number, default = 180 }