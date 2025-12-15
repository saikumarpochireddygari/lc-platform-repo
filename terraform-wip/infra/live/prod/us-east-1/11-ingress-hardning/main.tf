resource "time_sleep" "wait_for_albs" {
  create_duration = "${var.discovery_wait_seconds}s"
}

data "aws_lb" "jenkins" {
  name       = var.jenkins_alb_name
  depends_on = [time_sleep.wait_for_albs]
}

data "aws_lb" "mlflow" {
  name       = var.mlflow_alb_name
  depends_on = [time_sleep.wait_for_albs]
}