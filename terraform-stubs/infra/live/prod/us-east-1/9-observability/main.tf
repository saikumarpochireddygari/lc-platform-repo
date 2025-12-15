data "aws_eks_node_group" "core" {
  cluster_name    = data.terraform_remote_state.foundation.outputs.eks_cluster_name
  node_group_name = var.node_group_name
}

# CloudWatch agent permissions (simplest + supported path)
resource "aws_iam_role_policy_attachment" "cw_agent_on_nodes" {
  role       = regex("role/(.+)$", data.aws_eks_node_group.core.node_role_arn)[0]
  policy_arn  = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# Enable CloudWatch Observability add-on (installs CW agent + fluent-bit)
# AWS supports this add-on for enabling Container Insights  [oai_citation:2‡AWS Documentation](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/install-CloudWatch-Observability-EKS-addon.html?utm_source=chatgpt.com)
resource "aws_eks_addon" "cw_observability" {
  cluster_name  = data.terraform_remote_state.foundation.outputs.eks_cluster_name
  addon_name    = "amazon-cloudwatch-observability"

  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"
}

# Pre-create log groups to enforce retention
# (Container Insights uses these standard names)
locals {
  cluster_name = data.terraform_remote_state.foundation.outputs.eks_cluster_name
  ci_groups = [
    "/aws/containerinsights/${local.cluster_name}/application",
    "/aws/containerinsights/${local.cluster_name}/dataplane",
    "/aws/containerinsights/${local.cluster_name}/host",
    "/aws/containerinsights/${local.cluster_name}/performance",
  ]
}

resource "aws_cloudwatch_log_group" "container_insights" {
  for_each          = toset(local.ci_groups)
  name              = each.value
  retention_in_days = var.container_insights_log_retention_days
}

# Optional alerts: SNS topic + subscription (only if alarm_email provided)
resource "aws_sns_topic" "alarms" {
  count = var.alarm_email != "" ? 1 : 0
  name  = "${var.env}-platform-alarms"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alarm_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alarms[0].arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

# Example alarm: node CPU utilization (Container Insights publishes these metrics)  [oai_citation:3‡AWS Documentation](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Container-Insights-metrics-EKS.html?utm_source=chatgpt.com)
resource "aws_cloudwatch_metric_alarm" "node_cpu_high" {
  count               = var.alarm_email != "" ? 1 : 0
  alarm_name          = "${var.env}-${local.cluster_name}-node-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  period              = 300
  threshold           = 80
  statistic           = "Average"
  namespace           = "ContainerInsights"
  metric_name         = "node_cpu_utilization"
  dimensions = {
    ClusterName = local.cluster_name
  }

  alarm_actions = [aws_sns_topic.alarms[0].arn]
}