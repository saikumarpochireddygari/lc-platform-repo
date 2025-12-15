# -----------------------
# KMS + S3 bucket for audit logs (CloudTrail + Config snapshots)
# -----------------------
resource "aws_kms_key" "audit" {
  description             = "KMS key for audit logs"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_s3_bucket" "audit" {
  bucket = "${var.env}-audit-logs-${data.aws_caller_identity.me.account_id}"
}

resource "aws_s3_bucket_public_access_block" "audit" {
  bucket                  = aws_s3_bucket.audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.audit.arn
    }
  }
}

# CloudTrail requires a bucket policy
data "aws_iam_policy_document" "audit_bucket_policy" {
  statement {
    sid     = "CloudTrailAclCheck"
    effect  = "Allow"
    actions = ["s3:GetBucketAcl"]
    principals { type = "Service", identifiers = ["cloudtrail.amazonaws.com"] }
    resources = [aws_s3_bucket.audit.arn]
  }

  statement {
    sid     = "CloudTrailWrite"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    principals { type = "Service", identifiers = ["cloudtrail.amazonaws.com"] }
    resources = ["${aws_s3_bucket.audit.arn}/AWSLogs/${data.aws_caller_identity.me.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "audit" {
  bucket = aws_s3_bucket.audit.id
  policy = data.aws_iam_policy_document.audit_bucket_policy.json
}

# -----------------------
# CloudTrail (management events)
# -----------------------
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${var.env}"
  retention_in_days = var.cloudtrail_log_retention_days
}

resource "aws_iam_role" "cloudtrail_to_cw" {
  name = "${var.env}-cloudtrail-to-cloudwatch"
  assume_role_policy = jsonencode({
    Version="2012-10-17",
    Statement=[{
      Effect="Allow",
      Principal={ Service="cloudtrail.amazonaws.com" },
      Action="sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "cloudtrail_to_cw" {
  role = aws_iam_role.cloudtrail_to_cw.id
  policy = jsonencode({
    Version="2012-10-17",
    Statement=[{
      Effect="Allow",
      Action=["logs:CreateLogStream","logs:PutLogEvents"],
      Resource="${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    }]
  })
}

resource "aws_cloudtrail" "this" {
  name                          = "${var.env}-trail"
  s3_bucket_name                = aws_s3_bucket.audit.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.audit.arn

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_to_cw.arn
}

# -----------------------
# AWS Config (baseline recorder + delivery)
# -----------------------
resource "aws_iam_role" "config" {
  name = "${var.env}-aws-config"
  assume_role_policy = jsonencode({
    Version="2012-10-17",
    Statement=[{
      Effect="Allow",
      Principal={ Service="config.amazonaws.com" },
      Action="sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config_managed" {
  role       = aws_iam_role.config.name
  policy_arn  = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "recorder" {
  name     = "${var.env}-recorder"
  role_arn  = aws_iam_role.config.arn
  recording_group { all_supported = true, include_global_resource_types = true }
}

resource "aws_config_delivery_channel" "channel" {
  name           = "${var.env}-channel"
  s3_bucket_name = aws_s3_bucket.audit.bucket
  depends_on     = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_configuration_recorder_status" "status" {
  name       = aws_config_configuration_recorder.recorder.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.channel]
}

# -----------------------
# GuardDuty + Security Hub + Access Analyzer
# -----------------------
resource "aws_guardduty_detector" "this" {
  enable = true
}

resource "aws_securityhub_account" "this" {}

resource "aws_accessanalyzer_analyzer" "this" {
  analyzer_name = "${var.env}-access-analyzer"
  type          = "ACCOUNT"
}

# -----------------------
# VPC Flow Logs -> CloudWatch
# -----------------------
resource "aws_cloudwatch_log_group" "flowlogs" {
  name              = "/aws/vpc/flowlogs/${var.env}"
  retention_in_days = var.flowlogs_retention_days
}

resource "aws_iam_role" "flowlogs" {
  name = "${var.env}-vpc-flowlogs"
  assume_role_policy = jsonencode({
    Version="2012-10-17",
    Statement=[{
      Effect="Allow",
      Principal={ Service="vpc-flow-logs.amazonaws.com" },
      Action="sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "flowlogs" {
  role = aws_iam_role.flowlogs.id
  policy = jsonencode({
    Version="2012-10-17",
    Statement=[{
      Effect="Allow",
      Action=["logs:CreateLogStream","logs:PutLogEvents"],
      Resource="${aws_cloudwatch_log_group.flowlogs.arn}:*"
    }]
  })
}

resource "aws_flow_log" "vpc" {
  iam_role_arn    = aws_iam_role.flowlogs.arn
  log_destination = aws_cloudwatch_log_group.flowlogs.arn
  traffic_type    = "ALL"
  vpc_id          = data.terraform_remote_state.foundation.outputs.vpc_id
}

# -----------------------
# ECR registry scanning defaults (good security baseline)
# -----------------------
resource "aws_ecr_registry_scanning_configuration" "this" {
  scan_type = "ENHANCED"
  rule {
    scan_frequency = "CONTINUOUS_SCAN"
    repository_filter {
      filter      = "*"
      filter_type = "WILDCARD"
    }
  }
}

# -----------------------
# Optional: WAFv2 (associate with your internal ALB ARNs)
# -----------------------
resource "aws_wafv2_web_acl" "this" {
  count = var.enable_waf ? 1 : 0

  name  = "${var.env}-internal-alb-waf"
  scope = "REGIONAL"

  default_action { allow {} }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.env}-waf"
    sampled_requests_enabled   = true
  }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CommonRuleSet"
      sampled_requests_enabled   = true
    }
  }
}

resource "aws_wafv2_web_acl_association" "albs" {
  for_each = var.enable_waf ? toset(var.alb_arns) : toset([])
  resource_arn = each.value
  web_acl_arn  = aws_wafv2_web_acl.this[0].arn
}