# ============================================================
# AWS Security Controls — InvitISE Cloud Security POC
# Demonstrates: SecurityHub, GuardDuty, CloudTrail, KMS, VPC
# Compliance: CIS Benchmarks, AWS Foundational Security, NIST 800-53
# ============================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  required_version = ">= 1.5.0"
}

provider "aws" {
  region = var.aws_region
}

# ============================================================
# KMS — Customer Managed Key with automatic rotation
# NIST: SC-12, SC-28 | CIS: 3.8
# ============================================================
resource "aws_kms_key" "security_cmk" {
  description             = "CMK for InvitISE platform security — CloudTrail, GuardDuty findings"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  multi_region            = false

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudTrail to use key"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(var.common_tags, {
    Name       = "${var.project_prefix}-security-cmk"
    Compliance = "CIS-3.8,NIST-SC-28"
  })
}

resource "aws_kms_alias" "security_cmk_alias" {
  name          = "alias/${var.project_prefix}-security-cmk"
  target_key_id = aws_kms_key.security_cmk.key_id
}

# ============================================================
# AWS Security Hub — Centralised findings aggregation
# Standards: AWS Foundational Security Best Practices + CIS Benchmarks
# NIST: SI-4, CA-7 | CIS: 4.x
# ============================================================
resource "aws_securityhub_account" "main" {
  enable_default_standards = false

  tags = merge(var.common_tags, {
    Name       = "${var.project_prefix}-securityhub"
    Compliance = "CIS,NIST-SI-4,ISO27001-A.12.6"
  })
}

resource "aws_securityhub_standards_subscription" "aws_foundational" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
}

resource "aws_securityhub_standards_subscription" "cis_benchmarks" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/cis-aws-foundations-benchmark/v/1.4.0"
}

resource "aws_securityhub_standards_subscription" "pci_dss" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/pci-dss/v/3.2.1"
}

# Security Hub action target — auto-remediation via Lambda
resource "aws_securityhub_action_target" "auto_remediate" {
  depends_on  = [aws_securityhub_account.main]
  name        = "${var.project_prefix}-auto-remediate"
  identifier  = "AutoRemediate"
  description = "Trigger automated remediation Lambda for critical findings"
}

# ============================================================
# Amazon GuardDuty — Threat detection with ML
# NIST: SI-3, SI-4 | CIS: 4.x | PCI-DSS: Req 10, 11
# ============================================================
resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  finding_publishing_frequency = "FIFTEEN_MINUTES"

  tags = merge(var.common_tags, {
    Name       = "${var.project_prefix}-guardduty"
    Compliance = "NIST-SI-4,PCI-DSS-10,ISO27001-A.12.4"
  })
}

# GuardDuty publishing to S3 (findings archive)
resource "aws_guardduty_publishing_destination" "findings_s3" {
  detector_id     = aws_guardduty_detector.main.id
  destination_arn = aws_s3_bucket.security_logs.arn
  kms_key_arn     = aws_kms_key.security_cmk.arn

  depends_on = [aws_s3_bucket_policy.security_logs]
}

# ============================================================
# CloudTrail — Multi-region audit logging
# NIST: AU-2, AU-3, AU-12 | CIS: 2.1-2.9 | PCI-DSS: Req 10
# ============================================================
resource "aws_cloudtrail" "main" {
  name                          = "${var.project_prefix}-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.security_logs.id
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.security_cmk.arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cloudwatch.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }

    data_resource {
      type   = "AWS::Lambda::Function"
      values = ["arn:aws:lambda"]
    }
  }

  insight_selector {
    insight_type = "ApiCallRateInsight"
  }

  insight_selector {
    insight_type = "ApiErrorRateInsight"
  }

  tags = merge(var.common_tags, {
    Name       = "${var.project_prefix}-cloudtrail"
    Compliance = "CIS-2.1,NIST-AU-2,PCI-DSS-10"
  })

  depends_on = [
    aws_s3_bucket_policy.security_logs,
    aws_cloudwatch_log_group.cloudtrail
  ]
}

# ============================================================
# CloudWatch Log Group — CloudTrail destination
# ============================================================
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${var.project_prefix}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.security_cmk.arn

  tags = merge(var.common_tags, {
    Name = "${var.project_prefix}-cloudtrail-logs"
  })
}

# CloudWatch metric filters for CIS Benchmark controls
resource "aws_cloudwatch_metric_filter" "root_account_usage" {
  name           = "${var.project_prefix}-root-account-usage"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"

  metric_transformation {
    name      = "RootAccountUsageCount"
    namespace = "${var.project_prefix}/SecurityMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_alarm" "root_account_usage" {
  alarm_name          = "${var.project_prefix}-root-account-usage"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "RootAccountUsageCount"
  namespace           = "${var.project_prefix}/SecurityMetrics"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "CIS 3.3 — Root account usage detected"
  alarm_actions       = []

  tags = merge(var.common_tags, {
    Compliance = "CIS-3.3,NIST-AC-6"
  })
}

resource "aws_cloudwatch_metric_filter" "unauthorized_api_calls" {
  name           = "${var.project_prefix}-unauthorized-api"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($.errorCode = \"*UnauthorizedAccess*\") || ($.errorCode = \"AccessDenied*\") }"

  metric_transformation {
    name      = "UnauthorizedApiCallCount"
    namespace = "${var.project_prefix}/SecurityMetrics"
    value     = "1"
  }
}

# ============================================================
# IAM — Hardened role for CloudTrail → CloudWatch
# NIST: AC-2, AC-3, AC-6 | CIS: 1.x
# ============================================================
resource "aws_iam_role" "cloudtrail_cloudwatch" {
  name = "${var.project_prefix}-cloudtrail-cloudwatch-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "cloudtrail.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = merge(var.common_tags, {
    Name       = "${var.project_prefix}-cloudtrail-role"
    Compliance = "CIS-1.x,NIST-AC-6"
  })
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch_policy" {
  name = "${var.project_prefix}-cloudtrail-cloudwatch-policy"
  role = aws_iam_role.cloudtrail_cloudwatch.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    }]
  })
}

# IAM Password Policy (CIS 1.5-1.11)
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
}

# ============================================================
# S3 — Security logs bucket (encrypted, versioned, access logs)
# NIST: AU-9, SC-28 | CIS: 2.3, 2.6
# ============================================================
resource "aws_s3_bucket" "security_logs" {
  bucket        = "${var.project_prefix}-security-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = false

  tags = merge(var.common_tags, {
    Name       = "${var.project_prefix}-security-logs"
    Compliance = "CIS-2.3,NIST-AU-9,ISO27001-A.12.4"
  })
}

resource "aws_s3_bucket_versioning" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.security_cmk.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "security_logs" {
  bucket                  = aws_s3_bucket.security_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id

  rule {
    id     = "archive-old-logs"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 365
      storage_class = "GLACIER"
    }

    expiration {
      days = 2555 # 7 years for PCI-DSS compliance
    }
  }
}

resource "aws_s3_bucket_policy" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyNonTLS"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:*"
        Resource = [
          aws_s3_bucket.security_logs.arn,
          "${aws_s3_bucket.security_logs.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid    = "AllowCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.security_logs.arn}/cloudtrail/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"               = "bucket-owner-full-control"
            "aws:SourceAccount"           = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AllowCloudTrailGetACL"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.security_logs.arn
      },
      {
        Sid    = "AllowGuardDutyPublish"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.security_logs.arn}/guardduty/*"
      }
    ]
  })
}

# ============================================================
# VPC Flow Logs — Network traffic analysis
# NIST: SI-4, AU-3 | CIS: 2.9 | PCI-DSS: Req 10
# ============================================================
resource "aws_flow_log" "vpc_flow_logs" {
  iam_role_arn    = aws_iam_role.vpc_flow_logs.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.secure_vpc.id

  tags = merge(var.common_tags, {
    Name       = "${var.project_prefix}-vpc-flow-logs"
    Compliance = "CIS-2.9,NIST-SI-4,PCI-DSS-10"
  })
}

resource "aws_vpc" "secure_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(var.common_tags, {
    Name = "${var.project_prefix}-secure-vpc"
  })
}

resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/vpc-flow-logs/${var.project_prefix}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.security_cmk.arn

  tags = var.common_tags
}

resource "aws_iam_role" "vpc_flow_logs" {
  name = "${var.project_prefix}-vpc-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = var.common_tags
}

resource "aws_iam_role_policy" "vpc_flow_logs" {
  name = "${var.project_prefix}-vpc-flow-logs-policy"
  role = aws_iam_role.vpc_flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Resource = "*"
    }]
  })
}

# ============================================================
# Data sources
# ============================================================
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
