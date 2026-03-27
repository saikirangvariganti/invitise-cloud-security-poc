output "securityhub_account_id" {
  description = "Security Hub account ID"
  value       = aws_securityhub_account.main.id
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = aws_guardduty_detector.main.id
}

output "cloudtrail_arn" {
  description = "CloudTrail ARN"
  value       = aws_cloudtrail.main.arn
}

output "cloudtrail_s3_bucket" {
  description = "S3 bucket storing CloudTrail logs"
  value       = aws_s3_bucket.security_logs.bucket
}

output "kms_key_arn" {
  description = "KMS CMK ARN used for encryption"
  value       = aws_kms_key.security_cmk.arn
  sensitive   = true
}

output "kms_key_id" {
  description = "KMS CMK key ID"
  value       = aws_kms_key.security_cmk.key_id
}

output "vpc_id" {
  description = "Secure VPC ID"
  value       = aws_vpc.secure_vpc.id
}

output "cloudwatch_log_group_cloudtrail" {
  description = "CloudWatch log group for CloudTrail"
  value       = aws_cloudwatch_log_group.cloudtrail.name
}

output "security_hub_standards" {
  description = "Enabled Security Hub compliance standards"
  value = {
    aws_foundational = aws_securityhub_standards_subscription.aws_foundational.standards_arn
    cis_benchmarks   = aws_securityhub_standards_subscription.cis_benchmarks.standards_arn
    pci_dss          = aws_securityhub_standards_subscription.pci_dss.standards_arn
  }
}
