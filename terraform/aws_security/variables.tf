variable "aws_region" {
  description = "AWS region to deploy security controls"
  type        = string
  default     = "eu-west-2"
}

variable "project_prefix" {
  description = "Prefix for all resource names"
  type        = string
  default     = "invitise-sec"
}

variable "vpc_cidr" {
  description = "CIDR block for the secure VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "common_tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default = {
    Project     = "invitise-cloud-security-poc"
    Environment = "poc"
    ManagedBy   = "terraform"
    Compliance  = "CIS,NIST800-53,ISO27001,PCI-DSS"
    Owner       = "security-team"
  }
}

variable "guardduty_finding_frequency" {
  description = "Frequency for GuardDuty finding publishing"
  type        = string
  default     = "FIFTEEN_MINUTES"

  validation {
    condition     = contains(["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"], var.guardduty_finding_frequency)
    error_message = "Finding frequency must be FIFTEEN_MINUTES, ONE_HOUR, or SIX_HOURS."
  }
}

variable "cloudtrail_log_retention_days" {
  description = "Number of days to retain CloudTrail logs in CloudWatch"
  type        = number
  default     = 365

  validation {
    condition     = var.cloudtrail_log_retention_days >= 90
    error_message = "Log retention must be at least 90 days for PCI-DSS compliance."
  }
}

variable "enable_security_hub_pci" {
  description = "Enable PCI-DSS Security Hub standard (required for fintech)"
  type        = bool
  default     = true
}
