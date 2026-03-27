variable "azure_region" {
  description = "Azure region for security resources"
  type        = string
  default     = "uksouth"
}

variable "project_prefix" {
  description = "Prefix for all Azure resource names"
  type        = string
  default     = "invitise-sec"
}

variable "subscription_id" {
  description = "Azure Subscription ID"
  type        = string
  sensitive   = true
}

variable "tenant_id" {
  description = "Azure Active Directory Tenant ID"
  type        = string
  sensitive   = true
}

variable "security_contact_email" {
  description = "Security team email for Defender for Cloud alerts"
  type        = string
  default     = "security@invitise.com"
}

variable "security_contact_phone" {
  description = "Security team phone for critical alerts"
  type        = string
  default     = "+44-20-0000-0000"
}

variable "allowed_ip_ranges" {
  description = "IP ranges allowed to access Key Vault"
  type        = list(string)
  default     = []
}

variable "common_tags" {
  description = "Common tags applied to all Azure resources"
  type        = map(string)
  default = {
    Project     = "invitise-cloud-security-poc"
    Environment = "poc"
    ManagedBy   = "terraform"
    Compliance  = "CIS,NIST800-53,ISO27001,PCI-DSS"
    Owner       = "security-team"
  }
}

variable "log_analytics_retention_days" {
  description = "Log retention in Log Analytics Workspace (days)"
  type        = number
  default     = 365

  validation {
    condition     = var.log_analytics_retention_days >= 90
    error_message = "Log retention must be at least 90 days for compliance."
  }
}
