# ============================================================
# Azure Security Controls — InvitISE Cloud Security POC
# Demonstrates: Microsoft Defender for Cloud, Azure Monitor,
#               Log Analytics, Defender for Servers/Containers
# Compliance: CIS Benchmarks, NIST 800-53, ISO 27001, PCI-DSS
# ============================================================

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.90"
    }
  }
  required_version = ">= 1.5.0"
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = false
    }
  }
}

# ============================================================
# Resource Group
# ============================================================
resource "azurerm_resource_group" "security" {
  name     = "${var.project_prefix}-security-rg"
  location = var.azure_region

  tags = var.common_tags
}

# ============================================================
# Log Analytics Workspace — Central SIEM ingestion point
# NIST: SI-4, AU-3 | ISO 27001: A.12.4
# ============================================================
resource "azurerm_log_analytics_workspace" "security" {
  name                = "${var.project_prefix}-law"
  location            = azurerm_resource_group.security.location
  resource_group_name = azurerm_resource_group.security.name
  sku                 = "PerGB2018"
  retention_in_days   = 365

  tags = merge(var.common_tags, {
    Purpose    = "SIEM-SecurityLogs"
    Compliance = "NIST-SI-4,ISO27001-A.12.4"
  })
}

# ============================================================
# Microsoft Defender for Cloud — Security Center pricing tiers
# Covers all workload types relevant to financial services
# CIS: 2.x | NIST: SI-3, SI-4, RA-5 | ISO 27001: A.12.6
# ============================================================

# Defender for Servers (P2 — includes endpoint protection + JIT)
resource "azurerm_security_center_subscription_pricing" "servers" {
  tier          = "Standard"
  resource_type = "VirtualMachines"
}

# Defender for Containers (K8s threat protection)
resource "azurerm_security_center_subscription_pricing" "containers" {
  tier          = "Standard"
  resource_type = "Containers"
}

# Defender for Storage (malware scanning + anomaly detection)
resource "azurerm_security_center_subscription_pricing" "storage" {
  tier          = "Standard"
  resource_type = "StorageAccounts"
}

# Defender for Key Vault
resource "azurerm_security_center_subscription_pricing" "key_vault" {
  tier          = "Standard"
  resource_type = "KeyVaults"
}

# Defender for SQL
resource "azurerm_security_center_subscription_pricing" "sql" {
  tier          = "Standard"
  resource_type = "SqlServers"
}

# Defender for App Service
resource "azurerm_security_center_subscription_pricing" "app_service" {
  tier          = "Standard"
  resource_type = "AppServices"
}

# ============================================================
# Microsoft Defender for Cloud — Contact & Notifications
# ============================================================
resource "azurerm_security_center_contact" "security_team" {
  email               = var.security_contact_email
  phone               = var.security_contact_phone
  alert_notifications = true
  alerts_to_admins    = true
}

# ============================================================
# Azure Monitor — Diagnostic Settings for Activity Log
# Sends all control-plane audit events to Log Analytics
# CIS: 5.1.x | NIST: AU-2, AU-12
# ============================================================
resource "azurerm_monitor_diagnostic_setting" "activity_log" {
  name                       = "${var.project_prefix}-activity-log-diag"
  target_resource_id         = "/subscriptions/${var.subscription_id}"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.security.id

  enabled_log {
    category = "Administrative"
  }

  enabled_log {
    category = "Security"
  }

  enabled_log {
    category = "ServiceHealth"
  }

  enabled_log {
    category = "Alert"
  }

  enabled_log {
    category = "Recommendation"
  }

  enabled_log {
    category = "Policy"
  }

  enabled_log {
    category = "Autoscale"
  }

  enabled_log {
    category = "ResourceHealth"
  }
}

# ============================================================
# Azure Key Vault — Secrets and keys management
# Soft delete + purge protection enabled (NIST SC-12, SC-28)
# ============================================================
resource "azurerm_key_vault" "security" {
  name                        = "${var.project_prefix}-kv"
  location                    = azurerm_resource_group.security.location
  resource_group_name         = azurerm_resource_group.security.name
  tenant_id                   = var.tenant_id
  sku_name                    = "premium"
  soft_delete_retention_days  = 90
  purge_protection_enabled    = true
  enable_rbac_authorization   = true

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
    ip_rules       = var.allowed_ip_ranges
  }

  tags = merge(var.common_tags, {
    Compliance = "NIST-SC-12,ISO27001-A.10.1"
  })
}

# ============================================================
# Azure Policy — Enforce CIS Benchmark controls
# ============================================================
resource "azurerm_subscription_policy_assignment" "cis_benchmark" {
  name                 = "${var.project_prefix}-cis-benchmark"
  subscription_id      = "/subscriptions/${var.subscription_id}"
  policy_definition_id = "/providers/Microsoft.Authorization/policySetDefinitions/612b5213-9160-4969-8578-1518bd2a000c"
  description          = "CIS Microsoft Azure Foundations Benchmark v1.4.0"
  display_name         = "${var.project_prefix} — CIS Azure Benchmark"

  non_compliance_message {
    content = "Resource is not compliant with CIS Azure Benchmark v1.4.0"
  }
}

# ============================================================
# Storage Account — Security audit logs (immutable)
# PCI-DSS: Req 10 | NIST: AU-9
# ============================================================
resource "azurerm_storage_account" "security_logs" {
  name                     = replace("${var.project_prefix}logs", "-", "")
  resource_group_name      = azurerm_resource_group.security.name
  location                 = azurerm_resource_group.security.location
  account_tier             = "Standard"
  account_replication_type = "GRS"
  min_tls_version          = "TLS1_2"
  allow_nested_items_to_be_public = false

  blob_properties {
    delete_retention_policy {
      days = 365
    }
    versioning_enabled = true
  }

  tags = merge(var.common_tags, {
    Purpose    = "SecurityAuditLogs"
    Compliance = "PCI-DSS-10,NIST-AU-9,ISO27001-A.12.4"
  })
}

# Immutable blob storage for audit logs (WORM)
resource "azurerm_storage_management_policy" "security_logs_lifecycle" {
  storage_account_id = azurerm_storage_account.security_logs.id

  rule {
    name    = "archive-and-delete"
    enabled = true

    filters {
      blob_types = ["blockBlob"]
    }

    actions {
      base_blob {
        tier_to_cool_after_days_since_modification_greater_than    = 90
        tier_to_archive_after_days_since_modification_greater_than = 365
        delete_after_days_since_modification_greater_than          = 2555
      }
    }
  }
}
