"""
test_invitise_cloud_security.py — InvitISE Cloud Security POC Test Suite

Validates repository structure, Terraform configurations, Kubernetes manifests,
OPA constraints, Falco rules, CI/CD pipeline, and compliance scripts.

Run: pytest tests/ -q --tb=short
"""

import json
import os
import sys
from pathlib import Path

import pytest
import yaml

# ============================================================
# Repository root fixture
# ============================================================
REPO_ROOT = Path(__file__).parent.parent


# ============================================================
# 1. REPOSITORY STRUCTURE
# ============================================================
class TestRepositoryStructure:
    """Verify all required directories and files exist."""

    def test_terraform_aws_security_dir_exists(self):
        assert (REPO_ROOT / "terraform" / "aws_security").is_dir(), \
            "terraform/aws_security directory must exist"

    def test_terraform_azure_security_dir_exists(self):
        assert (REPO_ROOT / "terraform" / "azure_security").is_dir(), \
            "terraform/azure_security directory must exist"

    def test_kubernetes_security_dir_exists(self):
        assert (REPO_ROOT / "kubernetes" / "security").is_dir(), \
            "kubernetes/security directory must exist"

    def test_scripts_dir_exists(self):
        assert (REPO_ROOT / "scripts").is_dir(), \
            "scripts directory must exist"

    def test_tests_dir_exists(self):
        assert (REPO_ROOT / "tests").is_dir(), \
            "tests directory must exist"

    def test_opa_constraints_dir_exists(self):
        assert (REPO_ROOT / "kubernetes" / "security" / "opa-constraints").is_dir(), \
            "kubernetes/security/opa-constraints directory must exist"

    def test_network_policies_dir_exists(self):
        assert (REPO_ROOT / "kubernetes" / "security" / "network-policies").is_dir(), \
            "kubernetes/security/network-policies directory must exist"

    def test_falco_dir_exists(self):
        assert (REPO_ROOT / "kubernetes" / "security" / "falco").is_dir(), \
            "kubernetes/security/falco directory must exist"

    def test_github_workflows_dir_exists(self):
        assert (REPO_ROOT / ".github" / "workflows").is_dir(), \
            ".github/workflows directory must exist"

    def test_readme_exists(self):
        assert (REPO_ROOT / "README.md").exists(), \
            "README.md must exist"


# ============================================================
# 2. AWS TERRAFORM CONFIGURATION
# ============================================================
class TestAWSTerraform:
    """Validate AWS Security Terraform configuration content."""

    @pytest.fixture(scope="class")
    def aws_main_tf(self):
        tf_path = REPO_ROOT / "terraform" / "aws_security" / "main.tf"
        assert tf_path.exists(), "terraform/aws_security/main.tf must exist"
        return tf_path.read_text(encoding="utf-8")

    @pytest.fixture(scope="class")
    def aws_variables_tf(self):
        tf_path = REPO_ROOT / "terraform" / "aws_security" / "variables.tf"
        assert tf_path.exists(), "terraform/aws_security/variables.tf must exist"
        return tf_path.read_text(encoding="utf-8")

    @pytest.fixture(scope="class")
    def aws_outputs_tf(self):
        tf_path = REPO_ROOT / "terraform" / "aws_security" / "outputs.tf"
        assert tf_path.exists(), "terraform/aws_security/outputs.tf must exist"
        return tf_path.read_text(encoding="utf-8")

    def test_aws_securityhub_account_present(self, aws_main_tf):
        assert "aws_securityhub_account" in aws_main_tf, \
            "main.tf must contain aws_securityhub_account resource (Security Hub enablement)"

    def test_aws_guardduty_detector_present(self, aws_main_tf):
        assert "aws_guardduty_detector" in aws_main_tf, \
            "main.tf must contain aws_guardduty_detector resource"

    def test_aws_cloudtrail_present(self, aws_main_tf):
        assert "aws_cloudtrail" in aws_main_tf, \
            "main.tf must contain aws_cloudtrail resource"

    def test_aws_kms_key_present(self, aws_main_tf):
        assert "aws_kms_key" in aws_main_tf, \
            "main.tf must contain aws_kms_key resource (CMK with rotation)"

    def test_cloudtrail_multi_region_enabled(self, aws_main_tf):
        assert "is_multi_region_trail" in aws_main_tf, \
            "CloudTrail must be configured as multi-region (CIS 2.1)"

    def test_cloudtrail_log_validation_enabled(self, aws_main_tf):
        assert "enable_log_file_validation" in aws_main_tf, \
            "CloudTrail must have log file validation enabled (CIS 2.2)"

    def test_kms_rotation_enabled(self, aws_main_tf):
        assert "enable_key_rotation" in aws_main_tf, \
            "KMS CMK must have automatic rotation enabled (CIS 3.8)"

    def test_guardduty_s3_protection(self, aws_main_tf):
        assert "s3_logs" in aws_main_tf, \
            "GuardDuty must have S3 protection enabled"

    def test_security_hub_cis_standard(self, aws_main_tf):
        assert "cis-aws-foundations-benchmark" in aws_main_tf, \
            "Security Hub must have CIS Benchmarks standard enabled"

    def test_vpc_flow_logs_present(self, aws_main_tf):
        assert "aws_flow_log" in aws_main_tf, \
            "VPC flow logs must be configured (CIS 2.9, NIST SI-4)"

    def test_iam_password_policy_present(self, aws_main_tf):
        assert "aws_iam_account_password_policy" in aws_main_tf, \
            "IAM hardening: password policy must be configured (CIS 1.5-1.11)"

    def test_outputs_file_has_securityhub_output(self, aws_outputs_tf):
        assert "securityhub" in aws_outputs_tf.lower(), \
            "outputs.tf must export Security Hub information"

    def test_outputs_file_has_guardduty_output(self, aws_outputs_tf):
        assert "guardduty" in aws_outputs_tf.lower(), \
            "outputs.tf must export GuardDuty information"


# ============================================================
# 3. AZURE TERRAFORM CONFIGURATION
# ============================================================
class TestAzureTerraform:
    """Validate Azure Defender for Cloud Terraform configuration."""

    @pytest.fixture(scope="class")
    def azure_main_tf(self):
        tf_path = REPO_ROOT / "terraform" / "azure_security" / "main.tf"
        assert tf_path.exists(), "terraform/azure_security/main.tf must exist"
        return tf_path.read_text(encoding="utf-8")

    def test_azure_defender_subscription_pricing_present(self, azure_main_tf):
        assert (
            "azurerm_security_center_subscription_pricing" in azure_main_tf
            or "azurerm_defender" in azure_main_tf
        ), "Azure Terraform must contain Defender for Cloud subscription pricing resource"

    def test_azure_defender_for_servers_present(self, azure_main_tf):
        assert "VirtualMachines" in azure_main_tf or "Servers" in azure_main_tf, \
            "Azure Defender for Servers must be configured"

    def test_azure_defender_for_containers_present(self, azure_main_tf):
        assert "Containers" in azure_main_tf, \
            "Azure Defender for Containers must be configured"

    def test_azure_log_analytics_workspace_present(self, azure_main_tf):
        assert "azurerm_log_analytics_workspace" in azure_main_tf, \
            "Azure Log Analytics Workspace must be configured for SIEM"

    def test_azure_monitor_diagnostic_settings_present(self, azure_main_tf):
        assert "azurerm_monitor_diagnostic_setting" in azure_main_tf, \
            "Azure Monitor diagnostic settings must be configured (CIS 5.1.x)"

    def test_azure_variables_file_exists(self):
        variables_path = REPO_ROOT / "terraform" / "azure_security" / "variables.tf"
        assert variables_path.exists(), "terraform/azure_security/variables.tf must exist"


# ============================================================
# 4. OPA GATEKEEPER CONSTRAINTS
# ============================================================
class TestOPAConstraints:
    """Validate OPA Gatekeeper constraint files."""

    def _load_all_yaml_docs(self, filepath: Path) -> list:
        """Load all YAML documents from a multi-document file."""
        content = filepath.read_text(encoding="utf-8")
        docs = list(yaml.safe_load_all(content))
        return [d for d in docs if d is not None]

    def test_require_readonly_rootfs_exists(self):
        assert (REPO_ROOT / "kubernetes" / "security" / "opa-constraints" / "require-readonly-rootfs.yaml").exists(), \
            "require-readonly-rootfs.yaml OPA constraint must exist"

    def test_deny_privileged_exists(self):
        assert (REPO_ROOT / "kubernetes" / "security" / "opa-constraints" / "deny-privileged.yaml").exists(), \
            "deny-privileged.yaml OPA constraint must exist"

    def test_require_resource_limits_exists(self):
        assert (REPO_ROOT / "kubernetes" / "security" / "opa-constraints" / "require-resource-limits.yaml").exists(), \
            "require-resource-limits.yaml OPA constraint must exist"

    def test_require_readonly_rootfs_valid_yaml(self):
        filepath = REPO_ROOT / "kubernetes" / "security" / "opa-constraints" / "require-readonly-rootfs.yaml"
        docs = self._load_all_yaml_docs(filepath)
        assert len(docs) >= 1, "require-readonly-rootfs.yaml must contain valid YAML"

    def test_deny_privileged_valid_yaml(self):
        filepath = REPO_ROOT / "kubernetes" / "security" / "opa-constraints" / "deny-privileged.yaml"
        docs = self._load_all_yaml_docs(filepath)
        assert len(docs) >= 1, "deny-privileged.yaml must contain valid YAML"

    def test_require_resource_limits_valid_yaml(self):
        filepath = REPO_ROOT / "kubernetes" / "security" / "opa-constraints" / "require-resource-limits.yaml"
        docs = self._load_all_yaml_docs(filepath)
        assert len(docs) >= 1, "require-resource-limits.yaml must contain valid YAML"

    def test_readonly_rootfs_contains_constraint_template(self):
        filepath = REPO_ROOT / "kubernetes" / "security" / "opa-constraints" / "require-readonly-rootfs.yaml"
        content = filepath.read_text(encoding="utf-8")
        assert "ConstraintTemplate" in content or "kind:" in content, \
            "require-readonly-rootfs.yaml must contain ConstraintTemplate or kind: declaration"

    def test_deny_privileged_contains_cis_relevant_name(self):
        filepath = REPO_ROOT / "kubernetes" / "security" / "opa-constraints" / "deny-privileged.yaml"
        content = filepath.read_text(encoding="utf-8")
        assert any(kw in content for kw in ["privileged", "Privileged", "privilege"]), \
            "deny-privileged.yaml must reference privilege-related controls (CIS 5.2.1)"

    def test_resource_limits_contains_cis_relevant_name(self):
        filepath = REPO_ROOT / "kubernetes" / "security" / "opa-constraints" / "require-resource-limits.yaml"
        content = filepath.read_text(encoding="utf-8")
        assert any(kw in content for kw in ["resource", "limits", "memory", "cpu"]), \
            "require-resource-limits.yaml must reference resource limits (CIS 5.6.4)"


# ============================================================
# 5. NETWORK POLICIES
# ============================================================
class TestNetworkPolicies:
    """Validate Kubernetes NetworkPolicy manifests."""

    def _load_all_yaml_docs(self, filepath: Path) -> list:
        content = filepath.read_text(encoding="utf-8")
        return [d for d in yaml.safe_load_all(content) if d is not None]

    def test_default_deny_all_exists(self):
        assert (REPO_ROOT / "kubernetes" / "security" / "network-policies" / "default-deny-all.yaml").exists(), \
            "default-deny-all.yaml NetworkPolicy must exist"

    def test_allow_app_ingress_exists(self):
        assert (REPO_ROOT / "kubernetes" / "security" / "network-policies" / "allow-app-ingress.yaml").exists(), \
            "allow-app-ingress.yaml NetworkPolicy must exist"

    def test_default_deny_all_valid_yaml(self):
        filepath = REPO_ROOT / "kubernetes" / "security" / "network-policies" / "default-deny-all.yaml"
        docs = self._load_all_yaml_docs(filepath)
        assert len(docs) >= 1, "default-deny-all.yaml must be valid YAML"

    def test_allow_app_ingress_valid_yaml(self):
        filepath = REPO_ROOT / "kubernetes" / "security" / "network-policies" / "allow-app-ingress.yaml"
        docs = self._load_all_yaml_docs(filepath)
        assert len(docs) >= 1, "allow-app-ingress.yaml must be valid YAML"

    def test_default_deny_all_contains_networkpolicy_kind(self):
        filepath = REPO_ROOT / "kubernetes" / "security" / "network-policies" / "default-deny-all.yaml"
        content = filepath.read_text(encoding="utf-8")
        assert "NetworkPolicy" in content, \
            "default-deny-all.yaml must declare kind: NetworkPolicy"

    def test_default_deny_all_contains_pod_selector(self):
        filepath = REPO_ROOT / "kubernetes" / "security" / "network-policies" / "default-deny-all.yaml"
        content = filepath.read_text(encoding="utf-8")
        assert "podSelector" in content, \
            "default-deny-all.yaml must contain podSelector"

    def test_allow_app_ingress_contains_networkpolicy_kind(self):
        filepath = REPO_ROOT / "kubernetes" / "security" / "network-policies" / "allow-app-ingress.yaml"
        content = filepath.read_text(encoding="utf-8")
        assert "NetworkPolicy" in content, \
            "allow-app-ingress.yaml must declare kind: NetworkPolicy"

    def test_allow_app_ingress_contains_pod_selector(self):
        filepath = REPO_ROOT / "kubernetes" / "security" / "network-policies" / "allow-app-ingress.yaml"
        content = filepath.read_text(encoding="utf-8")
        assert "podSelector" in content, \
            "allow-app-ingress.yaml must contain podSelector"


# ============================================================
# 6. FALCO RULES
# ============================================================
class TestFalcoRules:
    """Validate Falco runtime security rules."""

    @pytest.fixture(scope="class")
    def falco_content(self):
        filepath = REPO_ROOT / "kubernetes" / "security" / "falco" / "falco-rules.yaml"
        assert filepath.exists(), "falco/falco-rules.yaml must exist"
        return filepath.read_text(encoding="utf-8")

    def test_falco_rules_exists(self):
        assert (REPO_ROOT / "kubernetes" / "security" / "falco" / "falco-rules.yaml").exists(), \
            "falco-rules.yaml must exist"

    def test_falco_rules_valid_yaml(self, falco_content):
        docs = list(yaml.safe_load_all(falco_content))
        valid_docs = [d for d in docs if d is not None]
        assert len(valid_docs) >= 1, "falco-rules.yaml must contain valid YAML documents"

    def test_falco_rules_contains_rule_keyword(self, falco_content):
        assert "rule:" in falco_content, \
            "falco-rules.yaml must contain 'rule:' declarations"

    def test_falco_rules_contains_privilege_escalation(self, falco_content):
        assert "privilege_escalation" in falco_content.lower() or \
               "privilege escalation" in falco_content.lower(), \
            "Falco rules must detect privilege escalation attempts"

    def test_falco_rules_contains_container_escape(self, falco_content):
        assert "container_escape" in falco_content.lower() or \
               "container escape" in falco_content.lower(), \
            "Falco rules must detect container escape attempts"

    def test_falco_rules_contains_crypto_mining(self, falco_content):
        assert "crypto" in falco_content.lower() or "mining" in falco_content.lower(), \
            "Falco rules must detect cryptocurrency mining activity"

    def test_falco_rules_contains_sensitive_file_access(self, falco_content):
        assert "sensitive" in falco_content.lower() or \
               "shadow" in falco_content.lower() or \
               "passwd" in falco_content.lower(), \
            "Falco rules must detect sensitive file access"

    def test_falco_rules_contains_priority(self, falco_content):
        assert "priority:" in falco_content, \
            "Falco rules must specify priority levels"


# ============================================================
# 7. DEVSECOPS PIPELINE
# ============================================================
class TestDevSecOpsPipeline:
    """Validate GitHub Actions DevSecOps CI/CD pipeline."""

    @pytest.fixture(scope="class")
    def pipeline_content(self):
        pipeline_path = REPO_ROOT / ".github" / "workflows" / "devsecops-pipeline.yml"
        assert pipeline_path.exists(), ".github/workflows/devsecops-pipeline.yml must exist"
        return pipeline_path.read_text(encoding="utf-8")

    @pytest.fixture(scope="class")
    def pipeline_yaml(self, pipeline_content):
        return yaml.safe_load(pipeline_content)

    def test_pipeline_file_exists(self):
        assert (REPO_ROOT / ".github" / "workflows" / "devsecops-pipeline.yml").exists(), \
            "DevSecOps pipeline YAML must exist"

    def test_pipeline_is_valid_yaml(self, pipeline_yaml):
        assert pipeline_yaml is not None, "devsecops-pipeline.yml must be valid YAML"

    def test_pipeline_contains_checkov(self, pipeline_content):
        assert "checkov" in pipeline_content.lower(), \
            "DevSecOps pipeline must include Checkov IaC security scan"

    def test_pipeline_contains_trivy(self, pipeline_content):
        assert "trivy" in pipeline_content.lower(), \
            "DevSecOps pipeline must include Trivy container security scan"

    def test_pipeline_contains_semgrep(self, pipeline_content):
        assert "semgrep" in pipeline_content.lower(), \
            "DevSecOps pipeline must include Semgrep SAST scan"

    def test_pipeline_contains_tfsec(self, pipeline_content):
        assert "tfsec" in pipeline_content.lower(), \
            "DevSecOps pipeline must include tfsec Terraform security scan"

    def test_pipeline_contains_owasp_zap(self, pipeline_content):
        assert "zap" in pipeline_content.lower() or "owasp" in pipeline_content.lower(), \
            "DevSecOps pipeline must reference OWASP ZAP DAST"

    def test_pipeline_has_jobs(self, pipeline_yaml):
        assert "jobs" in pipeline_yaml, \
            "Pipeline must define jobs"
        assert len(pipeline_yaml["jobs"]) >= 3, \
            "Pipeline must define at least 3 security scan stages"

    def test_pipeline_triggers_on_push(self, pipeline_yaml):
        # PyYAML parses bare `on:` key as Python True — check both forms
        triggers = pipeline_yaml.get("on", pipeline_yaml.get(True, {}))
        wf_text = (REPO_ROOT / ".github" / "workflows" / "devsecops-pipeline.yml").read_text()
        assert "push" in triggers or "push" in str(triggers) or "push" in wf_text, \
            "Pipeline must trigger on push events"


# ============================================================
# 8. COMPLIANCE MAPPER SCRIPT
# ============================================================
class TestComplianceMapper:
    """Validate compliance_mapper.py script."""

    @pytest.fixture(scope="class")
    def mapper_content(self):
        mapper_path = REPO_ROOT / "scripts" / "compliance_mapper.py"
        assert mapper_path.exists(), "scripts/compliance_mapper.py must exist"
        return mapper_path.read_text(encoding="utf-8")

    def test_compliance_mapper_exists(self):
        assert (REPO_ROOT / "scripts" / "compliance_mapper.py").exists(), \
            "scripts/compliance_mapper.py must exist"

    def test_compliance_mapper_references_nist(self, mapper_content):
        assert "NIST" in mapper_content or "nist" in mapper_content, \
            "compliance_mapper.py must reference NIST 800-53"

    def test_compliance_mapper_references_iso(self, mapper_content):
        assert "ISO" in mapper_content or "iso" in mapper_content or "27001" in mapper_content, \
            "compliance_mapper.py must reference ISO 27001"

    def test_compliance_mapper_has_main(self, mapper_content):
        assert "def main" in mapper_content or "__main__" in mapper_content, \
            "compliance_mapper.py must be executable as a main script"


# ============================================================
# 9. NIST ISO MAPPING JSON
# ============================================================
class TestNISTISOMappingJSON:
    """Validate nist_iso_mapping.json content."""

    @pytest.fixture(scope="class")
    def mapping_data(self):
        mapping_path = REPO_ROOT / "scripts" / "nist_iso_mapping.json"
        assert mapping_path.exists(), "scripts/nist_iso_mapping.json must exist"
        with open(mapping_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def test_nist_iso_mapping_exists(self):
        assert (REPO_ROOT / "scripts" / "nist_iso_mapping.json").exists(), \
            "scripts/nist_iso_mapping.json must exist"

    def test_nist_iso_mapping_valid_json(self, mapping_data):
        assert mapping_data is not None, "nist_iso_mapping.json must be valid JSON"

    def test_nist_iso_mapping_has_at_least_10_entries(self, mapping_data):
        controls = mapping_data.get("controls", {})
        assert len(controls) >= 10, \
            f"nist_iso_mapping.json must have at least 10 control entries (found {len(controls)})"

    def test_nist_iso_mapping_has_nist_fields(self, mapping_data):
        controls = mapping_data.get("controls", {})
        nist_controls = [c for c in controls.values() if c.get("nist")]
        assert len(nist_controls) >= 5, \
            "At least 5 controls must have NIST 800-53 mappings"

    def test_nist_iso_mapping_has_iso_fields(self, mapping_data):
        controls = mapping_data.get("controls", {})
        iso_controls = [c for c in controls.values() if c.get("iso")]
        assert len(iso_controls) >= 5, \
            "At least 5 controls must have ISO 27001 Annex A mappings"

    def test_nist_iso_mapping_contains_cis_controls(self, mapping_data):
        controls = mapping_data.get("controls", {})
        cis_keys = [k for k in controls.keys() if k.startswith("CIS")]
        assert len(cis_keys) >= 5, \
            "nist_iso_mapping.json must contain CIS control keys (CIS-x.x format)"


# ============================================================
# 10. SECURITY POSTURE REPORT SCRIPT
# ============================================================
class TestSecurityPostureReport:
    """Validate security_posture_report.py script."""

    @pytest.fixture(scope="class")
    def report_content(self):
        report_path = REPO_ROOT / "scripts" / "security_posture_report.py"
        assert report_path.exists(), "scripts/security_posture_report.py must exist"
        return report_path.read_text(encoding="utf-8")

    def test_security_posture_report_exists(self):
        assert (REPO_ROOT / "scripts" / "security_posture_report.py").exists(), \
            "scripts/security_posture_report.py must exist"

    def test_report_references_security_hub(self, report_content):
        assert "SecurityHub" in report_content or "security_hub" in report_content.lower() or \
               "securityhub" in report_content.lower(), \
            "security_posture_report.py must reference AWS SecurityHub"

    def test_report_references_findings(self, report_content):
        assert "findings" in report_content.lower(), \
            "security_posture_report.py must process security findings"

    def test_report_references_severity(self, report_content):
        assert "severity" in report_content.lower(), \
            "security_posture_report.py must categorise findings by severity"

    def test_report_has_dry_run_support(self, report_content):
        assert "dry_run" in report_content or "dry-run" in report_content, \
            "security_posture_report.py must support --dry-run mode for CI/CD"

    def test_report_outputs_json(self, report_content):
        assert "json.dumps" in report_content or "json.dump" in report_content, \
            "security_posture_report.py must output JSON format"


# ============================================================
# 11. README COVERAGE
# ============================================================
class TestREADMECoverage:
    """Validate README covers all required security topics."""

    @pytest.fixture(scope="class")
    def readme_content(self):
        readme_path = REPO_ROOT / "README.md"
        assert readme_path.exists(), "README.md must exist"
        return readme_path.read_text(encoding="utf-8").lower()

    def test_readme_mentions_aws_security_hub(self, readme_content):
        assert "security hub" in readme_content or "securityhub" in readme_content, \
            "README must mention AWS Security Hub"

    def test_readme_mentions_guardduty(self, readme_content):
        assert "guardduty" in readme_content, \
            "README must mention Amazon GuardDuty"

    def test_readme_mentions_nist(self, readme_content):
        assert "nist" in readme_content, \
            "README must reference NIST 800-53"

    def test_readme_mentions_cis(self, readme_content):
        assert "cis" in readme_content, \
            "README must reference CIS Benchmarks"

    def test_readme_mentions_iso_27001(self, readme_content):
        assert "iso 27001" in readme_content or "iso27001" in readme_content, \
            "README must reference ISO 27001"

    def test_readme_mentions_falco(self, readme_content):
        assert "falco" in readme_content, \
            "README must mention Falco runtime security"

    def test_readme_mentions_opa(self, readme_content):
        assert "opa" in readme_content or "gatekeeper" in readme_content, \
            "README must mention OPA Gatekeeper"

    def test_readme_mentions_checkov(self, readme_content):
        assert "checkov" in readme_content, \
            "README must mention Checkov IaC scanner"

    def test_readme_mentions_trivy(self, readme_content):
        assert "trivy" in readme_content, \
            "README must mention Trivy container scanner"

    def test_readme_mentions_devsecops(self, readme_content):
        assert "devsecops" in readme_content or "devsecops" in readme_content.replace(" ", ""), \
            "README must mention DevSecOps"


# ============================================================
# 12. FUNCTIONAL TESTS — compliance_mapper.py execution
# ============================================================
class TestComplianceMapperFunctional:
    """Run compliance_mapper.py functions directly."""

    def test_mapper_loads_mapping_file(self):
        """compliance_mapper.py loads nist_iso_mapping.json without error."""
        scripts_dir = REPO_ROOT / "scripts"
        sys.path.insert(0, str(scripts_dir))
        try:
            import compliance_mapper
            mapping_path = REPO_ROOT / "scripts" / "nist_iso_mapping.json"
            data = compliance_mapper.load_mapping(mapping_path)
            assert "controls" in data
            assert len(data["controls"]) >= 10
        finally:
            sys.path.pop(0)

    def test_mapper_returns_critical_controls(self):
        """compliance_mapper.py can filter by CRITICAL severity."""
        scripts_dir = REPO_ROOT / "scripts"
        sys.path.insert(0, str(scripts_dir))
        try:
            import compliance_mapper
            mapping_path = REPO_ROOT / "scripts" / "nist_iso_mapping.json"
            data = compliance_mapper.load_mapping(mapping_path)
            results = compliance_mapper.map_cis_to_nist_iso(data, severity_filter="CRITICAL")
            assert len(results) >= 1, "At least 1 CRITICAL control must be mappable"
            for r in results:
                assert r["severity"] == "CRITICAL"
        finally:
            sys.path.pop(0)

    def test_mapper_specific_control_lookup(self):
        """compliance_mapper.py can look up a specific CIS control."""
        scripts_dir = REPO_ROOT / "scripts"
        sys.path.insert(0, str(scripts_dir))
        try:
            import compliance_mapper
            mapping_path = REPO_ROOT / "scripts" / "nist_iso_mapping.json"
            data = compliance_mapper.load_mapping(mapping_path)
            # CIS-1.4 must exist in mapping
            results = compliance_mapper.map_cis_to_nist_iso(data, cis_control_id="CIS-1.4")
            assert len(results) == 1
            assert results[0]["cis_control"] == "CIS-1.4"
            nist = results[0]["mappings"]["nist_800_53"]["control"]
            assert nist, "CIS-1.4 must have a NIST 800-53 mapping"
        finally:
            sys.path.pop(0)


# ============================================================
# 13. FUNCTIONAL TESTS — security_posture_report.py execution
# ============================================================
class TestSecurityPostureReportFunctional:
    """Run security_posture_report.py functions directly."""

    def test_dry_run_returns_findings(self):
        """security_posture_report.py returns mock findings in dry-run mode."""
        scripts_dir = REPO_ROOT / "scripts"
        sys.path.insert(0, str(scripts_dir))
        try:
            import security_posture_report
            findings = security_posture_report.get_findings_dry_run()
            assert len(findings) >= 3, "Dry-run mode must return at least 3 mock findings"
        finally:
            sys.path.pop(0)

    def test_report_builds_successfully(self):
        """security_posture_report.py builds a complete JSON report."""
        scripts_dir = REPO_ROOT / "scripts"
        sys.path.insert(0, str(scripts_dir))
        try:
            import security_posture_report
            findings = security_posture_report.get_findings_dry_run()
            report = security_posture_report.build_report(findings, "eu-west-2", dry_run=True)
            assert "executive_summary" in report
            assert "findings_by_severity" in report
            assert "report_metadata" in report
            assert report["executive_summary"]["total_findings"] >= 3
        finally:
            sys.path.pop(0)

    def test_posture_score_is_valid(self):
        """Posture score must be between 0 and 100."""
        scripts_dir = REPO_ROOT / "scripts"
        sys.path.insert(0, str(scripts_dir))
        try:
            import security_posture_report
            findings = security_posture_report.get_findings_dry_run()
            report = security_posture_report.build_report(findings, "eu-west-2", dry_run=True)
            score = report["executive_summary"]["posture_score"]
            assert 0 <= score <= 100, f"Posture score {score} must be between 0 and 100"
        finally:
            sys.path.pop(0)
