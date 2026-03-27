# invitise-cloud-security-poc

Cloud Security Engineering Platform — proof-of-concept for a fintech/financial services environment. Demonstrates end-to-end platform hardening across AWS, Azure, and Kubernetes, integrating threat monitoring, DevSecOps tooling, and compliance frameworks (CIS Benchmarks, NIST 800-53, ISO 27001, PCI-DSS).

**Role target:** Cloud Security Engineer (Outside IR35, London) — InvitISE

---

## What This POC Demonstrates

| Area | Tools & Controls |
|---|---|
| AWS Threat Detection | AWS Security Hub, Amazon GuardDuty, AWS CloudTrail |
| AWS Data Protection | AWS KMS (CMK, rotation), VPC Flow Logs, S3 encryption |
| Azure Security | Microsoft Defender for Cloud, Azure Monitor, Log Analytics |
| Kubernetes Security | OPA Gatekeeper, Falco, Kubernetes NetworkPolicy |
| IaC Security | tfsec, Checkov, Trivy, Terraform |
| SAST/DAST | Semgrep, OWASP ZAP |
| Compliance | CIS Benchmarks, NIST 800-53, ISO 27001, PCI-DSS |
| DevSecOps | GitHub Actions pipeline with automated security gates |

---

## Architecture

```
invitise-cloud-security-poc/
├── terraform/
│   ├── aws_security/        # SecurityHub, GuardDuty, CloudTrail, KMS, VPC
│   └── azure_security/      # Defender for Cloud, Monitor, Log Analytics
├── kubernetes/security/
│   ├── opa-constraints/     # OPA Gatekeeper admission policies
│   ├── network-policies/    # Zero-trust NetworkPolicy (default-deny)
│   └── falco/               # Runtime threat detection rules
├── .github/workflows/
│   └── devsecops-pipeline.yml   # DevSecOps CI/CD: checkov→tfsec→trivy→semgrep→ZAP→deploy
├── scripts/
│   ├── security_posture_report.py   # AWS Security Hub findings aggregator
│   ├── compliance_mapper.py         # CIS → NIST 800-53 → ISO 27001 mapper
│   └── nist_iso_mapping.json        # Control mapping data
└── tests/
    └── test_invitise_cloud_security.py   # 30+ pytest tests
```

---

## AWS Security Controls

### AWS Security Hub
Centralised findings aggregation with three compliance standards enabled:
- **AWS Foundational Security Best Practices v1.0.0**
- **CIS AWS Foundations Benchmark v1.4.0**
- **PCI-DSS v3.2.1** — mandatory for financial services

```hcl
resource "aws_securityhub_account" "main" {
  enable_default_standards = false
}

resource "aws_securityhub_standards_subscription" "cis_benchmarks" {
  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.4.0"
}
```

### Amazon GuardDuty
ML-based threat detection with full data source coverage:
- S3 malicious activity detection
- EKS audit log analysis
- EC2 malware protection (EBS volume scanning)
- Findings published every 15 minutes to S3 (encrypted with KMS CMK)

### AWS CloudTrail
Multi-region audit logging meeting CIS 2.1–2.9:
- `is_multi_region_trail = true`
- `enable_log_file_validation = true`
- Encrypted with customer-managed KMS key
- CloudWatch Logs integration with metric filters for CIS alarms
- API call rate and error rate insights

### AWS KMS — IAM Hardening
- Customer-managed key with automatic annual rotation (`enable_key_rotation = true`)
- CMK policy restricts access to CloudTrail and account root
- IAM password policy: 14 char minimum, MFA enforcement, 90-day rotation, 24-password history

### VPC Flow Logs
All traffic captured (`traffic_type = "ALL"`) and streamed to CloudWatch Logs — retained 365 days for PCI-DSS Requirement 10 compliance.

---

## Azure Security Controls

### Microsoft Defender for Cloud
All Defender plans enabled for comprehensive workload protection:

| Defender Plan | Coverage |
|---|---|
| Defender for Servers | JIT access, endpoint protection, vulnerability assessment |
| Defender for Containers | Kubernetes threat protection, container image scanning |
| Defender for Storage | Malware scanning, anomaly detection |
| Defender for Key Vault | Unusual access pattern alerts |
| Defender for SQL | SQL injection, anomalous queries |

### Azure Monitor & Log Analytics
All Azure Activity Log categories (Administrative, Security, Policy, ResourceHealth) forwarded to a central Log Analytics Workspace — single SIEM pane for incident investigation.

### Azure Policy — CIS Benchmark Enforcement
CIS Microsoft Azure Foundations Benchmark v1.4.0 policy initiative assigned at subscription scope, with non-compliance alerts on all deviations.

---

## Kubernetes Security

### OPA Gatekeeper — Admission Control
Three constraint templates enforce platform hardening at admission time:

| Constraint | CIS Control | What It Blocks |
|---|---|---|
| `K8sRequireReadOnlyRootFs` | CIS 5.2.1 | Containers with writable root filesystem |
| `K8sDenyPrivilegedContainers` | CIS 5.2.1, 5.2.5 | `privileged: true`, `allowPrivilegeEscalation: true`, `hostPID`, `hostIPC` |
| `K8sRequireResourceLimits` | CIS 5.6.4 | Pods missing CPU or memory limits |

All constraints use `enforcementAction: deny` — non-compliant pods are rejected at the API server before scheduling.

### Kubernetes NetworkPolicy — Zero-Trust
Default deny-all baseline applied to all application namespaces:

```yaml
spec:
  podSelector: {}   # All pods
  policyTypes:
    - Ingress
    - Egress
  # No rules = deny everything
```

Explicit allow policies permit only:
- Ingress from `ingress-nginx` namespace to app pods (ports 8080, 8443)
- Egress to `kube-dns` for service discovery (port 53)
- Egress from API pods to database namespace (port 5432)

### Falco — Runtime Threat Detection
Custom Falco rules tuned for fintech environments:

| Rule | Threat | Severity |
|---|---|---|
| `privilege_escalation_setuid` | `su`, `sudo`, `pkexec` in containers | CRITICAL |
| `privilege_escalation_capabilities` | `capset`, `setuid` syscalls | HIGH |
| `container_escape_nsenter` | `nsenter` execution in container | CRITICAL |
| `container_escape_host_path_write` | Writes to `/host/etc`, `/var/run/docker.sock` | CRITICAL |
| `crypto_mining_process_detected` | `xmrig`, `minerd`, `ethminer` etc. | CRITICAL |
| `crypto_mining_network_activity` | Connections to mining pool ports | HIGH |
| `sensitive_file_read` | Reads of `/etc/shadow`, `/etc/ssh`, K8s secrets | HIGH |
| `payment_data_access_anomaly` | Unexpected PCI cardholder data access | CRITICAL |
| `shell_spawned_in_container` | Interactive shell (`bash`, `sh`) with TTY | HIGH |

---

## DevSecOps Pipeline

The `.github/workflows/devsecops-pipeline.yml` enforces security at every stage:

```
checkout → checkov → tfsec → trivy → semgrep → owasp-zap → terraform-plan → deploy
```

| Stage | Tool | What It Checks |
|---|---|---|
| IaC Security | **Checkov** | Terraform + K8s misconfigurations (AWS, Azure, K8s) |
| Terraform Lint | **tfsec** | Terraform-specific security rules |
| Container Scan | **Trivy** | CVEs in container images + filesystem |
| SAST | **Semgrep** | OWASP Top 10, secrets, Python security patterns |
| DAST | **OWASP ZAP** | Active API surface scan (staging environment) |
| IaC Validation | **Terraform validate** | Configuration correctness before plan |
| Deploy | Manual approval | Production gate requires all stages to pass |

All findings upload to GitHub Security tab as SARIF for unified review.

---

## Compliance Frameworks

### CIS Benchmarks
- CIS AWS Foundations Benchmark v1.4.0 (Security Hub standard)
- CIS Kubernetes Benchmark v1.8.0 (OPA constraints + Falco rules)
- CIS Microsoft Azure Foundations Benchmark v1.4.0 (Azure Policy)

### NIST 800-53 Rev. 5 Control Families Covered
`AC` (Access Control) · `AU` (Audit & Accountability) · `CM` (Configuration Management) · `IA` (Identification & Authentication) · `IR` (Incident Response) · `RA` (Risk Assessment) · `SA` (System & Services Acquisition) · `SC` (System & Communications Protection) · `SI` (System & Information Integrity)

### ISO 27001:2022 Annex A Domains Addressed
`A.9` Identity & Access Management · `A.10` Cryptography · `A.12` Operations Security · `A.13` Communications Security · `A.14` System Acquisition/Development/Maintenance · `A.16` Information Security Incident Management

### PCI-DSS v4.0 Requirements Addressed
`Req 1` Network Security · `Req 2` Secure Configurations · `Req 3` Protect Cardholder Data · `Req 7` Restrict Access · `Req 8` Authentication · `Req 10` Logging & Monitoring · `Req 11` Security Testing · `Req 12` Security Policy

---

## Scripts

### Security Posture Report
Aggregates AWS Security Hub findings, categorises by severity, and outputs a JSON posture score:

```bash
# Dry-run (no AWS credentials needed)
python scripts/security_posture_report.py --dry-run

# Live AWS query
python scripts/security_posture_report.py --region eu-west-2 --output report.json

# CI gate — fail if CRITICAL findings exist
python scripts/security_posture_report.py --dry-run --exit-on-critical
```

### Compliance Mapper
Maps CIS Benchmark controls to NIST 800-53 and ISO 27001 Annex A (local JSON, no cloud calls):

```bash
# Show all mappings
python scripts/compliance_mapper.py

# Lookup specific control
python scripts/compliance_mapper.py --control CIS-1.4

# Filter by domain
python scripts/compliance_mapper.py --domain IAM --severity CRITICAL

# Export JSON
python scripts/compliance_mapper.py --format json --output compliance_report.json
```

---

## Running Tests

```bash
pip install pytest pyyaml
pytest tests/ -v --tb=short
```

Expected: **30+ tests passing**

---

## Financial Services Context

This POC is designed for regulated financial services environments:

- **PCI-DSS compliance** — S3 WORM logs (7-year retention), payment data access monitoring via Falco, SecurityHub PCI-DSS standard
- **Platform hardening** — OPA deny-privileged/read-only-rootfs constraints block common container escape vectors
- **Threat monitoring** — GuardDuty ML + Falco runtime rules provide defence-in-depth against advanced persistent threats
- **Audit trail** — CloudTrail multi-region + Azure Activity Log → SIEM provides complete control-plane audit evidence for ISO 27001 A.12.4 and PCI-DSS Req 10

---

## Author

Sai Kiran Goud Variganti — Cloud & DevSecOps Engineer
GitHub: [github.com/saikirangvariganti](https://github.com/saikirangvariganti)
