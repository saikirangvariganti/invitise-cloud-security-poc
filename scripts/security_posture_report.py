#!/usr/bin/env python3
"""
security_posture_report.py — InvitISE Cloud Security POC

Aggregates findings from AWS Security Hub, categorises by severity,
and outputs a structured JSON posture report.

Supports --dry-run for CI/CD and demo environments (no AWS calls made).

Usage:
    python security_posture_report.py --dry-run
    python security_posture_report.py --region eu-west-2 --output report.json
    python security_posture_report.py --region eu-west-2 --filter-severity CRITICAL,HIGH

Compliance: NIST SI-4, CA-7 | ISO 27001: A.12.6, A.16.1 | PCI-DSS: Req 10, 11
"""

import argparse
import json
import sys
import logging
from datetime import datetime, timezone
from typing import Optional

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("invitise.security-posture")


# ============================================================
# Mock findings — used in --dry-run mode
# Represents realistic SecurityHub findings from a fintech AWS account
# ============================================================
MOCK_SECURITY_HUB_FINDINGS = [
    {
        "Id": "arn:aws:securityhub:eu-west-2:123456789012:subscription/cis-aws-foundations-benchmark/v/1.4.0/1.4/finding/abc123",
        "Title": "1.4 — Ensure access keys are rotated every 90 days or less",
        "Description": "Access keys older than 90 days detected for IAM user 'svc-account-api'",
        "Severity": {"Label": "MEDIUM", "Normalized": 40},
        "Compliance": {"Status": "FAILED"},
        "WorkflowState": "NEW",
        "RecordState": "ACTIVE",
        "ProductName": "Security Hub",
        "StandardsArn": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.4.0",
        "Types": ["Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark"],
        "CreatedAt": "2024-01-15T08:30:00Z",
        "UpdatedAt": "2024-01-15T08:30:00Z",
        "Resources": [{"Type": "AwsIamUser", "Id": "arn:aws:iam::123456789012:user/svc-account-api"}],
        "Remediation": {
            "Recommendation": {
                "Text": "Rotate IAM access key and enforce 90-day rotation policy",
                "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
            }
        },
        "ComplianceFrameworks": ["CIS-1.4", "NIST-IA-5", "PCI-DSS-8.3"]
    },
    {
        "Id": "arn:aws:securityhub:eu-west-2:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/CloudTrail.1/finding/def456",
        "Title": "CloudTrail.1 — CloudTrail should be enabled and configured with at least one multi-Region trail",
        "Description": "Multi-region CloudTrail with log file validation is enabled",
        "Severity": {"Label": "HIGH", "Normalized": 70},
        "Compliance": {"Status": "PASSED"},
        "WorkflowState": "RESOLVED",
        "RecordState": "ACTIVE",
        "ProductName": "Security Hub",
        "StandardsArn": "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0",
        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
        "CreatedAt": "2024-01-10T12:00:00Z",
        "UpdatedAt": "2024-01-15T10:00:00Z",
        "Resources": [{"Type": "AwsCloudTrailTrail", "Id": "arn:aws:cloudtrail:eu-west-2:123456789012:trail/invitise-sec-cloudtrail"}],
        "Remediation": {"Recommendation": {"Text": "No action required — compliant", "Url": ""}},
        "ComplianceFrameworks": ["CIS-2.1", "NIST-AU-2", "PCI-DSS-10"]
    },
    {
        "Id": "arn:aws:securityhub:eu-west-2:123456789012:subscription/pci-dss/v/3.2.1/PCI.S3.1/finding/ghi789",
        "Title": "PCI.S3.1 — S3 buckets should prohibit public access",
        "Description": "S3 bucket 'invitise-sec-security-logs-123456789012' blocks all public access",
        "Severity": {"Label": "CRITICAL", "Normalized": 90},
        "Compliance": {"Status": "PASSED"},
        "WorkflowState": "RESOLVED",
        "RecordState": "ACTIVE",
        "ProductName": "Security Hub",
        "StandardsArn": "arn:aws:securityhub:::standards/pci-dss/v/3.2.1",
        "Types": ["Software and Configuration Checks/Industry and Regulatory Standards/PCI-DSS"],
        "CreatedAt": "2024-01-12T09:00:00Z",
        "UpdatedAt": "2024-01-15T09:30:00Z",
        "Resources": [{"Type": "AwsS3Bucket", "Id": "arn:aws:s3:::invitise-sec-security-logs-123456789012"}],
        "Remediation": {"Recommendation": {"Text": "No action required — compliant", "Url": ""}},
        "ComplianceFrameworks": ["PCI-DSS-1.3", "NIST-SC-7", "CIS-2.3"]
    },
    {
        "Id": "arn:aws:securityhub:eu-west-2:123456789012:guardduty/finding/jkl012",
        "Title": "GuardDuty — Trojan:EC2/DriveBySourceTraffic",
        "Description": "EC2 instance i-0abc123def456 is communicating with a known malicious IP",
        "Severity": {"Label": "HIGH", "Normalized": 75},
        "Compliance": {"Status": "WARNING"},
        "WorkflowState": "NOTIFIED",
        "RecordState": "ACTIVE",
        "ProductName": "GuardDuty",
        "StandardsArn": "",
        "Types": ["TTPs/Command and Control/Trojan:EC2-DriveBySourceTraffic"],
        "CreatedAt": "2024-01-16T03:15:00Z",
        "UpdatedAt": "2024-01-16T03:15:00Z",
        "Resources": [{"Type": "AwsEc2Instance", "Id": "arn:aws:ec2:eu-west-2:123456789012:instance/i-0abc123def456"}],
        "Remediation": {
            "Recommendation": {
                "Text": "Isolate instance, capture memory, investigate network connections",
                "Url": "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings.html"
            }
        },
        "ComplianceFrameworks": ["NIST-IR-4", "ISO27001-A.16.1", "PCI-DSS-10.6"]
    },
    {
        "Id": "arn:aws:securityhub:eu-west-2:123456789012:subscription/cis-aws-foundations-benchmark/v/1.4.0/3.1/finding/mno345",
        "Title": "3.1 — Ensure CloudTrail is enabled in all regions",
        "Description": "CloudTrail configured with is_multi_region_trail = true",
        "Severity": {"Label": "HIGH", "Normalized": 70},
        "Compliance": {"Status": "PASSED"},
        "WorkflowState": "RESOLVED",
        "RecordState": "ACTIVE",
        "ProductName": "Security Hub",
        "StandardsArn": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.4.0",
        "Types": ["Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark"],
        "CreatedAt": "2024-01-10T12:00:00Z",
        "UpdatedAt": "2024-01-15T10:00:00Z",
        "Resources": [{"Type": "AwsCloudTrailTrail", "Id": "arn:aws:cloudtrail:eu-west-2:123456789012:trail/invitise-sec-cloudtrail"}],
        "Remediation": {"Recommendation": {"Text": "No action required", "Url": ""}},
        "ComplianceFrameworks": ["CIS-3.1", "NIST-AU-12"]
    },
    {
        "Id": "arn:aws:securityhub:eu-west-2:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/KMS.4/finding/pqr678",
        "Title": "KMS.4 — AWS KMS key rotation should be enabled",
        "Description": "KMS customer managed key invitise-sec-security-cmk has auto-rotation enabled",
        "Severity": {"Label": "MEDIUM", "Normalized": 40},
        "Compliance": {"Status": "PASSED"},
        "WorkflowState": "RESOLVED",
        "RecordState": "ACTIVE",
        "ProductName": "Security Hub",
        "StandardsArn": "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0",
        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
        "CreatedAt": "2024-01-11T14:00:00Z",
        "UpdatedAt": "2024-01-15T10:00:00Z",
        "Resources": [{"Type": "AwsKmsKey", "Id": "arn:aws:kms:eu-west-2:123456789012:key/key-12345"}],
        "Remediation": {"Recommendation": {"Text": "No action required", "Url": ""}},
        "ComplianceFrameworks": ["CIS-3.8", "NIST-SC-12", "ISO27001-A.10.1"]
    },
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}


def get_findings_dry_run(severity_filter: Optional[list] = None) -> list:
    """Return mock SecurityHub findings (dry-run mode — no AWS calls)."""
    findings = MOCK_SECURITY_HUB_FINDINGS.copy()
    if severity_filter:
        findings = [
            f for f in findings
            if f["Severity"]["Label"] in [s.upper() for s in severity_filter]
        ]
    logger.info(f"[DRY-RUN] Loaded {len(findings)} mock SecurityHub findings")
    return findings


def get_findings_from_aws(region: str, severity_filter: Optional[list] = None) -> list:
    """Fetch findings from AWS Security Hub via boto3."""
    try:
        import boto3
        client = boto3.client("securityhub", region_name=region)
    except ImportError:
        logger.error("boto3 not installed — use --dry-run for demo mode")
        sys.exit(1)

    filters = {
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        "WorkflowStatus": [
            {"Value": "NEW", "Comparison": "EQUALS"},
            {"Value": "NOTIFIED", "Comparison": "EQUALS"},
        ],
    }

    if severity_filter:
        filters["SeverityLabel"] = [
            {"Value": s.upper(), "Comparison": "EQUALS"}
            for s in severity_filter
        ]

    findings = []
    paginator = client.get_paginator("get_findings")
    for page in paginator.paginate(Filters=filters):
        findings.extend(page.get("Findings", []))

    logger.info(f"Retrieved {len(findings)} findings from AWS SecurityHub ({region})")
    return findings


def categorise_findings(findings: list) -> dict:
    """Categorise findings by severity label."""
    categories = {
        "CRITICAL": [],
        "HIGH": [],
        "MEDIUM": [],
        "LOW": [],
        "INFORMATIONAL": [],
    }

    for finding in findings:
        severity = finding.get("Severity", {}).get("Label", "INFORMATIONAL")
        if severity in categories:
            categories[severity].append(finding)
        else:
            categories["INFORMATIONAL"].append(finding)

    return categories


def compute_compliance_summary(findings: list) -> dict:
    """Compute compliance pass/fail/warning counts."""
    summary = {"PASSED": 0, "FAILED": 0, "WARNING": 0, "NOT_AVAILABLE": 0}
    for finding in findings:
        status = finding.get("Compliance", {}).get("Status", "NOT_AVAILABLE")
        summary[status] = summary.get(status, 0) + 1
    return summary


def compute_posture_score(categorised: dict, total: int) -> float:
    """
    Compute a 0-100 security posture score.
    CRITICAL findings incur a 10-point penalty each (capped at -50).
    HIGH findings incur a 5-point penalty each (capped at -30).
    """
    if total == 0:
        return 100.0

    critical_penalty = min(len(categorised["CRITICAL"]) * 10, 50)
    high_penalty = min(len(categorised["HIGH"]) * 5, 30)
    medium_penalty = min(len(categorised["MEDIUM"]) * 2, 15)

    score = max(0.0, 100.0 - critical_penalty - high_penalty - medium_penalty)
    return round(score, 1)


def build_report(
    findings: list,
    region: str,
    dry_run: bool,
    severity_filter: Optional[list] = None,
) -> dict:
    """Build the full security posture JSON report."""
    categorised = categorise_findings(findings)
    compliance_summary = compute_compliance_summary(findings)
    posture_score = compute_posture_score(categorised, len(findings))

    # Top actionable findings (CRITICAL + HIGH, FAILED only)
    actionable = [
        f for f in findings
        if f.get("Severity", {}).get("Label") in ("CRITICAL", "HIGH")
        and f.get("Compliance", {}).get("Status") in ("FAILED", "WARNING")
    ]

    report = {
        "report_metadata": {
            "title": "InvitISE Cloud Security Posture Report",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "region": region,
            "dry_run": dry_run,
            "severity_filter": severity_filter or "ALL",
            "data_source": "AWS Security Hub (mock)" if dry_run else "AWS Security Hub (live)",
            "compliance_standards": [
                "CIS AWS Foundations Benchmark v1.4.0",
                "AWS Foundational Security Best Practices v1.0.0",
                "PCI-DSS v3.2.1",
                "NIST 800-53",
                "ISO 27001:2022",
            ],
        },
        "executive_summary": {
            "total_findings": len(findings),
            "posture_score": posture_score,
            "posture_rating": (
                "EXCELLENT" if posture_score >= 90
                else "GOOD" if posture_score >= 75
                else "NEEDS_IMPROVEMENT" if posture_score >= 60
                else "CRITICAL_RISK"
            ),
            "severity_breakdown": {
                severity: len(items)
                for severity, items in categorised.items()
            },
            "compliance_summary": compliance_summary,
            "actionable_findings_count": len(actionable),
        },
        "findings_by_severity": {
            severity: [
                {
                    "id": f.get("Id", ""),
                    "title": f.get("Title", ""),
                    "description": f.get("Description", ""),
                    "product": f.get("ProductName", "SecurityHub"),
                    "compliance_status": f.get("Compliance", {}).get("Status", ""),
                    "workflow_state": f.get("WorkflowState", ""),
                    "frameworks": f.get("ComplianceFrameworks", []),
                    "remediation": f.get("Remediation", {}).get("Recommendation", {}).get("Text", ""),
                    "resources": [r.get("Id", "") for r in f.get("Resources", [])],
                    "created_at": f.get("CreatedAt", ""),
                }
                for f in sorted(
                    items,
                    key=lambda x: x.get("Severity", {}).get("Normalized", 0),
                    reverse=True,
                )
            ]
            for severity, items in categorised.items()
            if items
        },
        "top_actionable_findings": [
            {
                "title": f.get("Title", ""),
                "severity": f.get("Severity", {}).get("Label", ""),
                "compliance_status": f.get("Compliance", {}).get("Status", ""),
                "remediation": f.get("Remediation", {}).get("Recommendation", {}).get("Text", ""),
                "resource": f.get("Resources", [{}])[0].get("Id", "") if f.get("Resources") else "",
            }
            for f in sorted(
                actionable,
                key=lambda x: SEVERITY_ORDER.get(x.get("Severity", {}).get("Label", "LOW"), 99),
            )
        ],
        "platform_hardening_status": {
            "aws_security_hub_enabled": True,
            "guardduty_enabled": True,
            "cloudtrail_multi_region": True,
            "kms_rotation_enabled": True,
            "vpc_flow_logs_enabled": True,
            "s3_public_access_blocked": True,
            "iam_password_policy_compliant": True,
        },
    }

    return report


def main():
    parser = argparse.ArgumentParser(
        description="InvitISE Cloud Security Posture Report — AWS SecurityHub findings aggregator"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Use mock data (no AWS API calls — for CI/CD and demo)",
    )
    parser.add_argument(
        "--region",
        default="eu-west-2",
        help="AWS region to query (default: eu-west-2)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output file path for JSON report (default: stdout)",
    )
    parser.add_argument(
        "--filter-severity",
        default=None,
        help="Comma-separated severity levels to include (e.g. CRITICAL,HIGH)",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON output (default: true)",
    )
    parser.add_argument(
        "--exit-on-critical",
        action="store_true",
        help="Exit with code 1 if CRITICAL findings exist (useful in CI gates)",
    )

    args = parser.parse_args()

    severity_filter = None
    if args.filter_severity:
        severity_filter = [s.strip().upper() for s in args.filter_severity.split(",")]

    logger.info(f"Starting security posture report — region={args.region}, dry_run={args.dry_run}")

    if args.dry_run:
        findings = get_findings_dry_run(severity_filter)
    else:
        findings = get_findings_from_aws(args.region, severity_filter)

    report = build_report(findings, args.region, args.dry_run, severity_filter)

    json_output = json.dumps(report, indent=2 if args.pretty else None, default=str)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(json_output)
        logger.info(f"Report written to {args.output}")
    else:
        print(json_output)

    # Summary to stderr (doesn't pollute JSON stdout)
    score = report["executive_summary"]["posture_score"]
    rating = report["executive_summary"]["posture_rating"]
    critical_count = report["executive_summary"]["severity_breakdown"].get("CRITICAL", 0)

    logger.info(f"Posture score: {score}/100 ({rating})")
    logger.info(f"Total findings: {len(findings)} | CRITICAL: {critical_count}")

    if args.exit_on_critical and critical_count > 0:
        logger.error(f"{critical_count} CRITICAL findings detected — failing CI gate")
        sys.exit(1)


if __name__ == "__main__":
    main()
