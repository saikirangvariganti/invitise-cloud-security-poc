#!/usr/bin/env python3
"""
compliance_mapper.py — InvitISE Cloud Security POC

Maps CIS Benchmark controls to NIST 800-53 and ISO 27001 Annex A equivalents.
Uses a local JSON mapping file — no cloud calls required.

Usage:
    python compliance_mapper.py
    python compliance_mapper.py --control CIS-1.4
    python compliance_mapper.py --domain IAM
    python compliance_mapper.py --framework NIST
    python compliance_mapper.py --severity CRITICAL
    python compliance_mapper.py --output mapping_report.json

Compliance context: CIS Benchmarks, NIST 800-53 Rev.5, ISO 27001:2022, PCI-DSS 4.0
"""

import argparse
import json
import sys
import logging
from pathlib import Path
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("invitise.compliance-mapper")

# Default mapping file location — relative to this script
DEFAULT_MAPPING_FILE = Path(__file__).parent / "nist_iso_mapping.json"


def load_mapping(mapping_file: Path) -> dict:
    """Load CIS → NIST → ISO 27001 mapping from local JSON file."""
    if not mapping_file.exists():
        logger.error(f"Mapping file not found: {mapping_file}")
        sys.exit(1)

    with open(mapping_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    controls = data.get("controls", {})
    logger.info(f"Loaded {len(controls)} CIS control mappings from {mapping_file}")
    return data


def map_cis_to_nist_iso(
    mapping_data: dict,
    cis_control_id: Optional[str] = None,
    domain_filter: Optional[str] = None,
    severity_filter: Optional[str] = None,
    framework_filter: Optional[str] = None,
) -> list:
    """
    Return mapped controls matching the given filters.

    Args:
        mapping_data: Full mapping JSON dict
        cis_control_id: Specific CIS control (e.g. 'CIS-1.4')
        domain_filter: Domain category (e.g. 'IAM', 'Network', 'Logging')
        severity_filter: Severity level (e.g. 'CRITICAL', 'HIGH', 'MEDIUM')
        framework_filter: Filter by framework ('NIST', 'ISO', 'PCI')

    Returns:
        List of enriched control mapping dicts
    """
    controls = mapping_data.get("controls", {})
    results = []

    for ctrl_id, ctrl_data in controls.items():
        # Filter by specific control ID
        if cis_control_id and ctrl_id.upper() != cis_control_id.upper():
            continue

        # Filter by domain
        if domain_filter and ctrl_data.get("domain", "").upper() != domain_filter.upper():
            continue

        # Filter by severity
        if severity_filter and ctrl_data.get("severity", "").upper() != severity_filter.upper():
            continue

        entry = {
            "cis_control": ctrl_id,
            "cis_title": ctrl_data.get("title", ""),
            "severity": ctrl_data.get("severity", ""),
            "domain": ctrl_data.get("domain", ""),
            "mappings": {},
        }

        # Include NIST mapping
        if not framework_filter or framework_filter.upper() in ("NIST", "ALL"):
            entry["mappings"]["nist_800_53"] = {
                "control": ctrl_data.get("nist", ""),
                "title": ctrl_data.get("nist_title", ""),
                "revision": "Rev.5",
            }

        # Include ISO mapping
        if not framework_filter or framework_filter.upper() in ("ISO", "ISO27001", "ALL"):
            entry["mappings"]["iso_27001"] = {
                "annex_a": ctrl_data.get("iso", ""),
                "title": ctrl_data.get("iso_title", ""),
                "edition": "2022",
            }

        # Include PCI-DSS mapping
        if not framework_filter or framework_filter.upper() in ("PCI", "PCI-DSS", "ALL"):
            entry["mappings"]["pci_dss"] = {
                "requirement": ctrl_data.get("pci_dss", ""),
                "version": "4.0",
            }

        results.append(entry)

    return results


def generate_gap_analysis(mapping_data: dict) -> dict:
    """
    Generate a compliance gap analysis grouped by domain.
    Identifies CRITICAL controls and their cross-framework coverage.
    """
    controls = mapping_data.get("controls", {})
    domains: dict = {}

    for ctrl_id, ctrl_data in controls.items():
        domain = ctrl_data.get("domain", "Other")
        severity = ctrl_data.get("severity", "MEDIUM")

        if domain not in domains:
            domains[domain] = {
                "total_controls": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "controls": [],
            }

        domains[domain]["total_controls"] += 1
        severity_key = severity.lower()
        if severity_key in domains[domain]:
            domains[domain][severity_key] += 1

        domains[domain]["controls"].append({
            "cis": ctrl_id,
            "severity": severity,
            "nist": ctrl_data.get("nist", ""),
            "iso": ctrl_data.get("iso", ""),
        })

    return {
        "gap_analysis": {
            "total_controls_mapped": len(controls),
            "domains": domains,
            "summary": {
                "critical_controls": sum(
                    v.get("critical", 0) for v in domains.values()
                ),
                "high_controls": sum(v.get("high", 0) for v in domains.values()),
                "medium_controls": sum(v.get("medium", 0) for v in domains.values()),
            },
        }
    }


def print_table(results: list) -> None:
    """Print results as a formatted console table."""
    if not results:
        print("No controls found matching the specified filters.")
        return

    header = f"{'CIS Control':<20} {'Severity':<10} {'Domain':<15} {'NIST 800-53':<12} {'ISO 27001':<14} {'PCI-DSS':<10}"
    print("\n" + "=" * 85)
    print(f"  InvitISE Compliance Control Mapping — CIS → NIST 800-53 → ISO 27001")
    print("=" * 85)
    print(header)
    print("-" * 85)

    for ctrl in results:
        nist = ctrl.get("mappings", {}).get("nist_800_53", {}).get("control", "-")
        iso = ctrl.get("mappings", {}).get("iso_27001", {}).get("annex_a", "-")
        pci = ctrl.get("mappings", {}).get("pci_dss", {}).get("requirement", "-")

        row = (
            f"{ctrl['cis_control']:<20} "
            f"{ctrl['severity']:<10} "
            f"{ctrl['domain']:<15} "
            f"{nist:<12} "
            f"{iso:<14} "
            f"{pci:<10}"
        )
        print(row)

    print("=" * 85)
    print(f"  Total: {len(results)} controls | "
          f"Critical: {sum(1 for c in results if c['severity'] == 'CRITICAL')} | "
          f"High: {sum(1 for c in results if c['severity'] == 'HIGH')}")
    print("=" * 85 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="InvitISE Compliance Mapper — CIS Benchmarks to NIST 800-53 and ISO 27001"
    )
    parser.add_argument(
        "--mapping-file",
        default=str(DEFAULT_MAPPING_FILE),
        help=f"Path to the JSON mapping file (default: {DEFAULT_MAPPING_FILE})",
    )
    parser.add_argument(
        "--control",
        default=None,
        help="Lookup a specific CIS control (e.g. CIS-1.4, CIS-3.3)",
    )
    parser.add_argument(
        "--domain",
        default=None,
        choices=["IAM", "Logging", "Network", "Monitoring", "Encryption", "Configuration", "Kubernetes"],
        help="Filter by security domain",
    )
    parser.add_argument(
        "--severity",
        default=None,
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Filter by severity level",
    )
    parser.add_argument(
        "--framework",
        default=None,
        choices=["NIST", "ISO", "ISO27001", "PCI", "PCI-DSS", "ALL"],
        help="Show mappings for a specific framework only",
    )
    parser.add_argument(
        "--gap-analysis",
        action="store_true",
        help="Generate gap analysis report grouped by domain",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Write JSON output to file instead of stdout",
    )
    parser.add_argument(
        "--format",
        default="table",
        choices=["table", "json"],
        help="Output format: table (console) or json (default: table)",
    )

    args = parser.parse_args()
    mapping_data = load_mapping(Path(args.mapping_file))

    if args.gap_analysis:
        result = generate_gap_analysis(mapping_data)
        output = json.dumps(result, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output)
            logger.info(f"Gap analysis written to {args.output}")
        else:
            print(output)
        return

    results = map_cis_to_nist_iso(
        mapping_data,
        cis_control_id=args.control,
        domain_filter=args.domain,
        severity_filter=args.severity,
        framework_filter=args.framework,
    )

    if args.format == "json" or args.output:
        output_data = {
            "metadata": mapping_data.get("_metadata", {}),
            "filter_applied": {
                "control": args.control,
                "domain": args.domain,
                "severity": args.severity,
                "framework": args.framework,
            },
            "results_count": len(results),
            "controls": results,
        }
        json_str = json.dumps(output_data, indent=2)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(json_str)
            logger.info(f"Mapping report written to {args.output}")
        else:
            print(json_str)
    else:
        print_table(results)

    logger.info(f"Compliance mapping complete — {len(results)} controls matched")


if __name__ == "__main__":
    main()
