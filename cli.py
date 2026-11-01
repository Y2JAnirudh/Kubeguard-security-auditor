#!/usr/bin/env python3
"""
KubeGuard Command Line Interface (CLI)
Perform static security audits on Kubernetes manifests and Dockerfiles directly from terminal.
"""

import sys
import argparse
import json
from pathlib import Path

# Add project root and local python_libs to path
_root = Path(__file__).resolve().parent
_libs = _root / "python_libs"
if _libs.exists() and str(_libs) not in sys.path:
    sys.path.insert(0, str(_libs))
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from kube_guard.scanner import scan_files, scan_directory
from kube_guard.report import generate_html_report
from kube_guard.models import Severity


# ANSI terminal colors
class TermColor:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"


def print_banner():
    print(f"""
{TermColor.CYAN}{TermColor.BOLD}=======================================================
   _  __     __          ______                  __
  / |/ /_ __/ /  ___    / ____/_ _____ _________/ /
 /    / // / _ \\/ -_)  / / __/ // / _ `/ __/ _  / 
/_/|_/\\_,_/_.__/\\__/   \\_____/\\_,_/\\_,_/_/  \\_,_/  
Container & Kubernetes Security Auditor
======================================================={TermColor.RESET}
""")


def main():
    parser = argparse.ArgumentParser(
        description="KubeGuard: Static Security Auditor for Kubernetes Manifests and Dockerfiles",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "target",
        help="Path to a Kubernetes YAML file, Dockerfile, or directory to audit",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "html"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output file path for saving report",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with non-zero exit code if score < 70 or any critical/high finding exists",
    )

    args = parser.parse_args()
    target_path = Path(args.target)

    if not target_path.exists():
        print(f"{TermColor.RED}Error: Target path '{args.target}' does not exist.{TermColor.RESET}", file=sys.stderr)
        sys.exit(2)

    # Perform scan
    if target_path.is_dir():
        result = scan_directory(target_path)
    else:
        result = scan_files([target_path])

    # Handle JSON format
    if args.format == "json":
        output_data = {
            "score": result.score,
            "risk_level": result.risk_level,
            "files_scanned": result.files_scanned,
            "resources_scanned": result.resources_scanned,
            "counts": {
                "critical": result.critical_count,
                "high": result.high_count,
                "medium": result.medium_count,
                "low": result.low_count,
                "info": result.info_count,
            },
            "findings": [f.to_dict() for f in result.findings],
            "errors": result.errors,
        }
        json_str = json.dumps(output_data, indent=2)
        if args.output:
            Path(args.output).write_text(json_str, encoding="utf-8")
            print(f"Report written to {args.output}")
        else:
            print(json_str)

        sys.exit(1 if (args.strict and (result.score < 70 or result.critical_count > 0)) else 0)

    # Handle HTML format
    if args.format == "html":
        html_report = generate_html_report(result)
        out_file = args.output or "kubeguard-report.html"
        Path(out_file).write_text(html_report, encoding="utf-8")
        print(f"{TermColor.GREEN}✓ HTML Security Report generated: {out_file}{TermColor.RESET}")
        sys.exit(0)

    # Standard Human-Readable Text Output
    print_banner()

    # Risk level color selection
    risk_color = TermColor.GREEN
    if result.risk_level == "CRITICAL RISK":
        risk_color = TermColor.RED
    elif result.risk_level == "HIGH RISK":
        risk_color = TermColor.RED
    elif result.risk_level == "MODERATE RISK":
        risk_color = TermColor.YELLOW

    print(f"Security Score: {risk_color}{TermColor.BOLD}{result.score} / 100{TermColor.RESET}")
    print(f"Risk Level:     {risk_color}{TermColor.BOLD}{result.risk_level}{TermColor.RESET}")
    print(f"Scanned:        {len(result.files_scanned)} file(s), {result.resources_scanned} resource(s)\n")

    print(f"{TermColor.BOLD}Findings Breakdown:{TermColor.RESET}")
    print(f"  {TermColor.RED}Critical: {result.critical_count}{TermColor.RESET}")
    print(f"  {TermColor.MAGENTA}High:     {result.high_count}{TermColor.RESET}")
    print(f"  {TermColor.YELLOW}Medium:   {result.medium_count}{TermColor.RESET}")
    print(f"  {TermColor.BLUE}Low:      {result.low_count}{TermColor.RESET}")
    print("-" * 55)

    if result.errors:
        print(f"\n{TermColor.YELLOW}Parser / File Warnings:{TermColor.RESET}")
        for err in result.errors:
            print(f"  [!] {err}")

    if not result.findings:
        print(f"\n{TermColor.GREEN}✓ No security misconfigurations identified! Posture is hardened.{TermColor.RESET}\n")
    else:
        print(f"\n{TermColor.BOLD}Top Security Findings:{TermColor.RESET}\n")
        # Priority order
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        sorted_findings = sorted(result.findings, key=lambda f: severity_order.get(f.severity, 99))

        for idx, f in enumerate(sorted_findings, start=1):
            sev_badge = f"[{f.severity.value}]"
            if f.severity == Severity.CRITICAL:
                sev_str = f"{TermColor.RED}{TermColor.BOLD}{sev_badge}{TermColor.RESET}"
            elif f.severity == Severity.HIGH:
                sev_str = f"{TermColor.MAGENTA}{TermColor.BOLD}{sev_badge}{TermColor.RESET}"
            elif f.severity == Severity.MEDIUM:
                sev_str = f"{TermColor.YELLOW}{sev_badge}{TermColor.RESET}"
            else:
                sev_str = f"{TermColor.BLUE}{sev_badge}{TermColor.RESET}"

            print(f"{idx}. {sev_str} {TermColor.BOLD}{f.title}{TermColor.RESET} ({f.rule_id})")
            print(f"   Resource: {TermColor.CYAN}{f.resource}{TermColor.RESET}")
            print(f"   Evidence: {TermColor.GRAY}{f.evidence}{TermColor.RESET}")
            print(f"   Impact:   {f.impact}")
            print(f"   Remedy:   {TermColor.GREEN}{f.remediation}{TermColor.RESET}")
            print()

    print(f"{TermColor.GRAY}Note: Heuristic static audit. Complement with Trivy/Falco for runtime & CVE coverage.{TermColor.RESET}")

    if args.strict and (result.score < 70 or result.critical_count > 0 or result.high_count > 0):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
