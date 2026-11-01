"""
KubeGuard Scanner Engine
Core orchestrator that parses manifests and Dockerfiles, applies security rules,
and aggregates findings with deterministic scoring.
"""

import os
from pathlib import Path
from typing import List, Union, Dict
from collections import Counter

from kube_guard.models import Finding, ScanResult, Severity
from kube_guard.parsers import parse_yaml_manifests, ParsedResource
from kube_guard.rules import evaluate_kubernetes_rules
from kube_guard.docker_scanner import scan_dockerfile_content
from kube_guard.scoring import calculate_score


def is_dockerfile(file_path: Union[str, Path], content: str = "") -> bool:
    """Determine whether a file target is a Dockerfile."""
    name = Path(file_path).name.lower()
    if name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile"):
        return True
    # Heuristic check for raw string uploads
    if content.strip().upper().startswith("FROM "):
        return True
    return False


def scan_content(content: str, filename: str = "manifest.yaml") -> ScanResult:
    """
    Scan raw text content (Kubernetes YAML or Dockerfile).
    Safe against syntax errors and empty payloads.
    """
    all_findings: List[Finding] = []
    errors: List[str] = []
    resources_count = 0

    if not content or not content.strip():
        return ScanResult(
            files_scanned=[filename],
            resources_scanned=0,
            findings=[],
            score=100,
            risk_level="LOW RISK",
            errors=["Uploaded file was empty."],
        )

    if is_dockerfile(filename, content):
        docker_findings = scan_dockerfile_content(content, file_path=filename)
        all_findings.extend(docker_findings)
        resources_count = 1
    else:
        resources, parse_errors = parse_yaml_manifests(content, file_path=filename)
        errors.extend(parse_errors)
        resources_count = len(resources)
        for res in resources:
            k8s_findings = evaluate_kubernetes_rules(res)
            all_findings.extend(k8s_findings)

    score, risk_level = calculate_score(all_findings)

    crit = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in all_findings if f.severity == Severity.HIGH)
    med = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
    low = sum(1 for f in all_findings if f.severity == Severity.LOW)
    info = sum(1 for f in all_findings if f.severity == Severity.INFO)

    cat_counts = dict(Counter(f.category.value for f in all_findings))

    return ScanResult(
        files_scanned=[filename],
        resources_scanned=resources_count,
        findings=all_findings,
        score=score,
        risk_level=risk_level,
        critical_count=crit,
        high_count=high,
        medium_count=med,
        low_count=low,
        info_count=info,
        category_counts=cat_counts,
        errors=errors,
    )


def scan_files(paths: List[Union[str, Path]]) -> ScanResult:
    """
    Scan a list of file paths and aggregate findings into a single unified report.
    """
    all_findings: List[Finding] = []
    errors: List[str] = []
    files_scanned: List[str] = []
    total_resources = 0

    for p in paths:
        path = Path(p)
        if not path.is_file():
            errors.append(f"File not found: {p}")
            continue

        files_scanned.append(str(path))
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            errors.append(f"Failed to read file {p}: {str(exc)}")
            continue

        if is_dockerfile(path, content):
            docker_findings = scan_dockerfile_content(content, file_path=str(path))
            all_findings.extend(docker_findings)
            total_resources += 1
        else:
            resources, parse_errors = parse_yaml_manifests(content, file_path=str(path))
            errors.extend(parse_errors)
            total_resources += len(resources)
            for res in resources:
                k8s_findings = evaluate_kubernetes_rules(res)
                all_findings.extend(k8s_findings)

    score, risk_level = calculate_score(all_findings)

    crit = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in all_findings if f.severity == Severity.HIGH)
    med = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
    low = sum(1 for f in all_findings if f.severity == Severity.LOW)
    info = sum(1 for f in all_findings if f.severity == Severity.INFO)

    cat_counts = dict(Counter(f.category.value for f in all_findings))

    return ScanResult(
        files_scanned=files_scanned,
        resources_scanned=total_resources,
        findings=all_findings,
        score=score,
        risk_level=risk_level,
        critical_count=crit,
        high_count=high,
        medium_count=med,
        low_count=low,
        info_count=info,
        category_counts=cat_counts,
        errors=errors,
    )


def scan_directory(dir_path: Union[str, Path], recursive: bool = True) -> ScanResult:
    """
    Scan an entire directory for YAML manifests and Dockerfiles.
    """
    dir_p = Path(dir_path)
    if not dir_p.is_dir():
        return ScanResult(
            files_scanned=[],
            resources_scanned=0,
            findings=[],
            score=100,
            risk_level="LOW RISK",
            errors=[f"Directory not found: {dir_path}"],
        )

    file_paths: List[Path] = []
    pattern_iter = dir_p.rglob("*") if recursive else dir_p.glob("*")

    for p in pattern_iter:
        if p.is_file():
            name = p.name.lower()
            if (
                name.endswith((".yaml", ".yml"))
                or name == "dockerfile"
                or name.startswith("dockerfile.")
                or name.endswith(".dockerfile")
            ):
                file_paths.append(p)

    return scan_files(file_paths)
