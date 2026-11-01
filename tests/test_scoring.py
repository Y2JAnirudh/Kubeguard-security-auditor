"""
Unit tests for scoring calculations and risk classifications.
"""

from kube_guard.scoring import calculate_score
from kube_guard.models import Finding, Severity, Category


def make_dummy_finding(severity: Severity) -> Finding:
    return Finding(
        rule_id="TEST-001",
        title="Test finding",
        description="Test",
        severity=severity,
        category=Category.CONTAINER_SECURITY,
        file="test.yaml",
        resource="Pod/test",
        evidence="evidence",
        impact="impact",
        remediation="fix",
    )


def test_perfect_score():
    score, risk_level = calculate_score([])
    assert score == 100
    assert risk_level == "LOW RISK"


def test_severity_deductions():
    # 1 Critical (-20)
    score_crit, _ = calculate_score([make_dummy_finding(Severity.CRITICAL)])
    assert score_crit == 80

    # 1 High (-10)
    score_high, _ = calculate_score([make_dummy_finding(Severity.HIGH)])
    assert score_high == 90

    # 1 Medium (-5)
    score_med, _ = calculate_score([make_dummy_finding(Severity.MEDIUM)])
    assert score_med == 95

    # 1 Low (-2)
    score_low, _ = calculate_score([make_dummy_finding(Severity.LOW)])
    assert score_low == 98


def test_score_does_not_go_below_zero():
    # 10 critical findings = -200 points
    findings = [make_dummy_finding(Severity.CRITICAL) for _ in range(10)]
    score, risk_level = calculate_score(findings)
    assert score == 0
    assert risk_level == "CRITICAL RISK"


def test_risk_level_thresholds():
    # 90-100: LOW RISK
    assert calculate_score([make_dummy_finding(Severity.LOW)])[1] == "LOW RISK"

    # 70-89: MODERATE RISK
    # Deduct 25 (1 Crit + 1 Med) -> 75
    f_mod = [make_dummy_finding(Severity.CRITICAL), make_dummy_finding(Severity.MEDIUM)]
    assert calculate_score(f_mod)[1] == "MODERATE RISK"

    # 40-69: HIGH RISK
    # Deduct 40 (2 Crit) -> 60
    f_high = [make_dummy_finding(Severity.CRITICAL) for _ in range(2)]
    assert calculate_score(f_high)[1] == "HIGH RISK"

    # 0-39: CRITICAL RISK
    # Deduct 70 -> 30
    f_crit = [make_dummy_finding(Severity.CRITICAL) for _ in range(3)] + [make_dummy_finding(Severity.HIGH)]
    assert calculate_score(f_crit)[1] == "CRITICAL RISK"
