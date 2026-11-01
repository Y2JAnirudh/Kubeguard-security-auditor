"""
KubeGuard Security Scoring Engine
Transparent, deterministic heuristic scoring system.
"""

from typing import List, Tuple
from kube_guard.models import Finding, Severity

# Deduction weights per severity
SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}

SCORING_DISCLAIMER = (
    "Score is a heuristic based on detected configuration risks and should "
    "not be interpreted as a formal security certification."
)


def calculate_score(findings: List[Finding]) -> Tuple[int, str]:
    """
    Calculate an overall security score from 0 to 100 and determine risk level.
    
    Formula:
      score = max(0, 100 - sum(weight(f.severity) for f in findings))
      
    Risk Levels:
      90 - 100 : LOW RISK
      70 - 89  : MODERATE RISK
      40 - 69  : HIGH RISK
      0  - 39  : CRITICAL RISK
    """
    total_deduction = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
    score = max(0, 100 - total_deduction)

    if score >= 90:
        risk_level = "LOW RISK"
    elif score >= 70:
        risk_level = "MODERATE RISK"
    elif score >= 40:
        risk_level = "HIGH RISK"
    else:
        risk_level = "CRITICAL RISK"

    return score, risk_level


def get_risk_color(risk_level: str) -> str:
    """Return UI color associated with risk level."""
    colors = {
        "LOW RISK": "#22c55e",       # Green
        "MODERATE RISK": "#eab308",  # Yellow
        "HIGH RISK": "#f97316",      # Orange
        "CRITICAL RISK": "#ef4444",  # Red
    }
    return colors.get(risk_level, "#94a3b8")
