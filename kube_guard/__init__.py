"""
KubeGuard - Container & Kubernetes Security Auditor
Static security auditing engine for Kubernetes manifests and Dockerfiles.
"""
import sys
from pathlib import Path

_root = Path(__file__).resolve().parent.parent
_libs = _root / "python_libs"
if _libs.exists() and str(_libs) not in sys.path:
    sys.path.insert(0, str(_libs))

from kube_guard.models import Finding, Severity, Category, ScanResult
from kube_guard.scanner import scan_files, scan_directory, scan_content
from kube_guard.scoring import calculate_score
from kube_guard.report import generate_html_report
from kube_guard.trivy import get_trivy_status, scan_image_with_trivy

__version__ = "1.0.0"
__all__ = [
    "Finding",
    "Severity",
    "Category",
    "ScanResult",
    "scan_files",
    "scan_directory",
    "scan_content",
    "calculate_score",
    "generate_html_report",
    "get_trivy_status",
    "scan_image_with_trivy",
]
