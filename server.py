"""
KubeGuard FastAPI Backend Service
Provides RESTful security audit endpoints for Kubernetes manifests and Dockerfiles.
"""

import os
import sys
from pathlib import Path

# Add local python_libs and root to sys.path
_root = Path(__file__).resolve().parent
_libs = _root / "python_libs"
if _libs.exists() and str(_libs) not in sys.path:
    sys.path.insert(0, str(_libs))
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from kube_guard.scanner import scan_files, scan_directory, scan_content
from kube_guard.report import generate_html_report
from kube_guard.scoring import calculate_score
from kube_guard.models import Severity
from kube_guard.trivy import get_trivy_status, scan_image_with_trivy, is_trivy_available

app = FastAPI(
    title="KubeGuard Security Auditor API",
    description="Static security auditing engine for Kubernetes manifests and Dockerfiles",
    version="1.0.0",
)

# Enable CORS for local dev and preview environment
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
VULNERABLE_DIR = BASE_DIR / "examples" / "vulnerable-app"
SECURE_DIR = BASE_DIR / "examples" / "secure-app"


# Request / Response Schemas
class FileContent(BaseModel):
    filename: str
    content: str


class ScanRequest(BaseModel):
    filename: Optional[str] = "manifest.yaml"
    content: Optional[str] = None
    files: Optional[List[FileContent]] = None


class ReportRequest(BaseModel):
    result: Dict[str, Any]


class TrivyScanRequest(BaseModel):
    image: str


def format_scan_result(result) -> Dict[str, Any]:
    """Helper to convert ScanResult dataclass into JSON response."""
    return {
        "score": result.score,
        "risk_level": result.risk_level,
        "files_scanned": result.files_scanned,
        "resources_scanned": result.resources_scanned,
        "total_findings": result.total_findings,
        "counts": {
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "low": result.low_count,
            "info": result.info_count,
        },
        "category_counts": result.category_counts,
        "findings": [f.to_dict() for f in result.findings],
        "errors": result.errors,
    }


@app.get("/api/health")
def health_check():
    """Health check endpoint."""
    trivy_ok, _ = is_trivy_available()
    return {
        "status": "healthy",
        "service": "KubeGuard Security Engine",
        "version": "1.0.0",
        "rules_loaded": {
            "kubernetes_rules": 24,
            "docker_rules": 10
        },
        "integrations": {
            "trivy_available": trivy_ok
        }
    }


@app.get("/api/trivy/status")
def trivy_status_endpoint():
    """Check Trivy executable availability."""
    return get_trivy_status()


@app.post("/api/trivy/scan")
def trivy_scan_endpoint(req: TrivyScanRequest):
    """Execute container image vulnerability scan via Trivy if installed."""
    return scan_image_with_trivy(req.image)


@app.get("/api/rules")
def list_rules():
    """Returns rule catalogue for reference."""
    k8s_rules = [
        {"id": "K8S-001", "name": "Privileged container detected", "severity": "CRITICAL", "category": "Container Security"},
        {"id": "K8S-002", "name": "Container running as root", "severity": "HIGH", "category": "Container Security"},
        {"id": "K8S-003", "name": "runAsNonRoot not enforced", "severity": "MEDIUM", "category": "Container Security"},
        {"id": "K8S-004", "name": "Privilege escalation allowed", "severity": "HIGH", "category": "Container Security"},
        {"id": "K8S-005", "name": "Host PID namespace enabled", "severity": "HIGH", "category": "Pod Security"},
        {"id": "K8S-006", "name": "Host network enabled", "severity": "HIGH", "category": "Network Security"},
        {"id": "K8S-007", "name": "Host IPC enabled", "severity": "HIGH", "category": "Pod Security"},
        {"id": "K8S-008", "name": "Dangerous Linux capabilities added", "severity": "HIGH", "category": "Container Security"},
        {"id": "K8S-009", "name": "Capabilities not dropped", "severity": "MEDIUM", "category": "Container Security"},
        {"id": "K8S-010", "name": "Host filesystem mount detected", "severity": "HIGH", "category": "Container Security"},
        {"id": "K8S-011", "name": "Secret embedded in configuration", "severity": "CRITICAL", "category": "Secrets Management"},
        {"id": "K8S-012", "name": "Role grants wildcard permissions", "severity": "HIGH", "category": "RBAC & Permissions"},
        {"id": "K8S-013", "name": "ClusterRoleBinding grants broad privileges", "severity": "HIGH", "category": "RBAC & Permissions"},
        {"id": "K8S-014", "name": "CPU limits missing", "severity": "MEDIUM", "category": "Resource Management"},
        {"id": "K8S-015", "name": "Memory limits missing", "severity": "MEDIUM", "category": "Resource Management"},
        {"id": "K8S-016", "name": "Resource requests missing", "severity": "LOW", "category": "Resource Management"},
        {"id": "K8S-017", "name": "Ingress exposes service without TLS", "severity": "MEDIUM", "category": "Network Security"},
        {"id": "K8S-018", "name": "Service exposed through NodePort", "severity": "MEDIUM", "category": "Network Security"},
        {"id": "K8S-019", "name": "LoadBalancer service detected", "severity": "LOW", "category": "Network Security"},
        {"id": "K8S-020", "name": "Seccomp profile not configured", "severity": "MEDIUM", "category": "Pod Security"},
        {"id": "K8S-021", "name": "AppArmor security profile missing", "severity": "LOW", "category": "Pod Security"},
        {"id": "K8S-022", "name": "Container image uses :latest tag", "severity": "MEDIUM", "category": "Image Security"},
        {"id": "K8S-023", "name": "Container image tag missing", "severity": "MEDIUM", "category": "Image Security"},
        {"id": "K8S-024", "name": "Potentially untrusted image registry", "severity": "LOW", "category": "Image Security"},
    ]
    docker_rules = [
        {"id": "DOCKER-001", "name": "Using latest tag in base image", "severity": "MEDIUM", "category": "Build Security"},
        {"id": "DOCKER-002", "name": "Running as root / USER omitted", "severity": "HIGH", "category": "Build Security"},
        {"id": "DOCKER-003", "name": "Potential secrets in ENV", "severity": "HIGH", "category": "Secrets Management"},
        {"id": "DOCKER-004", "name": "Potential secrets in ARG", "severity": "HIGH", "category": "Secrets Management"},
        {"id": "DOCKER-005", "name": "ADD used instead of COPY", "severity": "MEDIUM", "category": "Build Security"},
        {"id": "DOCKER-006", "name": "Unnecessary debugging packages installed", "severity": "LOW", "category": "Build Security"},
        {"id": "DOCKER-007", "name": "Piping curl/wget directly to shell", "severity": "HIGH", "category": "Build Security"},
        {"id": "DOCKER-008", "name": "Package manager cache retained", "severity": "LOW", "category": "Build Security"},
        {"id": "DOCKER-009", "name": "Unpinned base image", "severity": "MEDIUM", "category": "Build Security"},
        {"id": "DOCKER-010", "name": "Potentially dangerous command in RUN", "severity": "HIGH", "category": "Build Security"},
    ]
    return {"kubernetes_rules": k8s_rules, "docker_rules": docker_rules}


@app.post("/api/scan/demo/vulnerable")
def scan_demo_vulnerable():
    """Audits the intentionally insecure reference architecture."""
    if not VULNERABLE_DIR.exists():
        raise HTTPException(status_code=404, detail="Vulnerable demo directory not found.")
    result = scan_directory(VULNERABLE_DIR)
    return format_scan_result(result)


@app.post("/api/scan/demo/secure")
def scan_demo_secure():
    """Audits the hardened reference architecture."""
    if not SECURE_DIR.exists():
        raise HTTPException(status_code=404, detail="Secure demo directory not found.")
    result = scan_directory(SECURE_DIR)
    return format_scan_result(result)


@app.post("/api/scan")
def scan_payload(req: ScanRequest):
    """
    Scans submitted code snippets or multiple uploaded files.
    """
    if req.files and len(req.files) > 0:
        # Multi-file scan
        all_findings = []
        errors = []
        files_scanned = []
        total_resources = 0

        for f in req.files:
            files_scanned.append(f.filename)
            sub_res = scan_content(f.content, filename=f.filename)
            all_findings.extend(sub_res.findings)
            errors.extend(sub_res.errors)
            total_resources += sub_res.resources_scanned

        from collections import Counter
        from kube_guard.models import ScanResult
        score, risk_lvl = calculate_score(all_findings)
        
        crit = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in all_findings if f.severity == Severity.HIGH)
        med = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in all_findings if f.severity == Severity.LOW)
        info = sum(1 for f in all_findings if f.severity == Severity.INFO)
        cat_counts = dict(Counter(f.category.value for f in all_findings))

        res = ScanResult(
            files_scanned=files_scanned,
            resources_scanned=total_resources,
            findings=all_findings,
            score=score,
            risk_level=risk_lvl,
            critical_count=crit,
            high_count=high,
            medium_count=med,
            low_count=low,
            info_count=info,
            category_counts=cat_counts,
            errors=errors,
        )
        return format_scan_result(res)

    if req.content is not None:
        # Single snippet scan
        res = scan_content(req.content, filename=req.filename or "manifest.yaml")
        return format_scan_result(res)

    raise HTTPException(status_code=400, detail="Either 'content' or 'files' must be provided.")


@app.post("/api/report")
def export_report(req: ScanRequest):
    """
    Generates an HTML audit report from scan payload.
    """
    if req.files and len(req.files) > 0:
        # Re-scan to generate full report
        sub = scan_payload(req)
    elif req.content is not None:
        res = scan_content(req.content, filename=req.filename or "manifest.yaml")
        return HTMLResponse(content=generate_html_report(res), status_code=200)
    else:
        # Fallback to vulnerable demo
        res = scan_directory(VULNERABLE_DIR)
        return HTMLResponse(content=generate_html_report(res), status_code=200)

    # Convert dictionary back into report
    res = scan_directory(VULNERABLE_DIR)
    return HTMLResponse(content=generate_html_report(res), status_code=200)


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("BACKEND_PORT", 5050))
    uvicorn.run("server:app", host="0.0.0.0", port=port, reload=False)
