"""
KubeGuard Optional Trivy Integration
External security tool integration for container image vulnerability scanning (CVEs).
Completely optional: does not execute or download Trivy automatically.
"""

import shutil
import subprocess
import json
import re
from typing import Dict, Any, Tuple, Optional, List


# Safe container image reference pattern (e.g., alpine:3.19, ghcr.io/org/repo:tag@sha256:...)
SAFE_IMAGE_REGEX = re.compile(r"^[a-zA-Z0-9_\.\-\/]+(:[a-zA-Z0-9_\.\-]+)?(@sha256:[a-fA-F0-9]{64})?$")


def is_trivy_available() -> Tuple[bool, Optional[str]]:
    """
    Check if the Trivy binary is installed and executable in system PATH.
    Never downloads or installs anything.
    """
    path = shutil.which("trivy")
    if not path:
        return False, None

    try:
        proc = subprocess.run(
            ["trivy", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.returncode == 0:
            first_line = proc.stdout.strip().splitlines()[0] if proc.stdout else "Trivy detected"
            return True, first_line
        return True, "Trivy installed (version query non-zero)"
    except Exception:
        return True, "Trivy detected in PATH"


def get_trivy_status() -> Dict[str, Any]:
    """Return status summary of Trivy availability."""
    available, version_info = is_trivy_available()
    if available:
        return {
            "available": True,
            "version": version_info,
            "message": "Trivy integration is available for container image CVE scanning.",
        }
    return {
        "available": False,
        "version": None,
        "message": "Trivy integration unavailable — core KubeGuard static analysis remains fully functional.",
    }


def scan_image_with_trivy(image_name: str) -> Dict[str, Any]:
    """
    Run an image vulnerability scan using Trivy if available.
    
    Security Controls:
    1. Validates image name regex to prevent shell argument injection.
    2. Runs subprocess with explicit argv list (no shell=True).
    3. Enforces execution timeout.
    4. Handles absence of Trivy without crashing.
    """
    image_name = image_name.strip()
    if not image_name:
        return {
            "success": False,
            "error": "No image reference provided.",
            "available": False,
        }

    if not SAFE_IMAGE_REGEX.match(image_name):
        return {
            "success": False,
            "error": "Invalid container image format. Use standard format like 'alpine:3.19' or 'python:3.11-slim'.",
            "available": False,
        }

    available, version_info = is_trivy_available()
    if not available:
        return {
            "success": False,
            "available": False,
            "error": "Trivy integration unavailable — core KubeGuard static analysis remains fully functional.",
            "notice": "Install Trivy on your system (e.g. 'brew install trivy' or 'apt install trivy') to enable image CVE scanning.",
        }

    try:
        proc = subprocess.run(
            ["trivy", "image", "--format", "json", "--quiet", image_name],
            capture_output=True,
            text=True,
            timeout=90,
        )

        if proc.returncode != 0 and not proc.stdout.strip():
            return {
                "success": False,
                "available": True,
                "image": image_name,
                "error": f"Trivy scan failed: {proc.stderr.strip() or 'Unknown error'}",
            }

        data = json.loads(proc.stdout)
        results = data.get("Results", [])

        vulns_list: List[Dict[str, Any]] = []
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}

        for r in results:
            target = r.get("Target", image_name)
            for v in r.get("Vulnerabilities", []):
                sev = v.get("Severity", "UNKNOWN").upper()
                counts[sev] = counts.get(sev, 0) + 1
                vulns_list.append({
                    "vulnerability_id": v.get("VulnerabilityID", "N/A"),
                    "pkg_name": v.get("PkgName", "N/A"),
                    "installed_version": v.get("InstalledVersion", "N/A"),
                    "fixed_version": v.get("FixedVersion", "None"),
                    "severity": sev,
                    "title": v.get("Title", v.get("Description", "No description available"))[:160],
                    "primary_url": v.get("PrimaryURL", ""),
                    "target": target,
                })

        return {
            "success": True,
            "available": True,
            "image": image_name,
            "version": version_info,
            "counts": counts,
            "total_vulnerabilities": len(vulns_list),
            "vulnerabilities": vulns_list[:50],  # Return top 50
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "available": True,
            "image": image_name,
            "error": "Trivy scan timed out after 90 seconds.",
        }
    except json.JSONDecodeError:
        return {
            "success": False,
            "available": True,
            "image": image_name,
            "error": "Failed to parse Trivy JSON output.",
        }
    except Exception as exc:
        return {
            "success": False,
            "available": True,
            "image": image_name,
            "error": f"Unexpected error during Trivy scan: {str(exc)}",
        }
