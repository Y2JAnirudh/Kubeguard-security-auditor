"""
Unit tests for the optional Trivy container image vulnerability integration.
All tests use mocking so that Trivy installation is NOT required in CI or test runners.
"""

import json
import pytest
from unittest.mock import patch, MagicMock
import subprocess

from kube_guard.trivy import (
    is_trivy_available,
    get_trivy_status,
    scan_image_with_trivy,
)


def test_trivy_unavailable_by_default():
    """Verify behavior when Trivy binary is not present in PATH."""
    with patch("shutil.which", return_value=None):
        avail, ver = is_trivy_available()
        assert avail is False
        assert ver is None

        status = get_trivy_status()
        assert status["available"] is False
        assert "Trivy integration unavailable" in status["message"]
        assert "core KubeGuard static analysis remains fully functional" in status["message"]


def test_trivy_available_mocked():
    """Verify behavior when Trivy binary is present in PATH."""
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "Version: 0.50.0\n"

    with patch("shutil.which", return_value="/usr/local/bin/trivy"):
        with patch("subprocess.run", return_value=mock_proc):
            avail, ver = is_trivy_available()
            assert avail is True
            assert "0.50.0" in ver

            status = get_trivy_status()
            assert status["available"] is True


def test_scan_image_when_trivy_unavailable():
    """Verify scan returns informative fallback without crashing when Trivy is absent."""
    with patch("shutil.which", return_value=None):
        res = scan_image_with_trivy("alpine:3.19")
        assert res["available"] is False
        assert res["success"] is False
        assert "Trivy integration unavailable" in res["error"]


def test_scan_image_input_validation():
    """Verify strict validation against shell injection or invalid image strings."""
    # Empty string
    res_empty = scan_image_with_trivy("")
    assert res_empty["success"] is False

    # Command injection attempt
    res_inject = scan_image_with_trivy("alpine:3.19; cat /etc/passwd")
    assert res_inject["success"] is False
    assert "Invalid container image format" in res_inject["error"]

    res_pipe = scan_image_with_trivy("alpine:latest | bash")
    assert res_pipe["success"] is False


def test_scan_image_successful_parsing():
    """Verify successful parsing of Trivy JSON CVE output."""
    mock_trivy_json = {
        "Results": [
            {
                "Target": "python:3.11-slim (debian 12.5)",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-21626",
                        "PkgName": "runc",
                        "InstalledVersion": "1.1.10",
                        "FixedVersion": "1.1.11",
                        "Severity": "CRITICAL",
                        "Title": "runc container breakout vulnerability",
                        "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2024-21626"
                    },
                    {
                        "VulnerabilityID": "CVE-2023-45853",
                        "PkgName": "zlib1g",
                        "InstalledVersion": "1:1.2.13",
                        "FixedVersion": "1:1.2.14",
                        "Severity": "HIGH",
                        "Title": "Denial of service in zlib",
                        "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2023-45853"
                    },
                    {
                        "VulnerabilityID": "CVE-2023-38545",
                        "PkgName": "curl",
                        "InstalledVersion": "7.88.1",
                        "FixedVersion": "7.88.2",
                        "Severity": "MEDIUM",
                        "Title": "SOCKS5 heap buffer overflow",
                        "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2023-38545"
                    }
                ]
            }
        ]
    }

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = json.dumps(mock_trivy_json)

    with patch("shutil.which", return_value="/usr/bin/trivy"):
        with patch("subprocess.run", return_value=mock_proc):
            res = scan_image_with_trivy("python:3.11-slim")
            assert res["success"] is True
            assert res["available"] is True
            assert res["image"] == "python:3.11-slim"
            assert res["counts"]["CRITICAL"] == 1
            assert res["counts"]["HIGH"] == 1
            assert res["counts"]["MEDIUM"] == 1
            assert res["counts"]["LOW"] == 0
            assert res["total_vulnerabilities"] == 3
            assert len(res["vulnerabilities"]) == 3

            v0 = res["vulnerabilities"][0]
            assert v0["vulnerability_id"] == "CVE-2024-21626"
            assert v0["pkg_name"] == "runc"
            assert v0["severity"] == "CRITICAL"


def test_scan_image_timeout_handling():
    """Verify graceful handling when scan process times out."""
    with patch("shutil.which", return_value="/usr/bin/trivy"):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["trivy"], timeout=90)):
            res = scan_image_with_trivy("heavy-image:latest")
            assert res["success"] is False
            assert "timed out" in res["error"]
