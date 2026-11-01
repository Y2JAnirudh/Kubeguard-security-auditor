"""
Unit tests for Dockerfile security scanner.
"""

from kube_guard.docker_scanner import scan_dockerfile_content
from kube_guard.models import Severity


def test_dockerfile_missing_user():
    content = """
FROM alpine:3.19
RUN apk add --no-cache curl
CMD ["sh"]
    """
    findings = scan_dockerfile_content(content)
    rule_ids = [f.rule_id for f in findings]
    assert "DOCKER-002" in rule_ids


def test_dockerfile_latest_tag():
    content = """
FROM python:latest
USER 10001
CMD ["python"]
    """
    findings = scan_dockerfile_content(content)
    rule_ids = [f.rule_id for f in findings]
    assert "DOCKER-001" in rule_ids


def test_dockerfile_secret_in_env():
    content = """
FROM python:3.11-slim
ENV API_KEY=my_secret_token_123456
USER 10001
    """
    findings = scan_dockerfile_content(content)
    rule_ids = [f.rule_id for f in findings]
    assert "DOCKER-003" in rule_ids
    f = next(item for item in findings if item.rule_id == "DOCKER-003")
    # Verify redacted: full secret is not in evidence
    assert "my_secret_token_123456" not in f.evidence
    assert "****" in f.evidence


def test_dockerfile_curl_bash():
    content = """
FROM ubuntu:22.04
RUN curl -fsSL https://get.docker.com | bash
USER 10001
    """
    findings = scan_dockerfile_content(content)
    rule_ids = [f.rule_id for f in findings]
    assert "DOCKER-007" in rule_ids
    f = next(item for item in findings if item.rule_id == "DOCKER-007")
    assert f.severity == Severity.HIGH


def test_dockerfile_uncleaned_apt_cache():
    content = """
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y git
USER 10001
    """
    findings = scan_dockerfile_content(content)
    rule_ids = [f.rule_id for f in findings]
    assert "DOCKER-008" in rule_ids


def test_dockerfile_add_instead_of_copy():
    content = """
FROM alpine:3.19
ADD app.py /app/app.py
USER 10001
    """
    findings = scan_dockerfile_content(content)
    rule_ids = [f.rule_id for f in findings]
    assert "DOCKER-005" in rule_ids
