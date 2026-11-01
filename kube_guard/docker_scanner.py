"""
KubeGuard Dockerfile Security Scanner
Static analysis for container image build configurations and Dockerfiles.
"""

import re
from typing import List, Tuple
from kube_guard.models import Finding, Severity, Category
from kube_guard.rules import redact_secret_value

# Suspicious build arguments and environment variables
SECRET_VAR_PATTERN = re.compile(
    r"(password|passwd|api_key|apikey|token|secret|private_key|auth_token|ssh_key)",
    re.IGNORECASE,
)

# Pipe to shell execution pattern
CURL_BASH_PATTERN = re.compile(
    r"(curl|wget)[^|\n]+(?:\|\s*(?:bash|sh|zsh|dash))",
    re.IGNORECASE,
)

# Dangerous Linux tools typically not needed in minimal runtime production containers
SUSPICIOUS_PACKAGES = [
    "net-tools",
    "telnet",
    "tcpdump",
    "nmap",
    "netcat",
    "nc",
    "gdb",
    "strace",
]


def scan_dockerfile_content(content: str, file_path: str = "Dockerfile") -> List[Finding]:
    """
    Parse and analyze Dockerfile line-by-line for security antipatterns.
    Returns structured Finding objects.
    """
    findings: List[Finding] = []
    lines = content.splitlines()

    has_user_directive = False
    has_from_directive = False
    base_image_lines: List[Tuple[int, str]] = []

    for line_idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # Check for FROM directive
        if line.upper().startswith("FROM "):
            has_from_directive = True
            parts = line.split()
            if len(parts) >= 2:
                base_image = parts[1]
                # DOCKER-001: Using latest tag
                if base_image.endswith(":latest"):
                    findings.append(Finding(
                        rule_id="DOCKER-001",
                        title="Using latest tag in base image",
                        severity=Severity.MEDIUM,
                        category=Category.BUILD_SECURITY,
                        file=file_path,
                        resource=f"Dockerfile:{line_idx}",
                        location=f"Line {line_idx}",
                        evidence=line,
                        impact="Using :latest base images introduces unpredictable build variations and risks breaking builds or deploying unverified upstream changes.",
                        remediation="Pin base images to a specific release tag or exact sha256 digest.",
                        remediation_yaml=f"FROM {base_image.split(':')[0]}:22.04@sha256:...",
                        references=["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#from"]
                    ))
                # DOCKER-009: Unpinned base image
                elif ":" not in base_image and "@" not in base_image and base_image.lower() != "scratch":
                    findings.append(Finding(
                        rule_id="DOCKER-009",
                        title="Unpinned base image tag",
                        severity=Severity.MEDIUM,
                        category=Category.BUILD_SECURITY,
                        file=file_path,
                        resource=f"Dockerfile:{line_idx}",
                        location=f"Line {line_idx}",
                        evidence=line,
                        impact="Base images without explicit tags default to :latest, resulting in non-deterministic builds.",
                        remediation="Explicitly specify a version tag on the FROM instruction.",
                        remediation_yaml=f"FROM {base_image}:3.19",
                        references=["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"]
                    ))

        # Check for USER directive
        if line.upper().startswith("USER "):
            user_val = line.split()[1].strip() if len(line.split()) > 1 else ""
            if user_val in ("0", "root"):
                findings.append(Finding(
                    rule_id="DOCKER-002",
                    title="Container explicitly configured to run as root user",
                    severity=Severity.HIGH,
                    category=Category.BUILD_SECURITY,
                    file=file_path,
                    resource=f"Dockerfile:{line_idx}",
                    location=f"Line {line_idx}",
                    evidence=line,
                    impact="Running container processes as root increases vulnerability impact if the application is compromised.",
                    remediation="Create a dedicated non-root user and switch to it using USER <user_id>.",
                    remediation_yaml="RUN useradd -u 10001 -m appuser\nUSER 10001",
                    references=["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user"]
                ))
            else:
                has_user_directive = True

        # Check for ENV secrets
        if line.upper().startswith("ENV "):
            env_content = line[4:].strip()
            # Match KEY=VAL or KEY VAL
            tokens = env_content.split("=", 1) if "=" in env_content else env_content.split(None, 1)
            if tokens:
                key = tokens[0].strip()
                val = tokens[1].strip() if len(tokens) > 1 else ""
                if SECRET_VAR_PATTERN.search(key):
                    redacted = redact_secret_value(val)
                    findings.append(Finding(
                        rule_id="DOCKER-003",
                        title="Potential secret embedded in ENV instruction",
                        severity=Severity.HIGH,
                        category=Category.SECRETS,
                        file=file_path,
                        resource=f"Dockerfile:{line_idx}",
                        location=f"Line {line_idx}",
                        evidence=f"ENV {key}={redacted}",
                        impact="Potential security concern: Environment variables declared via ENV are permanently baked into image layer metadata and visible via 'docker inspect'.",
                        remediation="Do not bake secrets into images. Mount secrets at runtime or use Docker BuildKit secret mounts (--mount=type=secret).",
                        remediation_yaml="# Use buildkit secret mount:\nRUN --mount=type=secret,id=mysecret cat /run/secrets/mysecret",
                        references=["https://docs.docker.com/build/building/secrets/"]
                    ))

        # Check for ARG secrets
        if line.upper().startswith("ARG "):
            arg_content = line[4:].strip()
            tokens = arg_content.split("=", 1)
            key = tokens[0].strip()
            val = tokens[1].strip() if len(tokens) > 1 else ""
            if SECRET_VAR_PATTERN.search(key):
                redacted = redact_secret_value(val) if val else "[NOT_SET_IN_FILE]"
                findings.append(Finding(
                    rule_id="DOCKER-004",
                    title="Potential secret in build ARG",
                    severity=Severity.HIGH,
                    category=Category.SECRETS,
                    file=file_path,
                    resource=f"Dockerfile:{line_idx}",
                    location=f"Line {line_idx}",
                    evidence=f"ARG {key}={redacted}",
                    impact="Potential security concern: Build arguments remain present in image build history unless multi-stage builds properly encapsulate them.",
                    remediation="Use BuildKit secret mounts (--mount=type=secret) rather than build ARGs for credentials.",
                    remediation_yaml="# Use build secrets instead of ARGs\n# docker build --secret id=api_key,src=token.txt .",
                    references=["https://docs.docker.com/build/building/secrets/"]
                ))

        # Check for ADD vs COPY
        if line.upper().startswith("ADD "):
            parts = line.split()
            # If not an archive (.tar, .gz) or remote URL, COPY is preferred
            if len(parts) >= 3:
                src = parts[1]
                if not (src.endswith(".tar") or src.endswith(".tar.gz") or src.endswith(".tgz")):
                    findings.append(Finding(
                        rule_id="DOCKER-005",
                        title="Use of ADD instruction where COPY is preferred",
                        severity=Severity.MEDIUM,
                        category=Category.BUILD_SECURITY,
                        file=file_path,
                        resource=f"Dockerfile:{line_idx}",
                        location=f"Line {line_idx}",
                        evidence=line,
                        impact="Potential security concern: ADD has complex auto-extraction and remote URL fetching behaviors that can introduce unexpected files or tar-bomb vulnerabilities.",
                        remediation="Use COPY instead of ADD for standard local file and directory copies.",
                        remediation_yaml=f"COPY {parts[1]} {parts[2]}",
                        references=["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#add-or-copy"]
                    ))

        # Check for remote scripts via curl/wget | sh
        if CURL_BASH_PATTERN.search(line):
            findings.append(Finding(
                rule_id="DOCKER-007",
                title="Piping curl or wget output directly to shell",
                severity=Severity.HIGH,
                category=Category.BUILD_SECURITY,
                file=file_path,
                resource=f"Dockerfile:{line_idx}",
                location=f"Line {line_idx}",
                evidence=line,
                impact="Piping remote scripts directly into bash executes unverified code without checksum validation, exposing builds to man-in-the-middle or upstream compromise.",
                remediation="Download the script, verify its cryptographic sha256 checksum, and inspect it prior to execution.",
                remediation_yaml="RUN curl -fsSL -o installer.sh https://example.com/install.sh \\\n    && echo 'expected_sha256  installer.sh' | sha256sum -c - \\\n    && sh installer.sh",
                references=["https://cwe.mitre.org/data/definitions/494.html"]
            ))

        # Check for package manager cache cleanup issues
        if "apt-get install" in line and not ("rm -rf /var/lib/apt/lists/*" in line or "rm -rf /var/cache/apt" in line):
            findings.append(Finding(
                rule_id="DOCKER-008",
                title="Package manager cache retained in image layer",
                severity=Severity.LOW,
                category=Category.BUILD_SECURITY,
                file=file_path,
                resource=f"Dockerfile:{line_idx}",
                location=f"Line {line_idx}",
                evidence=line,
                impact="Failing to clean apt lists bloats container image size and leaves unnecessary cache data.",
                remediation="Append '&& rm -rf /var/lib/apt/lists/*' to the apt-get install RUN command within the same layer.",
                remediation_yaml="RUN apt-get update && apt-get install -y --no-install-recommends pkg \\\n    && rm -rf /var/lib/apt/lists/*",
                references=["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#apt-get"]
            ))

        # Check for suspicious debugging/network tools
        for pkg in SUSPICIOUS_PACKAGES:
            if re.search(rf"\b(apt-get|apk|yum|dnf)\s+install[^\n]*\b{pkg}\b", line):
                findings.append(Finding(
                    rule_id="DOCKER-006",
                    title=f"Potential unnecessary debugging package installed ({pkg})",
                    severity=Severity.LOW,
                    category=Category.BUILD_SECURITY,
                    file=file_path,
                    resource=f"Dockerfile:{line_idx}",
                    location=f"Line {line_idx}",
                    evidence=line,
                    impact=f"Potential security concern: Including diagnostic utilities like '{pkg}' in production containers aids attackers in post-exploitation enumeration and pivoting.",
                    remediation="Employ multi-stage builds or omit diagnostic packages from production runtime images.",
                    remediation_yaml="# Remove unnecessary tools from final container image",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html"]
                ))

        # DOCKER-010: Potentially dangerous commands
        if "chmod 777" in line or "sudo " in line or "--insecure" in line:
            findings.append(Finding(
                rule_id="DOCKER-010",
                title="Potentially dangerous command detected in RUN instruction",
                severity=Severity.HIGH,
                category=Category.BUILD_SECURITY,
                file=file_path,
                resource=f"Dockerfile:{line_idx}",
                location=f"Line {line_idx}",
                evidence=line,
                impact="Potential security concern: Excessive permissions (chmod 777), sudo invocation, or SSL verification bypass introduce critical attack vectors.",
                remediation="Apply least-privilege POSIX file permissions (e.g. 755 or 644) and avoid sudo or disabling certificate checks.",
                remediation_yaml="RUN chmod 750 /app/entrypoint.sh",
                references=["https://cwe.mitre.org/data/definitions/732.html"]
            ))

    # DOCKER-002: Check if USER was never specified in Dockerfile
    if has_from_directive and not has_user_directive:
        findings.append(Finding(
            rule_id="DOCKER-002",
            title="USER directive not specified in Dockerfile",
            severity=Severity.HIGH,
            category=Category.BUILD_SECURITY,
            file=file_path,
            resource="Dockerfile",
            location="End of Dockerfile",
            evidence="No 'USER <username|uid>' instruction found in Dockerfile",
            impact="The container will default to executing as root (UID 0), granting full root capabilities inside the container namespace.",
            remediation="Add a non-root user and add 'USER <user>' before CMD or ENTRYPOINT.",
            remediation_yaml="RUN groupadd -r app && useradd -r -g app -u 10001 app\nUSER 10001",
            references=["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user"]
        ))

    return findings
