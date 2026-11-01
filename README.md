# 🛡️ KubeGuard: Container & Kubernetes Security Auditor

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![React](https://img.shields.io/badge/React-19.0-61DAFB?style=flat&logo=react&logoColor=black)](https://react.dev/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Standards: PSS & CIS](https://img.shields.io/badge/Standards-Kubernetes%20PSS%20%7C%20CIS-blue)](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
[![Tests](https://img.shields.io/badge/tests-25%20passing-brightgreen)](https://pytest.org/)

**KubeGuard** is an open-source static security auditing tool designed to inspect Kubernetes YAML manifests and Dockerfiles before deployment. It identifies critical security misconfigurations, privilege escalations, excessive RBAC permissions, and insecure build patterns, translating raw infrastructure-as-code into an actionable security score and prioritized remediation plan.

---

## 🏛️ System Architecture

KubeGuard follows a decoupled, production-grade cybersecurity architecture:

```
┌─────────────────────────────────────────────────────────────┐
│              React 19 Security Dashboard                    │
│   (Tailwind CSS • Dark Cyber Theme • Real-time Charts)      │
└──────────────────────────────┬──────────────────────────────┘
                               │ REST API (/api/*)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                 FastAPI Python Service                      │
│   (server.py • Endpoints: /api/scan, /api/trivy/scan, etc.) │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│               KubeGuard Security Rule Engine                │
│  ├── 24 Kubernetes Rules (K8S-001..024)                     │
│  ├── 10 Dockerfile Rules (DOCKER-001..010)                  │
│  ├── Multi-Document YAML & Dockerfile Parsers               │
│  ├── Transparent Heuristic Scoring Engine (0-100)           │
│  ├── Standalone HTML Audit Report Generator                 │
│  └── Optional Trivy Integration (Container CVE Scanning)    │
└─────────────────────────────────────────────────────────────┘
                               ▲
                               │
┌──────────────────────────────┴──────────────────────────────┐
│           Command Line Interface & Automation (cli.py)      │
│         (CI/CD Pipeline integration with --strict mode)     │
└─────────────────────────────────────────────────────────────┘
```

> **Design Principle:** The React frontend contains **zero duplicated security logic**. All syntax analysis, rules evaluation, secret redacting, and score calculations remain strictly centralized within the Python security engine.

---

## 📌 Problem Statement

In modern cloud-native architectures, Kubernetes orchestrates millions of containers daily. However, **default Kubernetes and Docker configurations prioritize backwards compatibility and convenience over defense-in-depth**:
- By default, containers execute with unrestricted `root` (UID 0) privileges.
- Linux capabilities are retained, leaving processes vulnerable to kernel exploits.
- Insecure volume mounts (e.g., host `/` or `/var/run/docker.sock`) allow catastrophic container breakouts.
- Overly broad RBAC roles (`verbs: ["*"]`, `resources: ["*"]`) grant malicious or compromised services total cluster takeover capabilities.
- Developers frequently hardcode secrets or unpinned `:latest` tags in deployment manifests.

---

## 💡 Solution

**KubeGuard** bridges this gap by providing an instant, offline static configuration scanner:
1. **Multi-Source Analysis:** Parses multi-document Kubernetes manifests (`Deployment`, `StatefulSet`, `DaemonSet`, `Pod`, `Job`, `CronJob`, `Service`, `Ingress`, `RBAC`, `Secrets`, `ConfigMaps`) and `Dockerfiles`.
2. **Deterministic Risk Scoring:** Starts at 100 points and calculates transparent deductions based on vulnerability severity.
3. **Actionable Remediation Blueprints:** Rather than generic warning labels, KubeGuard delivers concrete YAML and Dockerfile snippets showing exact security corrections.
4. **Interactive Cyber Dashboard & CLI:** Offers an executive React dashboard alongside a CI/CD-friendly CLI.
5. **Standalone Audit Reports:** One-click generation of print-ready, styled HTML security reports for compliance submissions.

---

## 🛡️ Security Rules Reference

### Kubernetes Manifest Security Rules (`K8S-001` - `K8S-024`)

| Rule ID | Title | Severity | Category | Description |
| :--- | :--- | :--- | :--- | :--- |
| **K8S-001** | Privileged container detected | `CRITICAL` | Container Security | Flags `securityContext.privileged: true` granting unrestricted host access. |
| **K8S-002** | Container running as root | `HIGH` | Container Security | Detects `runAsUser: 0` or explicit `runAsNonRoot: false`. |
| **K8S-003** | runAsNonRoot not enforced | `MEDIUM` | Container Security | Identifies missing `runAsNonRoot: true` in container/pod security contexts. |
| **K8S-004** | Privilege escalation allowed | `HIGH` | Container Security | Detects `allowPrivilegeEscalation: true` or default unblocked status. |
| **K8S-005** | Host PID namespace enabled | `HIGH` | Pod Security | Detects `hostPID: true` sharing host process table. |
| **K8S-006** | Host network enabled | `HIGH` | Network Security | Detects `hostNetwork: true` bypassing cluster network policies. |
| **K8S-007** | Host IPC enabled | `HIGH` | Pod Security | Detects `hostIPC: true` exposing shared memory to the host node. |
| **K8S-008** | Dangerous Linux capabilities | `HIGH` | Container Security | Catches dangerous additions (`SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`, etc.). |
| **K8S-009** | Capabilities not dropped | `MEDIUM` | Container Security | Flags missing `drop: ["ALL"]` capability reduction. |
| **K8S-010** | Host filesystem mount detected | `HIGH` | Container Security | Catches `hostPath` volumes mounting sensitive host paths (`/`, `/var/run/docker.sock`). |
| **K8S-011** | Secret embedded in configuration | `CRITICAL` | Secrets | Detects credentials in plaintext environment variables; redacts values in reports. |
| **K8S-012** | Role grants wildcard permissions | `HIGH` | RBAC | Flags `*` wildcards in RBAC rules (`verbs: ["*"]`, `resources: ["*"]`). |
| **K8S-013** | ClusterRoleBinding grants admin | `HIGH` | RBAC | Detects bindings granting broad `cluster-admin` privileges. |
| **K8S-014** | CPU limits missing | `MEDIUM` | Resource Mgmt | Warns on missing `resources.limits.cpu` preventing noisy neighbor DoS. |
| **K8S-015** | Memory limits missing | `MEDIUM` | Resource Mgmt | Warns on missing `resources.limits.memory` preventing node-wide OOM kills. |
| **K8S-016** | Resource requests missing | `LOW` | Resource Mgmt | Detects missing CPU or memory requests required for scheduler decisions. |
| **K8S-017** | Ingress exposes service without TLS | `MEDIUM` | Network Security | Flags Ingress controllers missing `spec.tls` encrypted termination. |
| **K8S-018** | Service exposed via NodePort | `MEDIUM` | Network Security | Warns when services expose high node-level ports across cluster worker nodes. |
| **K8S-019** | Service exposed via LoadBalancer | `LOW` | Network Security | Identifies externally provisioned cloud load balancers. |
| **K8S-020** | Seccomp profile not configured | `MEDIUM` | Pod Security | Verifies `seccompProfile.type: RuntimeDefault` is enforced. |
| **K8S-021** | AppArmor profile missing | `LOW` | Pod Security | Advises adding Mandatory Access Control (MAC) profiles. |
| **K8S-022** | Container image uses :latest tag | `MEDIUM` | Image Security | Detects `:latest` tags causing non-deterministic rollouts. |
| **K8S-023** | Container image tag missing | `MEDIUM` | Image Security | Catches unversioned image references defaulting to latest. |
| **K8S-024** | Image registry provenance policy warning | `LOW` | Image Security | Hardening recommendation: Flags images lacking explicit enterprise registry prefix or cryptographic provenance digest. |

### Dockerfile Security Rules (`DOCKER-001` - `DOCKER-010`)

| Rule ID | Title | Severity | Description |
| :--- | :--- | :--- | :--- |
| **DOCKER-001** | Using latest tag in base image | `MEDIUM` | `FROM <image>:latest` introduces non-deterministic builds. |
| **DOCKER-002** | Running as root / USER omitted | `HIGH` | Container defaults to root execution without a `USER` directive. |
| **DOCKER-003** | Potential secrets in ENV | `HIGH` | Redacted credentials detected baked into immutable image layer metadata. |
| **DOCKER-004** | Potential secrets in ARG | `HIGH` | Build arguments with sensitive variable names found in image history. |
| **DOCKER-005** | ADD used instead of COPY | `MEDIUM` | `ADD` has risky tar-bomb auto-unpack and remote retrieval side-effects. |
| **DOCKER-006** | Unnecessary debugging utilities | `LOW` | Unneeded tools (`telnet`, `net-tools`, `gdb`) left in production image. |
| **DOCKER-007** | Piping curl/wget output to shell | `HIGH` | Executing remote scripts (`curl ... \| bash`) without sha256 checksums. |
| **DOCKER-008** | Retained package manager cache | `LOW` | Missing `rm -rf /var/lib/apt/lists/*` bloating image attack surface. |
| **DOCKER-009** | Unpinned base image | `MEDIUM` | `FROM <image>` without tag defaults to latest. |
| **DOCKER-010** | Dangerous command executed | `HIGH` | Detects `chmod 777`, `sudo`, or SSL verification bypass. |

---

## 📊 Deterministic Security Posture Score

KubeGuard begins each audit with a baseline score of **100 points**. Points are deducted deterministically for each security finding:

$$\text{Security Posture Score} = \max\left(0, 100 - \sum \text{Deductions}\right)$$

> **Disclaimer:** The Security Posture Score is a heuristic engineering metric reflecting configuration deviations from baseline security controls. It is designed for developer feedback and risk prioritization, not as a formal regulatory compliance certificate.

| Severity Level | Point Deduction | Rationale |
| :---: | :---: | :--- |
| **CRITICAL** | **-20 pts** | Direct host compromise or unrestricted root privilege escalation. |
| **HIGH** | **-10 pts** | Severe isolation bypass, host namespace leaks, or wildcard RBAC. |
| **MEDIUM** | **-5 pts** | Absence of baseline hardening controls (limits, TLS, seccomp). |
| **LOW** | **-2 pts** | Hygiene recommendations and defense-in-depth suggestions. |

### Risk Classification
- 🟢 **90 - 100 : LOW RISK** (Hardened configuration aligned with Pod Security Standards)
- 🟡 **70 - 89 : MODERATE RISK** (Acceptable baseline; minor hygiene or resource limits missing)
- 🟠 **40 - 69 : HIGH RISK** (Significant security weaknesses detected; remediation required)
- 🔴 **0 - 39 : CRITICAL RISK** (Severe vulnerabilities present; unsafe for cluster deployment)

---

## 💻 Installation & Local Run

### Prerequisites
- Python 3.11+
- Node.js 18+ & npm

```bash
# 1. Clone repository
git clone https://github.com/your-username/KubeGuard.git
cd KubeGuard

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Install frontend dependencies
npm install

# 4. Start the application (starts FastAPI backend + React Vite frontend)
npm run dev
```

Open `http://localhost:3000` in your browser.

---

## 🌐 FastAPI REST Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Health probe reporting service state, rule counts, and Trivy status. |
| `GET` | `/api/rules` | Complete catalogue of all 24 K8S rules and 10 Dockerfile rules. |
| `POST` | `/api/scan` | Audit submitted manifest/Dockerfile snippets or multiple files. |
| `POST` | `/api/scan/demo/vulnerable` | Evaluates the vulnerable benchmark app (`0/100`). |
| `POST` | `/api/scan/demo/secure` | Evaluates the hardened reference app (`96/100`). |
| `POST` | `/api/report` | Returns a standalone, styled HTML executive audit report. |
| `GET` | `/api/trivy/status` | Reports whether Trivy CLI is installed, version string, or fallback message. |
| `POST` | `/api/trivy/scan` | Runs safe Trivy CVE scan on user-supplied container image name (mockable). |

---

## 🔍 Security Tool Integration: Optional Trivy CVE Scanning

To provide defense-in-depth container security, KubeGuard features an **optional security tool integration** with **[Aqua Security's Trivy](https://github.com/aquasecurity/trivy)** for container image package vulnerability scanning.

### Architectural Separation & Rationale

| Dimension | KubeGuard Core Engine | Trivy External Integration |
| :--- | :--- | :--- |
| **Analysis Scope** | Infrastructure-as-Code (Kubernetes YAML & Dockerfile syntax) | Compiled container image OS packages & language dependencies |
| **Focus Area** | Misconfigurations, privilege escalation, RBAC, isolation bypass | Known CVE advisories (NVD, GitHub Security Advisories) |
| **Scoring / Output** | Deterministic 0-100 compliance score with strict deductions | Raw CVE counts categorized by CVSS severity (Critical, High, Medium, Low) |
| **Connectivity** | **100% offline** — zero network dependencies | Requires local image or registry access + vulnerability database |
| **Dependency Status** | **Core built-in** Python engine | **Strictly OPTIONAL** external CLI binary |

> **Why the scoring systems are NOT merged:**
> KubeGuard scores **configuration posture** under the developer's direct control (e.g. dropping Linux capabilities, setting resource limits). Merging external CVE counts (which fluctuate based on daily NVD updates and upstream base OS patch cycles) into the 0-100 configuration score would obscure whether a deployment's security settings are correctly configured. Instead, KubeGuard presents them side-by-side as complementary defense-in-depth dimensions.

### Graceful Degradation Without Trivy
- KubeGuard **never automatically downloads or executes binaries** from the internet.
- If Trivy is not installed on the host system, KubeGuard detects this via `shutil.which('trivy')` and clearly reports:
  > `"Trivy integration unavailable — core KubeGuard static analysis remains fully functional."`
- The React dashboard clearly indicates the unavailable status with an informational badge and quick setup guide, while all 24 Kubernetes rules, 10 Dockerfile rules, scoring, and report generation continue running at 100% functionality.

### Installing Trivy (Optional)
If you wish to enable container image CVE scanning:

```bash
# macOS (Homebrew)
brew install trivy

# Debian / Ubuntu Linux
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install trivy

# RedHat / CentOS
rpm -ivh https://github.com/aquasecurity/trivy/releases/download/v0.50.0/trivy_0.50.0_Linux-64bit.rpm
```

### Security Guardrails on Scans
- Input validation prevents shell injection via strict regex (`^[a-zA-Z0-9_./:@-]+$`).
- Subprocess execution enforces a strict 90-second timeout.
- The React dashboard includes a **"Preview Sample Trivy CVEs"** toggle for quick evaluation and demonstration even without external package scanning.

---

## ⌨️ Command Line Interface (CLI)

The Python CLI allows automated manifest audits in CI/CD pipelines without running any web servers:

```bash
# Scan a single manifest:
python3 cli.py examples/vulnerable-app/deployment.yaml

# Scan an entire directory:
python3 cli.py examples/vulnerable-app/

# Generate an HTML audit report via CLI:
python3 cli.py examples/vulnerable-app/ --format html -o audit-report.html

# Output JSON for CI/CD pipelines:
python3 cli.py examples/vulnerable-app/ --format json

# Strict mode (fails with exit code 1 if score < 70 or critical issues exist):
python3 cli.py examples/secure-app/ --strict
```

---

## 🧪 Testing

Run the automated test suite with `pytest`:

```bash
pytest -v
```

All **25 unit tests** validate:
- Privileged container, root user, and namespace leak detection (`test_k8s_rules.py`).
- Redaction of sensitive credentials in evidence strings.
- Dockerfile syntax rule evaluations (`test_docker_rules.py`).
- Scoring deduction mathematics and risk thresholds (`test_scoring.py`).
- Safe handling of malformed YAML input.
- **Trivy integration verification (`test_trivy_integration.py`):**
  - Graceful degradation when `trivy` binary is missing.
  - Image name sanitization and shell injection protection.
  - JSON output parsing into structured CVE summaries.
  - Mocked subprocess execution for CI environments without Trivy installed.

---

## ⚠️ Limitations & Honest Scope

KubeGuard is a **static configuration auditing tool** designed to catch misconfigurations before deployment.
- **Not a Live Penetration Testing Tool:** Does not simulate active network attacks or exploit running clusters.
- **Configuration vs. CVEs:** KubeGuard identifies configuration hygiene (e.g. unpinned tags, latest); for binary package CVEs, use the built-in **Trivy integration**.
- **Not a Runtime Threat Detector:** Does not intercept live system calls. In production, pair KubeGuard with eBPF runtime engines like **Falco**.
- **Not a Node CIS Auditor:** Audits manifests, not worker node OS configurations. Use **kube-bench** for node OS benchmarks.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
