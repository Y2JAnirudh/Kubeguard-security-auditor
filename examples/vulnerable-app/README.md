# Intentionally Vulnerable Application (Demo Scenario)

> **WARNING:** The manifests and configurations in this directory are **intentionally insecure** and designed strictly for educational testing, vulnerability auditing benchmarking, and classroom demonstrations with **KubeGuard**.
> **NEVER apply these manifests to a production Kubernetes cluster.**
> All credentials and API keys in these files are dummy demonstration strings (e.g., `DEMO_NOT_A_REAL_PASSWORD`).

## Included Misconfigurations

| Component | Rule ID | Security Flaw |
| :--- | :--- | :--- |
| `deployment.yaml` | `K8S-001` | **Privileged Container:** Container runs with `--privileged` |
| `deployment.yaml` | `K8S-002` | **Root User:** Explicitly runs as UID 0 |
| `deployment.yaml` | `K8S-004` | **Privilege Escalation:** `allowPrivilegeEscalation: true` |
| `deployment.yaml` | `K8S-005` | **Host PID:** Container shares host process ID namespace |
| `deployment.yaml` | `K8S-006` | **Host Network:** Container bypasses network policy via host network |
| `deployment.yaml` | `K8S-007` | **Host IPC:** Container shares host inter-process communication |
| `deployment.yaml` | `K8S-008` | **Dangerous Capabilities:** Added `SYS_ADMIN` and `NET_ADMIN` |
| `deployment.yaml` | `K8S-009` | **Capabilities Not Dropped:** Missing `drop: [ALL]` |
| `deployment.yaml` | `K8S-010` | **Host Filesystem Mount:** Mounts host root `/` and `/var/run/docker.sock` |
| `deployment.yaml` | `K8S-011` | **Hardcoded Secrets:** Plaintext credentials embedded in `env` |
| `deployment.yaml` | `K8S-014` | **Missing Limits:** No CPU limits configured |
| `deployment.yaml` | `K8S-015` | **Missing Limits:** No memory limits configured |
| `deployment.yaml` | `K8S-022` | **Unpinned Image:** Uses `:latest` tag |
| `service.yaml` | `K8S-018` | **NodePort:** Exposes application directly on high node port |
| `rbac.yaml` | `K8S-012` | **Wildcard Role:** Grants `*` on all resources and verbs |
| `rbac.yaml` | `K8S-013` | **Super-Admin Binding:** Binds service account to `cluster-admin` |
| `secret.yaml` | `K8S-011` | **Plaintext stringData:** Plain credentials committed to manifest |
| `ingress.yaml` | `K8S-017` | **Unencrypted Traffic:** No TLS configuration block |
| `Dockerfile` | `DOCKER-001..010` | Uses latest, runs as root, uncleaned apt cache, curl piped to bash |
