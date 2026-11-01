# Hardened Reference Architecture (Secure Example)

This directory provides a **hardened, defense-in-depth Kubernetes application stack** designed to achieve a **HIGH security score (90-100)** in KubeGuard.

## Applied Security Controls

1. **Pod Security Standards (Restricted Profile):**
   - Non-root user execution (`runAsNonRoot: true`, `runAsUser: 10001`)
   - Read-only root filesystem (`readOnlyRootFilesystem: true`) with transient `/tmp` on memory `emptyDir`
   - Linux capabilities dropped completely (`drop: ["ALL"]`)
   - Privilege escalation blocked (`allowPrivilegeEscalation: false`)
   - Runtime default seccomp profile enabled (`seccompProfile: { type: "RuntimeDefault" }`)
   - Isolation namespaces preserved (`hostNetwork: false`, `hostPID: false`, `hostIPC: false`)
2. **Resource Governance & QoS:**
   - Both CPU and memory requests and limits defined to avoid noisy neighbors and OOM kills.
3. **Supply Chain & Image Pinning:**
   - Explicit immutable semantic tags (`payment-service:v1.4.2`).
4. **Secrets Management:**
   - Decoupled from manifests via Kubernetes `secretKeyRef`.
5. **Least-Privilege RBAC:**
   - Scope-limited `Role` instead of `ClusterRole`.
   - Granular read-only verbs (`get`, `list`, `watch`) on non-sensitive `configmaps`.
6. **Network Isolation:**
   - Internal `ClusterIP` instead of public node ports.
   - Encrypted TLS termination on Ingress with SSL redirect.
