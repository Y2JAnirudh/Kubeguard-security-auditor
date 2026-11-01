"""
KubeGuard Kubernetes Security Rules Engine
Static rule implementations covering Pod Security Standards, RBAC, Resources, Networking, and Secrets.
"""

import re
from typing import List, Dict, Any, Optional
from kube_guard.models import Finding, Severity, Category
from kube_guard.parsers import ParsedResource


# Dangerous Linux capabilities often leveraged for container breakout
DANGEROUS_CAPABILITIES = {
    "SYS_ADMIN",
    "NET_ADMIN",
    "SYS_PTRACE",
    "SYS_RAWIO",
    "DAC_OVERRIDE",
    "NET_RAW",
    "SYS_MODULE",
    "SYS_BOOT",
    "MKNOD",
}

# Suspicious keyword patterns for embedded secrets in environment variables
SECRET_KEY_PATTERNS = re.compile(
    r"(password|passwd|api_key|apikey|token|secret|private_key|auth_token|access_key)",
    re.IGNORECASE,
)


def redact_secret_value(value: Any) -> str:
    """Safely redact secret values for evidence reporting."""
    s = str(value)
    if len(s) <= 4:
        return "****"
    return s[:2] + "****" + s[-2:]


def evaluate_kubernetes_rules(resource: ParsedResource) -> List[Finding]:
    """Evaluate all applicable Kubernetes security rules against a parsed resource."""
    findings: List[Finding] = []

    # 1. Pod & Container Security Rules (apply if pod spec exists)
    pod_spec = resource.get_pod_spec()
    if pod_spec is not None:
        findings.extend(_check_pod_spec_rules(resource, pod_spec))
        for ctype, container, cname in resource.get_all_containers():
            findings.extend(_check_container_rules(resource, pod_spec, ctype, container, cname))

    # 2. RBAC Rules
    if resource.kind in ("ClusterRole", "Role"):
        findings.extend(_check_role_rules(resource))
    elif resource.kind in ("ClusterRoleBinding", "RoleBinding"):
        findings.extend(_check_binding_rules(resource))

    # 3. Networking Rules (Service, Ingress)
    if resource.kind == "Service":
        findings.extend(_check_service_rules(resource))
    elif resource.kind == "Ingress":
        findings.extend(_check_ingress_rules(resource))

    # 4. Secret embedded in plain manifest / ConfigMap
    if resource.kind == "ConfigMap":
        findings.extend(_check_configmap_secrets(resource))
    elif resource.kind == "Secret":
        findings.extend(_check_secret_resource(resource))

    return findings


# ============================================================================
# POD SPEC RULES
# ============================================================================

def _check_pod_spec_rules(res: ParsedResource, pod_spec: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    pod_sec = pod_spec.get("securityContext") or {}

    # K8S-005: Host PID namespace enabled
    if pod_spec.get("hostPID") is True:
        findings.append(Finding(
            rule_id="K8S-005",
            title="Host PID namespace enabled",
            severity=Severity.HIGH,
            category=Category.POD_SECURITY,
            file=res.file_path,
            resource=res.resource_id,
            location="spec.template.spec.hostPID",
            evidence="hostPID: true",
            impact="The container shares the host's process ID namespace, allowing it to inspect, attach to, and potentially signal processes running on the host.",
            remediation="Remove hostPID: true or set hostPID: false.",
            remediation_yaml="spec:\n  hostPID: false",
            references=["https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline"]
        ))

    # K8S-006: Host network enabled
    if pod_spec.get("hostNetwork") is True:
        findings.append(Finding(
            rule_id="K8S-006",
            title="Host network enabled",
            severity=Severity.HIGH,
            category=Category.NETWORK_SECURITY,
            file=res.file_path,
            resource=res.resource_id,
            location="spec.template.spec.hostNetwork",
            evidence="hostNetwork: true",
            impact="The container shares the host network namespace, bypassing network policies, exposing loopback services, and enabling network sniffing on the node.",
            remediation="Disable hostNetwork by setting hostNetwork: false and use standard Kubernetes Services/Ingress.",
            remediation_yaml="spec:\n  hostNetwork: false",
            references=["https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline"]
        ))

    # K8S-007: Host IPC enabled
    if pod_spec.get("hostIPC") is True:
        findings.append(Finding(
            rule_id="K8S-007",
            title="Host IPC enabled",
            severity=Severity.HIGH,
            category=Category.POD_SECURITY,
            file=res.file_path,
            resource=res.resource_id,
            location="spec.template.spec.hostIPC",
            evidence="hostIPC: true",
            impact="Sharing the host IPC namespace allows inter-process communication with host processes and shared memory segment access.",
            remediation="Remove hostIPC: true or set hostIPC: false.",
            remediation_yaml="spec:\n  hostIPC: false",
            references=["https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline"]
        ))

    # K8S-010: Host filesystem mount detected (hostPath volumes)
    volumes = pod_spec.get("volumes")
    if isinstance(volumes, list):
        for vol in volumes:
            if isinstance(vol, dict) and "hostPath" in vol:
                hp = vol.get("hostPath") or {}
                hp_path = hp.get("path", "unknown")
                findings.append(Finding(
                    rule_id="K8S-010",
                    title="Host filesystem mount detected",
                    severity=Severity.HIGH,
                    category=Category.CONTAINER_SECURITY,
                    file=res.file_path,
                    resource=res.resource_id,
                    location=f"spec.template.spec.volumes[name={vol.get('name')}]",
                    evidence=f"hostPath: {{ path: \"{hp_path}\" }}",
                    impact="Mounting host directories grants container access to underlying node storage, sensitive sockets (/var/run/docker.sock), or critical host files.",
                    remediation="Use PersistentVolumeClaims (PVC), ConfigMaps, or EmptyDir instead of mounting the host filesystem.",
                    remediation_yaml="volumes:\n  - name: app-storage\n    persistentVolumeClaim:\n      claimName: app-pvc",
                    references=["https://kubernetes.io/docs/concepts/storage/volumes/#hostpath"]
                ))

    # K8S-020: Seccomp profile not configured
    seccomp = pod_sec.get("seccompProfile") or {}
    seccomp_type = seccomp.get("type")
    if seccomp_type not in ("RuntimeDefault", "Localhost"):
        findings.append(Finding(
            rule_id="K8S-020",
            title="Seccomp profile not configured",
            severity=Severity.MEDIUM,
            category=Category.POD_SECURITY,
            file=res.file_path,
            resource=res.resource_id,
            location="spec.template.spec.securityContext.seccompProfile",
            evidence=f"seccompProfile.type = {seccomp_type or 'None'}",
            impact="Without a seccomp profile, containers can issue arbitrary system calls allowed by the Linux kernel, expanding the kernel exploit surface.",
            remediation="Configure the seccompProfile type as RuntimeDefault in the pod securityContext.",
            remediation_yaml="spec:\n  securityContext:\n    seccompProfile:\n      type: RuntimeDefault",
            references=["https://kubernetes.io/docs/tutorials/security/seccomp/"]
        ))

    # K8S-021: AppArmor profile missing or unconfined
    # Checked via annotations or appArmorProfile field (K8s 1.30+)
    metadata = res.doc.get("spec", {}).get("template", {}).get("metadata", {}) if res.kind != "Pod" else res.doc.get("metadata", {})
    annotations = (metadata.get("annotations") or {}) if isinstance(metadata, dict) else {}
    has_apparmor_ann = any("apparmor.security.beta.kubernetes.io" in k for k in annotations.keys())
    has_apparmor_sec = bool(pod_sec.get("appArmorProfile"))
    if not (has_apparmor_ann or has_apparmor_sec):
        findings.append(Finding(
            rule_id="K8S-021",
            title="AppArmor security profile missing",
            severity=Severity.LOW,
            category=Category.POD_SECURITY,
            file=res.file_path,
            resource=res.resource_id,
            location="spec.template.metadata.annotations",
            evidence="No AppArmor profile annotation or appArmorProfile field defined",
            impact="Lack of Mandatory Access Control (MAC) profile reduces defense-in-depth isolation against kernel-level attacks.",
            remediation="Specify a default or custom AppArmor profile (e.g., runtime/default).",
            remediation_yaml="metadata:\n  annotations:\n    container.apparmor.security.beta.kubernetes.io/container-name: runtime/default",
            references=["https://kubernetes.io/docs/tutorials/security/apparmor/"]
        ))

    return findings


# ============================================================================
# CONTAINER SPEC RULES
# ============================================================================

def _check_container_rules(
    res: ParsedResource,
    pod_spec: Dict[str, Any],
    ctype: str,
    c: Dict[str, Any],
    cname: str
) -> List[Finding]:
    findings: List[Finding] = []
    c_sec = c.get("securityContext") or {}
    p_sec = pod_spec.get("securityContext") or {}

    # K8S-001: Privileged container detected
    if c_sec.get("privileged") is True:
        findings.append(Finding(
            rule_id="K8S-001",
            title="Privileged container detected",
            severity=Severity.CRITICAL,
            category=Category.CONTAINER_SECURITY,
            file=res.file_path,
            resource=f"{res.resource_id} (container: {cname})",
            location=f"spec.template.spec.{ctype}[name={cname}].securityContext.privileged",
            evidence="securityContext.privileged: true",
            impact="Privileged containers inherit virtually all host capabilities, access raw devices, and can easily break out of container isolation to compromise the host node.",
            remediation="Set securityContext.privileged: false and grant only specific minimal capabilities if needed.",
            remediation_yaml=f"containers:\n  - name: {cname}\n    securityContext:\n      privileged: false",
            references=["https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted"]
        ))

    # K8S-002: Container running as root
    run_as_user = c_sec.get("runAsUser")
    pod_run_as_user = p_sec.get("runAsUser")
    effective_user = run_as_user if run_as_user is not None else pod_run_as_user
    explicit_root_false = (c_sec.get("runAsNonRoot") is False) or (p_sec.get("runAsNonRoot") is False)

    if effective_user == 0 or explicit_root_false:
        ev = f"runAsUser: {effective_user}" if effective_user == 0 else "runAsNonRoot: false"
        findings.append(Finding(
            rule_id="K8S-002",
            title="Container running as root",
            severity=Severity.HIGH,
            category=Category.CONTAINER_SECURITY,
            file=res.file_path,
            resource=f"{res.resource_id} (container: {cname})",
            location=f"spec.template.spec.{ctype}[name={cname}].securityContext",
            evidence=ev,
            impact="Processes running as root (UID 0) inside a container have standard root system permissions, dramatically increasing the fallout of a container breakout.",
            remediation="Specify a non-root UID (e.g. runAsUser: 10001) and enforce runAsNonRoot: true.",
            remediation_yaml=f"securityContext:\n  runAsUser: 10001\n  runAsGroup: 10001\n  runAsNonRoot: true",
            references=["https://kubernetes.io/docs/tasks/configure-pod-container/security-context/"]
        ))

    # K8S-003: runAsNonRoot not enforced
    run_as_non_root = c_sec.get("runAsNonRoot")
    pod_run_as_non_root = p_sec.get("runAsNonRoot")
    if (run_as_non_root is None and pod_run_as_non_root is None) or (run_as_non_root is False and not explicit_root_false):
        findings.append(Finding(
            rule_id="K8S-003",
            title="runAsNonRoot not enforced",
            severity=Severity.MEDIUM,
            category=Category.CONTAINER_SECURITY,
            file=res.file_path,
            resource=f"{res.resource_id} (container: {cname})",
            location=f"spec.template.spec.{ctype}[name={cname}].securityContext.runAsNonRoot",
            evidence="runAsNonRoot is not set to true",
            impact="Without explicit enforcement, containers may fall back to root UID from the container image without runtime warning or prevention.",
            remediation="Set runAsNonRoot: true in the container or pod securityContext.",
            remediation_yaml="securityContext:\n  runAsNonRoot: true",
            references=["https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted"]
        ))

    # K8S-004: Privilege escalation allowed
    allow_priv_esc = c_sec.get("allowPrivilegeEscalation")
    if allow_priv_esc is True or allow_priv_esc is None:
        findings.append(Finding(
            rule_id="K8S-004",
            title="Privilege escalation allowed",
            severity=Severity.HIGH,
            category=Category.CONTAINER_SECURITY,
            file=res.file_path,
            resource=f"{res.resource_id} (container: {cname})",
            location=f"spec.template.spec.{ctype}[name={cname}].securityContext.allowPrivilegeEscalation",
            evidence=f"allowPrivilegeEscalation: {allow_priv_esc if allow_priv_esc is not None else 'default (true)'}",
            impact="Allows child processes to gain more privileges than their parent process via setuid/setgid binaries, facilitating local privilege escalation.",
            remediation="Explicitly set allowPrivilegeEscalation: false in container securityContext.",
            remediation_yaml="securityContext:\n  allowPrivilegeEscalation: false",
            references=["https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted"]
        ))

    # K8S-008: Dangerous Linux capabilities
    caps = c_sec.get("capabilities") or {}
    added_caps = [str(x).upper() for x in (caps.get("add") or [])]
    dangerous_found = [cap for cap in added_caps if cap in DANGEROUS_CAPABILITIES or cap == "ALL"]
    if dangerous_found:
        findings.append(Finding(
            rule_id="K8S-008",
            title="Dangerous Linux capabilities added",
            severity=Severity.HIGH,
            category=Category.CONTAINER_SECURITY,
            file=res.file_path,
            resource=f"{res.resource_id} (container: {cname})",
            location=f"spec.template.spec.{ctype}[name={cname}].securityContext.capabilities.add",
            evidence=f"capabilities.add: {dangerous_found}",
            impact=f"Capabilities {dangerous_found} bypass critical kernel security controls, permitting raw network packet forgery, kernel debugging, or container escape.",
            remediation="Remove dangerous capabilities from the 'add' list. Only grant least-privilege POSIX capabilities.",
            remediation_yaml="securityContext:\n  capabilities:\n    drop:\n      - ALL\n    add:\n      - NET_BIND_SERVICE",
            references=["https://man7.org/linux/man-pages/man7/capabilities.7.html"]
        ))

    # K8S-009: Capabilities not dropped
    dropped_caps = [str(x).upper() for x in (caps.get("drop") or [])]
    if "ALL" not in dropped_caps:
        findings.append(Finding(
            rule_id="K8S-009",
            title="Capabilities not dropped",
            severity=Severity.MEDIUM,
            category=Category.CONTAINER_SECURITY,
            file=res.file_path,
            resource=f"{res.resource_id} (container: {cname})",
            location=f"spec.template.spec.{ctype}[name={cname}].securityContext.capabilities.drop",
            evidence=f"capabilities.drop: {dropped_caps if dropped_caps else 'None'}",
            impact="Containers retain Linux kernel default capabilities that are unnecessary for normal execution, widening the exploitation vector.",
            remediation="Drop all capabilities by specifying 'drop: [ALL]' and only re-add strictly needed capabilities.",
            remediation_yaml="securityContext:\n  capabilities:\n    drop:\n      - ALL",
            references=["https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted"]
        ))

    # K8S-011: Secret embedded directly in configuration (env vars)
    env_vars = c.get("env") or []
    if isinstance(env_vars, list):
        for item in env_vars:
            if isinstance(item, dict) and "name" in item:
                key = str(item.get("name", ""))
                val = item.get("value")
                if val is not None and SECRET_KEY_PATTERNS.search(key):
                    redacted = redact_secret_value(val)
                    findings.append(Finding(
                        rule_id="K8S-011",
                        title="Secret embedded directly in container environment",
                        severity=Severity.CRITICAL,
                        category=Category.SECRETS,
                        file=res.file_path,
                        resource=f"{res.resource_id} (container: {cname})",
                        location=f"spec.template.spec.{ctype}[name={cname}].env[name={key}]",
                        evidence=f"env: - name: {key}, value: \"{redacted}\"",
                        impact="Hardcoding credentials or tokens in manifests exposes them in git repositories, logs, kubectl describe commands, and cluster audits.",
                        remediation="Store secrets in Kubernetes Secret objects and reference them using valueFrom.secretKeyRef.",
                        remediation_yaml=f"env:\n  - name: {key}\n    valueFrom:\n      secretKeyRef:\n        name: app-credentials\n        key: {key.lower()}",
                        references=["https://kubernetes.io/docs/concepts/configuration/secret/"]
                    ))

    # K8S-014: CPU limits missing
    resources = c.get("resources") or {}
    limits = resources.get("limits") or {}
    requests = resources.get("requests") or {}

    if not limits.get("cpu"):
        findings.append(Finding(
            rule_id="K8S-014",
            title="CPU limits missing",
            severity=Severity.MEDIUM,
            category=Category.RESOURCE_MANAGEMENT,
            file=res.file_path,
            resource=f"{res.resource_id} (container: {cname})",
            location=f"spec.template.spec.{ctype}[name={cname}].resources.limits.cpu",
            evidence="resources.limits.cpu is missing",
            impact="A runaway process or Denial of Service (DoS) attack could consume all CPU capacity on the node, starving co-located workloads.",
            remediation="Define explicit CPU limits in resources.limits.cpu (e.g. 500m).",
            remediation_yaml="resources:\n  limits:\n    cpu: \"500m\"\n    memory: \"512Mi\"",
            references=["https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/"]
        ))

    # K8S-015: Memory limits missing
    if not limits.get("memory"):
        findings.append(Finding(
            rule_id="K8S-015",
            title="Memory limits missing",
            severity=Severity.MEDIUM,
            category=Category.RESOURCE_MANAGEMENT,
            file=res.file_path,
            resource=f"{res.resource_id} (container: {cname})",
            location=f"spec.template.spec.{ctype}[name={cname}].resources.limits.memory",
            evidence="resources.limits.memory is missing",
            impact="Memory leaks or memory-exhaustion attacks could trigger node-wide OOM (Out of Memory) kills, crashing critical cluster processes.",
            remediation="Define explicit memory limits in resources.limits.memory (e.g. 512Mi).",
            remediation_yaml="resources:\n  limits:\n    memory: \"512Mi\"",
            references=["https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/"]
        ))

    # K8S-016: Resource requests missing
    if not requests.get("cpu") or not requests.get("memory"):
        missing_req = []
        if not requests.get("cpu"):
            missing_req.append("cpu")
        if not requests.get("memory"):
            missing_req.append("memory")
        findings.append(Finding(
            rule_id="K8S-016",
            title="Resource requests missing",
            severity=Severity.LOW,
            category=Category.RESOURCE_MANAGEMENT,
            file=res.file_path,
            resource=f"{res.resource_id} (container: {cname})",
            location=f"spec.template.spec.{ctype}[name={cname}].resources.requests",
            evidence=f"Missing requests for: {', '.join(missing_req)}",
            impact="The Kubernetes scheduler cannot make informed scheduling decisions without requests, risking node overcommitment.",
            remediation="Set both cpu and memory requests to match expected baseline workload usage.",
            remediation_yaml="resources:\n  requests:\n    cpu: \"100m\"\n    memory: \"128Mi\"",
            references=["https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/"]
        ))

    # K8S-022 & K8S-023 & K8S-024: Image tag rules
    image = str(c.get("image", ""))
    if image:
        if image.endswith(":latest") or ":latest@" in image:
            findings.append(Finding(
                rule_id="K8S-022",
                title="Container image uses :latest tag",
                severity=Severity.MEDIUM,
                category=Category.IMAGE_SECURITY,
                file=res.file_path,
                resource=f"{res.resource_id} (container: {cname})",
                location=f"spec.template.spec.{ctype}[name={cname}].image",
                evidence=f"image: \"{image}\"",
                impact="Using the :latest tag introduces non-deterministic deployments, breaks rollback reliability, and may pull unvetted upstream changes.",
                remediation="Pin container images to an immutable version tag or exact sha256 digest.",
                remediation_yaml=f"image: {image.split(':')[0]}:v1.4.2",
                references=["https://kubernetes.io/docs/concepts/containers/images/#image-names"]
            ))
        elif ":" not in image and "@" not in image:
            findings.append(Finding(
                rule_id="K8S-023",
                title="Container image tag missing",
                severity=Severity.MEDIUM,
                category=Category.IMAGE_SECURITY,
                file=res.file_path,
                resource=f"{res.resource_id} (container: {cname})",
                location=f"spec.template.spec.{ctype}[name={cname}].image",
                evidence=f"image: \"{image}\"",
                impact="When no image tag or digest is specified, Kubernetes defaults to pulling :latest, leading to unpredictable runtime behavior.",
                remediation="Specify a concrete version tag or sha256 digest on the image reference.",
                remediation_yaml=f"image: {image}:1.25.3-alpine",
                references=["https://kubernetes.io/docs/concepts/containers/images/"]
            ))
        else:
            # K8S-024: Image registry provenance / supply-chain policy recommendation
            # Note: Static inspection only; advise Trivy for package CVEs
            if not image.startswith(("docker.io/", "ghcr.io/", "gcr.io/", "quay.io/", "ecr.", "registry.")):
                findings.append(Finding(
                    rule_id="K8S-024",
                    title="Image registry provenance policy warning",
                    severity=Severity.LOW,
                    category=Category.IMAGE_SECURITY,
                    file=res.file_path,
                    resource=f"{res.resource_id} (container: {cname})",
                    location=f"spec.template.spec.{ctype}[name={cname}].image",
                    evidence=f"image: \"{image}\"",
                    impact="Hardening recommendation: Image reference lacks an explicit enterprise registry domain prefix or cryptographic provenance digest. Workloads pulling from default public repositories lack supply-chain provenance attestation. (Note: Known CVE detection requires package vulnerability scanners such as Trivy).",
                    remediation="Configure image pull policy to pull from an approved internal or verified enterprise artifact registry with image signing and vulnerability scanning.",
                    remediation_yaml=f"image: internal-registry.corp.net/security/{image}",
                    references=["https://trivy.dev/"]
                ))

    return findings


# ============================================================================
# RBAC RULES
# ============================================================================

def _check_role_rules(res: ParsedResource) -> List[Finding]:
    findings: List[Finding] = []
    rules = res.doc.get("rules") or []
    if isinstance(rules, list):
        for idx, rule in enumerate(rules):
            if not isinstance(rule, dict):
                continue
            verbs = [str(v) for v in rule.get("verbs", [])]
            resources = [str(r) for r in rule.get("resources", [])]
            api_groups = [str(g) for g in rule.get("apiGroups", [])]

            has_wildcard_verbs = "*" in verbs
            has_wildcard_resources = "*" in resources

            if has_wildcard_verbs or has_wildcard_resources:
                ev_parts = []
                if has_wildcard_verbs:
                    ev_parts.append('verbs: ["*"]')
                if has_wildcard_resources:
                    ev_parts.append('resources: ["*"]')
                evidence_str = ", ".join(ev_parts)

                findings.append(Finding(
                    rule_id="K8S-012",
                    title="Role grants excessive wildcard permissions",
                    severity=Severity.HIGH,
                    category=Category.RBAC,
                    file=res.file_path,
                    resource=res.resource_id,
                    location=f"rules[{idx}]",
                    evidence=evidence_str,
                    impact="Wildcard RBAC privileges violate the principle of least privilege, enabling full control over cluster objects, secrets theft, and privilege escalation.",
                    remediation="Explicitly specify only required verbs (e.g. ['get', 'list', 'watch']) and specific resources.",
                    remediation_yaml="rules:\n  - apiGroups: [\"\"]\n    resources: [\"pods\"]\n    verbs: [\"get\", \"list\", \"watch\"]",
                    references=["https://kubernetes.io/docs/reference/access-authn-authz/rbac/#privilege-escalation-prevention-and-bootstrapping"]
                ))
    return findings


def _check_binding_rules(res: ParsedResource) -> List[Finding]:
    findings: List[Finding] = []
    role_ref = res.doc.get("roleRef") or {}
    role_name = role_ref.get("name", "")

    # K8S-013: ClusterRoleBinding grants broad privileges (e.g. cluster-admin)
    if res.kind == "ClusterRoleBinding" and role_name in ("cluster-admin", "admin"):
        subjects = res.doc.get("subjects") or []
        subject_names = [s.get("name") for s in subjects if isinstance(s, dict)]
        findings.append(Finding(
            rule_id="K8S-013",
            title="ClusterRoleBinding grants cluster-admin privileges",
            severity=Severity.HIGH,
            category=Category.RBAC,
            file=res.file_path,
            resource=res.resource_id,
            location="roleRef.name",
            evidence=f"roleRef: {role_name}, subjects: {subject_names}",
            impact="Binding subjects to cluster-admin grants god-mode administrative powers across all namespaces, nullifying multi-tenant isolation.",
            remediation="Create a scoped RoleBinding bound to a namespace-limited Role with restricted permissions.",
            remediation_yaml="apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata:\n  name: app-restricted-binding\n  namespace: production\nroleRef:\n  kind: Role\n  name: pod-reader\n  apiGroup: rbac.authorization.k8s.io",
            references=["https://kubernetes.io/docs/reference/access-authn-authz/rbac/"]
        ))
    return findings


# ============================================================================
# NETWORKING RULES
# ============================================================================

def _check_service_rules(res: ParsedResource) -> List[Finding]:
    findings: List[Finding] = []
    spec = res.doc.get("spec") or {}
    svc_type = spec.get("type", "ClusterIP")

    # K8S-018: Service exposed through NodePort
    if svc_type == "NodePort":
        findings.append(Finding(
            rule_id="K8S-018",
            title="Service exposed through NodePort",
            severity=Severity.MEDIUM,
            category=Category.NETWORK_SECURITY,
            file=res.file_path,
            resource=res.resource_id,
            location="spec.type",
            evidence="type: NodePort",
            impact="NodePort opens high-range ports on every node's IP address, exposing the service directly to any client capable of routing to worker nodes.",
            remediation="Use ClusterIP services fronted by a properly secured Ingress controller with TLS and rate limiting.",
            remediation_yaml="spec:\n  type: ClusterIP\n  ports:\n    - port: 80\n      targetPort: 8080",
            references=["https://kubernetes.io/docs/concepts/services-networking/service/#type-nodeport"]
        ))

    # K8S-019: LoadBalancer service detected
    elif svc_type == "LoadBalancer":
        findings.append(Finding(
            rule_id="K8S-019",
            title="Service exposed via external LoadBalancer",
            severity=Severity.LOW,
            category=Category.NETWORK_SECURITY,
            file=res.file_path,
            resource=res.resource_id,
            location="spec.type",
            evidence="type: LoadBalancer",
            impact="LoadBalancer provisions cloud infrastructure directly exposing the service to external traffic. Verify that loadBalancerSourceRanges or firewall rules restrict ingress.",
            remediation="Restrict access using spec.loadBalancerSourceRanges or migrate external routing to Ingress / Gateway API.",
            remediation_yaml="spec:\n  type: LoadBalancer\n  loadBalancerSourceRanges:\n    - 203.0.113.0/24",
            references=["https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer"]
        ))

    return findings


def _check_ingress_rules(res: ParsedResource) -> List[Finding]:
    findings: List[Finding] = []
    spec = res.doc.get("spec") or {}
    tls = spec.get("tls")

    # K8S-017: Ingress exposes service without TLS
    if not tls or not isinstance(tls, list) or len(tls) == 0:
        findings.append(Finding(
            rule_id="K8S-017",
            title="Ingress exposes service without TLS termination",
            severity=Severity.MEDIUM,
            category=Category.NETWORK_SECURITY,
            file=res.file_path,
            resource=res.resource_id,
            location="spec.tls",
            evidence="spec.tls is missing or empty",
            impact="HTTP plain-text communication allows eavesdropping, man-in-the-middle tampering, and credential interception in transit.",
            remediation="Configure a TLS certificate block in spec.tls referencing a valid certificate secret or cert-manager issuer.",
            remediation_yaml="spec:\n  tls:\n    - hosts:\n        - api.example.com\n      secretName: api-tls-cert",
            references=["https://kubernetes.io/docs/concepts/services-networking/ingress/#tls"]
        ))

    return findings


# ============================================================================
# SECRETS & CONFIGMAP RULES
# ============================================================================

def _check_configmap_secrets(res: ParsedResource) -> List[Finding]:
    findings: List[Finding] = []
    data = res.doc.get("data") or {}
    if isinstance(data, dict):
        for k, v in data.items():
            if SECRET_KEY_PATTERNS.search(k):
                redacted = redact_secret_value(v)
                findings.append(Finding(
                    rule_id="K8S-011",
                    title="Potential secret stored in ConfigMap",
                    severity=Severity.HIGH,
                    category=Category.SECRETS,
                    file=res.file_path,
                    resource=res.resource_id,
                    location=f"data.{k}",
                    evidence=f"key '{k}' contains value '{redacted}'",
                    impact="ConfigMaps are intended for non-confidential data; storing credentials in ConfigMaps leaves them unencrypted in etcd by default and readable by any viewer.",
                    remediation="Migrate credential data into a Kubernetes Secret and use sealed-secrets or an external secret store (e.g. HashiCorp Vault).",
                    remediation_yaml="apiVersion: v1\nkind: Secret\nmetadata:\n  name: app-secret\ntype: Opaque\nstringData:\n  db_password: <VAULT_REF>",
                    references=["https://kubernetes.io/docs/concepts/configuration/configmap/#motivation"]
                ))
    return findings


def _check_secret_resource(res: ParsedResource) -> List[Finding]:
    """Check Secret resources for plaintext commits or dangerous exposure."""
    findings: List[Finding] = []
    data = res.doc.get("stringData") or {}
    if isinstance(data, dict):
        for k, v in data.items():
            redacted = redact_secret_value(v)
            findings.append(Finding(
                rule_id="K8S-011",
                title="Plaintext stringData in Secret manifest",
                severity=Severity.HIGH,
                category=Category.SECRETS,
                file=res.file_path,
                resource=res.resource_id,
                location=f"stringData.{k}",
                evidence=f"stringData.{k} = \"{redacted}\"",
                impact="Committing plaintext Secret manifests to source control leaks sensitive credentials directly into git logs.",
                remediation="Do not commit Secret manifests containing stringData to git. Use git-crypt, SOPS, Sealed Secrets, or Vault.",
                remediation_yaml="# Use SealedSecret or external secret operator instead of plain manifest commits",
                references=["https://kubernetes.io/docs/concepts/configuration/secret/"]
            ))
    return findings
