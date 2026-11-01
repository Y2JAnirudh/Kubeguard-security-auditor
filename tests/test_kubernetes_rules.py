"""
Unit tests for Kubernetes Security Rules Engine.
"""

import pytest
from kube_guard.parsers import parse_yaml_manifests
from kube_guard.rules import evaluate_kubernetes_rules
from kube_guard.models import Severity


def test_privileged_container_detected():
    yaml_str = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: priv-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: app:1.0
          securityContext:
            privileged: true
    """
    resources, errors = parse_yaml_manifests(yaml_str)
    assert len(errors) == 0
    findings = evaluate_kubernetes_rules(resources[0])
    rule_ids = [f.rule_id for f in findings]
    assert "K8S-001" in rule_ids
    f = next(item for item in findings if item.rule_id == "K8S-001")
    assert f.severity == Severity.CRITICAL


def test_root_user_and_escalation_detected():
    yaml_str = """
apiVersion: v1
kind: Pod
metadata:
  name: root-pod
spec:
  containers:
    - name: worker
      image: worker:1.0
      securityContext:
        runAsUser: 0
        allowPrivilegeEscalation: true
    """
    resources, _ = parse_yaml_manifests(yaml_str)
    findings = evaluate_kubernetes_rules(resources[0])
    rule_ids = [f.rule_id for f in findings]
    assert "K8S-002" in rule_ids
    assert "K8S-004" in rule_ids


def test_host_namespace_and_hostpath_detected():
    yaml_str = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: host-access-app
spec:
  template:
    spec:
      hostNetwork: true
      hostPID: true
      hostIPC: true
      containers:
        - name: agent
          image: agent:1.0
      volumes:
        - name: sock
          hostPath:
            path: /var/run/docker.sock
    """
    resources, _ = parse_yaml_manifests(yaml_str)
    findings = evaluate_kubernetes_rules(resources[0])
    rule_ids = [f.rule_id for f in findings]
    assert "K8S-005" in rule_ids  # hostPID
    assert "K8S-006" in rule_ids  # hostNetwork
    assert "K8S-007" in rule_ids  # hostIPC
    assert "K8S-010" in rule_ids  # hostPath


def test_latest_image_tag_detected():
    yaml_str = """
apiVersion: v1
kind: Pod
metadata:
  name: unpinned-pod
spec:
  containers:
    - name: web
      image: nginx:latest
    """
    resources, _ = parse_yaml_manifests(yaml_str)
    findings = evaluate_kubernetes_rules(resources[0])
    rule_ids = [f.rule_id for f in findings]
    assert "K8S-022" in rule_ids


def test_embedded_secret_detected_and_redacted():
    yaml_str = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secret-leak-app
spec:
  template:
    spec:
      containers:
        - name: api
          image: api:v1.0.0
          env:
            - name: DB_PASSWORD
              value: "super_secret_cleartext_password"
    """
    resources, _ = parse_yaml_manifests(yaml_str)
    findings = evaluate_kubernetes_rules(resources[0])
    rule_ids = [f.rule_id for f in findings]
    assert "K8S-011" in rule_ids
    f = next(item for item in findings if item.rule_id == "K8S-011")
    # Verify redacted: should NOT show full plaintext password in evidence
    assert "super_secret_cleartext_password" not in f.evidence
    assert "****" in f.evidence


def test_rbac_wildcard_detected():
    yaml_str = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: super-admin-role
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
    """
    resources, _ = parse_yaml_manifests(yaml_str)
    findings = evaluate_kubernetes_rules(resources[0])
    rule_ids = [f.rule_id for f in findings]
    assert "K8S-012" in rule_ids


def test_rbac_cluster_admin_binding_detected():
    yaml_str = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: bind-admin
subjects:
  - kind: ServiceAccount
    name: dev-user
    namespace: default
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
    """
    resources, _ = parse_yaml_manifests(yaml_str)
    findings = evaluate_kubernetes_rules(resources[0])
    rule_ids = [f.rule_id for f in findings]
    assert "K8S-013" in rule_ids


def test_service_nodeport_detected():
    yaml_str = """
apiVersion: v1
kind: Service
metadata:
  name: web-nodeport
spec:
  type: NodePort
  ports:
    - port: 80
      nodePort: 30080
    """
    resources, _ = parse_yaml_manifests(yaml_str)
    findings = evaluate_kubernetes_rules(resources[0])
    rule_ids = [f.rule_id for f in findings]
    assert "K8S-018" in rule_ids


def test_malformed_yaml_graceful_handling():
    malformed = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: broken
spec:
  [this is invalid yaml:
    """
    resources, errors = parse_yaml_manifests(malformed)
    assert len(errors) > 0
    assert "YAML Syntax Error" in errors[0]
