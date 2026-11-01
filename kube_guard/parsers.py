"""
KubeGuard Parsers
Safe parsing of multi-document Kubernetes YAML manifests and resource traversal.
"""

from typing import List, Dict, Any, Tuple, Optional
import yaml


class ParsedResource:
    """Wrapper around a parsed Kubernetes resource document."""

    def __init__(self, doc: Dict[str, Any], file_path: str, index: int):
        self.doc = doc or {}
        self.file_path = file_path
        self.index = index
        self.api_version: str = str(self.doc.get("apiVersion", "unknown"))
        self.kind: str = str(self.doc.get("kind", "Unknown"))
        metadata = self.doc.get("metadata") or {}
        self.name: str = str(metadata.get("name", f"unnamed-{index}"))
        self.namespace: str = str(metadata.get("namespace", "default"))

    @property
    def resource_id(self) -> str:
        """Formatted resource identifier like Deployment/payment-api."""
        return f"{self.kind}/{self.name}"

    def get_pod_spec(self) -> Optional[Dict[str, Any]]:
        """
        Extract the PodSpec dictionary depending on the controller kind.
        Handles Pod, Deployment, DaemonSet, StatefulSet, Job, CronJob, ReplicaSet.
        """
        if self.kind == "Pod":
            return self.doc.get("spec") or {}

        spec = self.doc.get("spec")
        if not isinstance(spec, dict):
            return None

        if self.kind in ("Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet", "ReplicationController"):
            template = spec.get("template")
            if isinstance(template, dict):
                pod_spec = template.get("spec")
                if isinstance(pod_spec, dict):
                    return pod_spec

        elif self.kind == "CronJob":
            job_template = spec.get("jobTemplate")
            if isinstance(job_template, dict):
                job_spec = job_template.get("spec")
                if isinstance(job_spec, dict):
                    template = job_spec.get("template")
                    if isinstance(template, dict):
                        pod_spec = template.get("spec")
                        if isinstance(pod_spec, dict):
                            return pod_spec

        return None

    def get_all_containers(self) -> List[Tuple[str, Dict[str, Any], str]]:
        """
        Returns a list of tuples: (container_type, container_dict, container_name)
        Covering containers, initContainers, and ephemeralContainers.
        """
        pod_spec = self.get_pod_spec()
        if not pod_spec:
            return []

        results = []
        for ctype in ("containers", "initContainers", "ephemeralContainers"):
            containers = pod_spec.get(ctype)
            if isinstance(containers, list):
                for c in containers:
                    if isinstance(c, dict):
                        c_name = c.get("name", "unnamed")
                        results.append((ctype, c, c_name))
        return results


def parse_yaml_manifests(content: str, file_path: str = "manifest.yaml") -> Tuple[List[ParsedResource], List[str]]:
    """
    Safely parse a multi-document YAML string.
    Returns:
      (list of ParsedResource, list of parse error messages)
    Never crashes on malformed YAML.
    """
    resources: List[ParsedResource] = []
    errors: List[str] = []

    try:
        docs = list(yaml.safe_load_all(content))
    except yaml.YAMLError as exc:
        errors.append(f"YAML Syntax Error in '{file_path}': {str(exc)}")
        return resources, errors
    except Exception as exc:
        errors.append(f"Unexpected parsing error in '{file_path}': {str(exc)}")
        return resources, errors

    for idx, doc in enumerate(docs):
        if not doc:
            continue
        if not isinstance(doc, dict):
            errors.append(f"Skipping document #{idx+1} in '{file_path}': root must be a YAML mapping/dictionary.")
            continue
        resources.append(ParsedResource(doc, file_path, idx))

    return resources, errors
