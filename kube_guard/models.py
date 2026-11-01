"""
KubeGuard Models
Data structures representing security findings, severity levels, and scan results.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Optional, Dict, Any


class Severity(str, Enum):
    """Vulnerability severity classifications."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Category(str, Enum):
    """Security categories for classification."""
    CONTAINER_SECURITY = "Container Security"
    SECRETS = "Secrets Management"
    RBAC = "RBAC & Permissions"
    RESOURCE_MANAGEMENT = "Resource Management"
    NETWORK_SECURITY = "Network Security"
    POD_SECURITY = "Pod Security"
    IMAGE_SECURITY = "Image Security"
    BUILD_SECURITY = "Build Security"


@dataclass
class Finding:
    """Represents a single detected security finding."""
    rule_id: str
    title: str
    severity: Severity
    category: Category
    file: str
    resource: str
    evidence: str
    impact: str
    remediation: str
    description: str = ""
    location: Optional[str] = None
    remediation_yaml: Optional[str] = None
    references: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.description:
            self.description = self.title

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to standard dictionary representation."""
        data = asdict(self)
        data["severity"] = self.severity.value
        data["category"] = self.category.value
        return data


@dataclass
class ScanResult:
    """Aggregated scan findings and security score."""
    files_scanned: List[str]
    resources_scanned: int
    findings: List[Finding]
    score: int
    risk_level: str
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    category_counts: Dict[str, int] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return len(self.findings)
