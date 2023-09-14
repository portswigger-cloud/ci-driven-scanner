from dataclasses import dataclass, field


@dataclass
class Evidence:
    request: str
    response: str


@dataclass
class CollaboratorInteraction:
    message: str
    evidence: Evidence


@dataclass
class Issue:
    name: str
    description: str
    severity: str
    confidence: str
    host: str
    path: str
    detail: str
    background: str = None
    remediation: str = None
    remediation_detail: str = None
    remediation_background: str = None
    evidence: list[Evidence] = field(default_factory=list)
    collaborator_interaction: CollaboratorInteraction = None
    static_analysis: str = None
    dynamic_analysis: str = None
    references: list[str] = field(default_factory=list)
    vulnerability_classifications: list[str] = field(default_factory=list)


@dataclass
class Target:
    url: str
    issues: list[Issue] = field(default_factory=list)


@dataclass
class IssueDefinitionMetadata:
    name: str
    severity: str
    hex_id: str
    dec_id: str
