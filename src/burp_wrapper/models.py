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
class IssueLocation:
    host: str
    path: str
    detail: str
    evidence: list[Evidence] = field(default_factory=list)
    collaborator_interaction: CollaboratorInteraction = None
    static_analysis: str = None
    dynamic_analysis: str = None


@dataclass
class Issue:
    name: str
    severity: str
    confidence: str
    kb_article_url: str
    background: str = None
    remediation: str = None
    remediation_detail: str = None
    remediation_background: str = None
    references: list[str] = field(default_factory=list)
    vulnerability_classifications: list[str] = field(default_factory=list)
    issue_locations: list[IssueLocation] = field(default_factory=list)

    def issue_location_count(self):
        return len(self.issue_locations)


@dataclass
class IssueDefinitionMetadata:
    name: str
    severity: str
    hex_id: str
    dec_id: int
    cwe_ids: list[int] = field(default_factory=list)

    def hex_id_str(self):
        return f"{self.dec_id:08x}"

    def kb_article_url(self):
        return f"https://portswigger.net/kb/issues/{self.hex_id_str()}"
