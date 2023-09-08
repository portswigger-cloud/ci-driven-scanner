import os
import re
from dataclasses import dataclass, field

from junitparser import JUnitXml


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
    evidence: list[Evidence] = None
    collaborator_interaction: CollaboratorInteraction = None
    static_analysis: str = None
    dynamic_analysis: str = None
    references: list[str] = field(default_factory=list)
    vulnerability_classifications: list[str] = field(default_factory=list)


@dataclass
class Target:
    url: str
    issues: list[Issue] = field(default_factory=list)


def parse_url_issues_from_junit(junit_file_path: str) -> list[Target]:
    if not os.path.exists(junit_file_path):
        print(f"WARNING: Unable to find JUnit report file at: {junit_file_path}")

    url_issue_list: list[Target] = []

    xml = JUnitXml.fromfile(junit_file_path)
    for url_test_suite in xml:
        url_test_issues = Target(url_test_suite.name)

        if int(url_test_suite.failures) > 0:
            for url_test_case in url_test_suite:
                for result in url_test_case.result:
                    url_test_issues.issues.append(
                        Issue(
                            name=url_test_case.name,
                            description=result.message,
                            severity=parse_message_for_field("Severity", result.text),
                            confidence=parse_message_for_field(
                                "Confidence", result.text
                            ),
                            host=parse_message_for_field("Host", result.text),
                            path=parse_message_for_field("Path", result.text),
                            detail=parse_message_for_field("Issue Detail", result.text),
                            background=parse_message_for_field(
                                "Issue Background", result.text
                            ),
                            remediation=parse_message_for_field(
                                "Issue Remediation", result.text
                            ),
                            remediation_detail=parse_message_for_field(
                                "Remediation Detail", result.text
                            ),
                            remediation_background=parse_message_for_field(
                                "Remediation Background", result.text
                            ),
                            evidence=parse_message_for_field("Evidence", result.text),
                            collaborator_interaction=parse_message_for_field(
                                "Collaborator HTTP interaction", result.text
                            ),
                            static_analysis=parse_message_for_field(
                                "Static analysis", result.text
                            ),
                            dynamic_analysis=parse_message_for_field(
                                "Dynamic analysis", result.text
                            ),
                            references=parse_message_for_field(
                                "References", result.text
                            ),
                            vulnerability_classifications=parse_message_for_field(
                                "Vulnerability Classifications", result.text
                            ),
                        )
                    )

        url_issue_list.append(url_test_issues)

    return url_issue_list


def parse_message_for_field(field: str, message: str):
    parse_fields = {
        "inline": ["Severity", "Confidence", "Host", "Path"],
        "list": ["References", "Vulnerability Classifications"],
        "evidence": ["Evidence"],
        "collaborator_interaction": ["Collaborator HTTP interaction"],
        "multiline": [
            "Issue Detail",
            "Issue Background",
            "Issue Remediation",
            "Remediation Detail",
            "Remediation Background",
            "Static analysis:",
            "Dynamic analysis:",
        ],
        "footer": [
            "Reported by Burp Suite Enterprise: https://portswigger.net/kb/issues"
        ],
    }

    all_fields = [item for row in parse_fields.values() for item in row]

    if field in parse_fields["inline"]:
        re_search = re.search(rf"^{field}: (\S+)$", message, flags=re.MULTILINE)

        if re_search:
            return re_search.group(1)

        return ""
    else:
        gather = False
        result_list = []
        for line in message.splitlines():
            if line.startswith(field):
                gather = True
                continue
            elif line in all_fields:
                gather = False

            if gather:
                result_list.append(line)

        # Evidence fields contain (multiple) a request and a response - I'd like to refactor this,
        # but once BurpXML output arrives it can probably go away :D

        if field in parse_fields["evidence"]:
            evidence_content = "\n".join(result_list).strip()
            evidence_list = []
            request = False
            request_list = []

            response = False
            response_list = []
            for evidence_line in evidence_content.splitlines():
                if evidence_line.startswith("Request"):
                    request = True
                    response = False
                    continue
                elif evidence_line.startswith("Response"):
                    request = False
                    response = True
                    continue

                if request and len(response_list) > 0:
                    request_str = "\n".join(request_list).strip()
                    response_str = "\n".join(response_list).strip()

                    if request_str and response_str:
                        evidence_list.append(
                            Evidence(
                                request=request_str,
                                response=response_str,
                            )
                        )
                    request_list = []
                    response_list = []

                if request:
                    request_list.append(evidence_line)

                elif response:
                    response_list.append(evidence_line)

            request_str = "\n".join(request_list).strip()
            response_str = "\n".join(response_list).strip()

            if request_str and response_str:
                evidence_list.append(
                    Evidence(
                        request=request_str,
                        response=response_str,
                    )
                )
            return evidence_list

        if field in parse_fields["collaborator_interaction"]:
            collaborator_interaction_content = "\n".join(result_list).strip()
            collaborator_interaction_message = True
            collaborator_interaction_message_list = []

            collaborator_interaction_request = False
            collaborator_interaction_request_list = []

            collaborator_interaction_response = False
            collaborator_interaction_response_list = []

            for (
                collaborator_interaction_line
            ) in collaborator_interaction_content.splitlines():
                if collaborator_interaction_line.startswith("Request to collaborator"):
                    collaborator_interaction_message = False
                    collaborator_interaction_request = True
                    collaborator_interaction_response = False
                    continue
                elif collaborator_interaction_line.startswith(
                    "Response from collaborator"
                ):
                    collaborator_interaction_message = False
                    collaborator_interaction_request = False
                    collaborator_interaction_response = True
                    continue

                if collaborator_interaction_message:
                    collaborator_interaction_message_list.append(
                        collaborator_interaction_line
                    )
                elif collaborator_interaction_request:
                    collaborator_interaction_request_list.append(
                        collaborator_interaction_line
                    )
                elif collaborator_interaction_response:
                    collaborator_interaction_response_list.append(
                        collaborator_interaction_line
                    )

            collaborator_interaction_message_str = "\n".join(
                collaborator_interaction_message_list
            ).strip()

            collaborator_interaction_request_str = "\n".join(
                collaborator_interaction_request_list
            ).strip()

            collaborator_interaction_response_str = "\n".join(
                collaborator_interaction_response_list
            ).strip()

            return CollaboratorInteraction(
                message=collaborator_interaction_message_str,
                evidence=Evidence(
                    request=collaborator_interaction_request_str,
                    response=collaborator_interaction_response_str,
                ),
            )

        # List fields should return a list of strings
        elif field in parse_fields["list"]:
            return [
                x.replace("- ", "", 1).strip() for x in result_list if x.strip() != ""
            ]

        # Everything else is just a multipline string
        return "\n".join(result_list).strip()
