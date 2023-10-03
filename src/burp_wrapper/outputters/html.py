import os
from datetime import datetime, timezone
from jinja2 import Environment, FileSystemLoader


def get_confidence_counts(severity: str, issues: list) -> list[int]:
    confidence_counts = [0, 0, 0]

    for issue in issues:
        if severity == issue.severity.lower():
            match issue.confidence.lower():
                case "certain":
                    confidence_counts[0] += len(issue.issue_locations)
                case "firm":
                    confidence_counts[1] += len(issue.issue_locations)
                case "tentative":
                    confidence_counts[2] += len(issue.issue_locations)

    return confidence_counts


def severity_confidence_table(issues: list) -> dict:
    severity_confidence = {
        "high": get_confidence_counts("high", issues),
        "medium": get_confidence_counts("medium", issues),
        "low": get_confidence_counts("low", issues),
        "info": get_confidence_counts("info", issues),
    }

    severity_confidence["total"] = sum(
        [
            *severity_confidence["high"],
            *severity_confidence["medium"],
            *severity_confidence["low"],
            *severity_confidence["info"],
        ]
    )

    return severity_confidence


def issue_overview_table(issues: list) -> list:
    """
    Return issues organised by severity, confidence and counts of the issue.
    There is no consistent behaviour in the output.
    """

    _issue_overview = {
        "high_certain": {},
        "high_firm": {},
        "high_tentative": {},
        "medium_certain": {},
        "medium_firm": {},
        "medium_tentative": {},
        "low_certain": {},
        "low_firm": {},
        "low_tentative": {},
        "info_certain": {},
        "info_firm": {},
        "info_tentative": {},
    }

    sorted_issue_lists: dict[list] = {}

    for issue in issues:
        issue_criticality = f"{issue.severity.lower()}_{issue.confidence.lower()}"
        _issue_overview[issue_criticality][issue.name] = {
            "count": len(issue.issue_locations),
            "kb_article_url": issue.kb_article_url,
        }

    for issue_criticality in _issue_overview:
        sorted_issue_lists[issue_criticality] = sorted(
            _issue_overview[issue_criticality].items(),
            key=lambda issue: issue[1]["count"],
            reverse=True,
        )
    return sorted_issue_lists


def create_report(reports_directory: str, issues: dict) -> None:
    environment = Environment(
        loader=FileSystemLoader(f"{os.path.dirname(__file__)}/templates")
    )

    template = environment.get_template("burp.html")
    template.globals["iso_now"] = datetime.now(timezone.utc).isoformat

    filename = f"{reports_directory}/burp.html"

    content = template.render(
        severity_confidence_table=severity_confidence_table(list(issues.values())),
        issue_overview_table=issue_overview_table(issues.values()),
        issues=issues,
    )

    with open(filename, mode="w", encoding="utf-8") as message:
        message.write(content)

    print(f"  HTML report output: {filename}")
