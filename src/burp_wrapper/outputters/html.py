import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader


def get_confidence_counts(severity: str, target_issues: list) -> list[int]:
    confidence_counts = [0, 0, 0]

    for target in target_issues:
        for issue in target.issues:
            if severity == issue.severity.lower():
                match issue.confidence.lower():
                    case "certain":
                        confidence_counts[0] += 1
                    case "firm":
                        confidence_counts[1] += 1
                    case "tentative":
                        confidence_counts[2] += 1

    return confidence_counts


def get_severity_confidence(target_issues: list) -> dict:
    severity_confidence = {
        "high": get_confidence_counts("high", target_issues),
        "medium": get_confidence_counts("medium", target_issues),
        "low": get_confidence_counts("low", target_issues),
        "info": get_confidence_counts("info", target_issues),
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


def create_report(reports_directory: str, target_issues: list) -> None:
    environment = Environment(
        loader=FileSystemLoader(f"{os.path.dirname(__file__)}/templates")
    )

    template = environment.get_template("burp.html")
    template.globals["now"] = datetime.now

    filename = f"{reports_directory}/burp.html"

    content = template.render(
        severity_confidence=get_severity_confidence(target_issues)
    )

    with open(filename, mode="w", encoding="utf-8") as message:
        message.write(content)

    print(f"  HTML report output: {filename}")
