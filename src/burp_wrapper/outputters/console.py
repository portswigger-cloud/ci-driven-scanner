import os

SUCCESS = "✅"
FAIL = "❌"


def get_severity_emoji(severity: str):
    match severity.lower():
        case "info":
            return "ℹ️"
        case "low":
            return "🙈"
        case "medium":
            return "😱"
        case "high":
            return "🚨"
        case _:
            return "🤔"


def output_summary(issues: dict) -> None:
    if len(issues.keys()) > 0:
        print(f"{FAIL} Detected Issues:")
        severities = ["high", "medium", "low", "info"]
        confidences = ["certain", "firm", "tentative"]

        for severity in severities:
            for confidence in confidences:
                sev_issues = {
                    key: value
                    for (key, value) in issues.items()
                    if value.severity.lower() == severity
                    and value.confidence.lower() == confidence
                }
                for issue in sev_issues.values():
                    print("")
                    print(
                        f"  {get_severity_emoji(issue.severity)} - {issue.severity} - {issue.name}:"
                    )
                    print(
                        f"    Confidence: {issue.confidence}",
                    )
                    print(f"    KB Article: {issue.kb_article_url}")
                    print("")
                    print("    Affected Locations:")
                    for location in issue.issue_locations:
                        print(f"      {location.host}{location.path}")
        print("")


def severity_count(issues: dict) -> dict:
    sev_counts = {
        "info": 0,
        "low": 0,
        "medium": 0,
        "high": 0,
    }

    for sev in sev_counts.keys():
        sev_counts[sev] += sum(
            [
                len(value.issue_locations)
                for value in issues.values()
                if value.severity.lower() == sev
            ]
        )

    return sev_counts


def output_issue_counts(issues: dict) -> None:
    issue_counts = severity_count(issues)

    total_issues = sum(issue_counts.values())

    issue_count_message = f"""Issue Count Summary:

    Total issues : {total_issues}

        High     : {issue_counts["high"]}
        Medium   : {issue_counts["medium"]}
        Low      : {issue_counts["low"]}
        Info     : {issue_counts["info"]}"""

    if total_issues > 0:
        print(issue_count_message)
    else:
        print("🎉✨ - No issues detected!")

    if total_issues > 0 and os.environ.get("GITHUB_ACTIONS", False):
        print("")

        high_count = issue_counts["high"]
        medium_count = issue_counts["medium"]

        if high_count > 0:
            print(f"::error ::{high_count} high severity issues detected")

        if medium_count > 0:
            print(f"::warning ::{medium_count} medium severity issues detected")

        print(f"::notice ::{total_issues} total issues detected")
