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


def output_summary(target_issues: list) -> None:
    successful_targets = []
    failed_targets = []
    for target in target_issues:
        if len(target.issues) > 0:
            failed_message_list = [
                "",
                f"{FAIL} - {len(target.issues)} issues detected at: {target.url} ",
            ]
            for issue in target.issues:
                failed_message = [
                    f"     {get_severity_emoji(issue.severity)} - {issue.severity} - {issue.name}:",
                    "",
                    f"       Description: {issue.description}",
                    f"       Confidence: {issue.confidence}",
                ]
                if issue.references:
                    failed_message.append("       References:")
                    for reference in issue.references:
                        failed_message.append(f"           {reference}")

                failed_message.append("")
                failed_message_list.extend(failed_message)

            failed_targets.append("\n".join(failed_message_list))

            continue
        successful_targets.append(f"{SUCCESS} - No issues detected at: {target.url}")

    print("Scan summary:")
    print("")
    print("\n".join(successful_targets))
    if failed_targets:
        print("\n".join(failed_targets))


def output_issue_counts(target_issues: list) -> None:
    issue_counts = {
        "info": 0,
        "low": 0,
        "medium": 0,
        "high": 0,
    }

    for target in target_issues:
        if len(target.issues) > 0:
            for issue in target.issues:
                l_severity = issue.severity.lower()

                match l_severity:
                    case "info" | "low" | "medium" | "high":
                        issue_counts[l_severity] += 1

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
