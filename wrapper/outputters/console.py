SUCCESS = "✅"
FAIL = "❌"


def get_severity_emoji(severity: str):
    match severity.lower():
        case "info":
            return "ℹ️"
        case "low":
            return "🙈"
        case "medium":
            return "🔔"
        case "high":
            return "😱"
        case "critical":
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
