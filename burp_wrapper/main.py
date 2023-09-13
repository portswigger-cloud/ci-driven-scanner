import os
import pprint
import subprocess
import sys

from art import text2art

import burp_wrapper.outputters.console as o_console
import burp_wrapper.outputters.json as o_json
import burp_wrapper.parsers.junit as p_junit

JUNIT_FILE_PATH = os.environ.get("BURP_REPORT_FILE_PATH", "burp_junit_report.xml")
REPORTS_DIRECTORY = os.environ.get("BURP_REPORTS_DIRECTORY", "./burp_reports")

SCAN_INITIATOR_PATH = "/usr/local/burpsuite_enterprise/bin/initiate-scan"


def print_page_break(
    leading_new_line: bool = True, trailing_new_line: bool = True
) -> None:
    if leading_new_line:
        print("")
    print("=======================================================")
    if trailing_new_line:
        print("")


def print_header() -> None:
    print_page_break(trailing_new_line=False)
    print(text2art("BurpSuite").rstrip())
    print("                                        CI-Driven Scans")
    print_page_break()
    print(f"JUnit report input: {JUNIT_FILE_PATH}")
    print(f"Report output directory: {REPORTS_DIRECTORY}")
    print_page_break()


def run_scan_initiator() -> int:
    if os.path.exists(SCAN_INITIATOR_PATH):
        process_result = subprocess.run(["/bin/bash", "-c", SCAN_INITIATOR_PATH])
        return process_result.returncode

    print(f"INFO: Would have executed: /bin/bash -c {SCAN_INITIATOR_PATH} ")
    return 42


def main():
    print_header()
    exit_code = run_scan_initiator()
    print_page_break(leading_new_line=False)

    target_issues = p_junit.parse_url_issues_from_junit(JUNIT_FILE_PATH)

    o_console.output_summary(target_issues)
    print_page_break(leading_new_line=False)

    o_console.output_issue_counts(target_issues)
    print_page_break()

    if not os.path.exists(REPORTS_DIRECTORY):
        os.makedirs(REPORTS_DIRECTORY)

    o_json.create_report(REPORTS_DIRECTORY, target_issues)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
