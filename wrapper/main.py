import os
import sys
import subprocess

from art import text2art

import parsers.junit as p_junit
import outputters.console as o_console

JUNIT_FILE_PATH = os.environ.get("BURP_REPORT_FILE_PATH", "burp_junit_report.xml")
REPORTS_DIRECTORY = os.environ.get("BURP_REPORTS_DIRECTORY", "burp_reports")

SCAN_INITIATOR_PATH = "/usr/local/burpsuite_enterprise/bin/initiate-scan"


def print_page_break(trailing_new_line: bool = True) -> None:
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


if __name__ == "__main__":
    print_header()
    exit_code = run_scan_initiator()
    print_page_break()

    target_issues = p_junit.parse_url_issues_from_junit(JUNIT_FILE_PATH)

    o_console.output_summary(target_issues)
    print_page_break()
    o_console.output_issue_counts(target_issues)
    print_page_break()

    sys.exit(exit_code)
