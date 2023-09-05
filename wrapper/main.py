import os
import sys
import subprocess

from art import text2art

from parsers.junit import parse_url_issues_from_junit
import outputters.console as console

JUNIT_FILE_PATH = os.environ.get("BURP_REPORT_FILE_PATH", "burp_junit_report.xml")
REPORTS_DIRECTORY = os.environ.get("BURP_REPORTS_DIRECTORY", "burp_reports")

SCAN_INITIATOR_PATH = "/usr/local/burpsuite_enterprise/bin/initiate-scan"


def print_header() -> None:
    print("")
    print("=======================================================")
    print(text2art("BurpSuite").rstrip())
    print("                                        CI-Driven Scans")
    print("")
    print("=======================================================")
    print("")
    print(f"JUnit report input: {JUNIT_FILE_PATH}")
    print(f"Report output directory: {REPORTS_DIRECTORY}")
    print("")
    print("=======================================================")
    print("")


def run_scan_initiator() -> int:
    if os.path.exists(SCAN_INITIATOR_PATH):
        process_result = subprocess.run(["/bin/bash", "-c", SCAN_INITIATOR_PATH])
        return process_result.returncode

    print(f"INFO: Would have executed: /bin/bash -c {SCAN_INITIATOR_PATH} ")
    return 42


if __name__ == "__main__":
    print_header()
    exit_code = run_scan_initiator()
    print("")
    print("=======================================================")
    print("")
    target_issues = parse_url_issues_from_junit(JUNIT_FILE_PATH)

    console.output_summary(target_issues)

    print("")
    print("=======================================================")
    print("")

    sys.exit(exit_code)
