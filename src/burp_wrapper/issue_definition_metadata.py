import csv
import os


from burp_wrapper.models import IssueDefinitionMetadata


def get_issue_metadata(name: str):
    with open(
        f"{os.path.dirname(__file__)}/resources/issue_definitions.csv", "r"
    ) as file:
        csvreader = csv.reader(file)
        for row in csvreader:
            if name == row[0]:
                return IssueDefinitionMetadata(
                    name=name,
                    severity=row[1],
                    hex_id=row[2],
                    dec_id=int(row[3]),
                )
