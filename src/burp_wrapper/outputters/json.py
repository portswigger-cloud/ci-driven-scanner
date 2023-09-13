import dataclasses
import json


def del_none(d: dict):
    d_copy = d.copy()
    for key, value in list(d_copy.items()):
        if value is None:
            del d_copy[key]
        elif isinstance(value, dict):
            del_none(value)
    return d_copy


class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            return del_none(dataclasses.asdict(o))
        return super().default(o)


def create_report(reports_directory: str, target_issues: list) -> None:
    json_out = json.dumps(target_issues, indent=4, cls=EnhancedJSONEncoder)
    filename = f"{reports_directory}/burp.json"
    with open(filename, "w") as outfile:
        outfile.write(json_out)

    print(f"  JSON report output: {filename}")
