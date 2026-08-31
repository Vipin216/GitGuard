import json

from dataclasses import asdict

from gitguard.detectors import Finding


def print_terminal_report(files_scanned: int,findings: list[Finding]) -> None:

    print()
    print("GitGuard Security Scan")
    print("────────────────────────────────")
    print()

    print(f"Files scanned: {files_scanned}")
    print()

    if not findings:
        print("Secrets found: 0")
        print()
        print("Status: ✅ PASSED")
        return

    print("🚨 FINDINGS")
    print()

    for finding in findings:

        print(
            f"[{finding.severity}] "
            f"{finding.file}:{finding.line}"
        )

        print(
            f"  Type: {finding.secret_type}"
        )

        print(
            f"  Confidence: {finding.confidence}"
        )

        print()

    print("────────────────────────────────")
    print(f"Findings: {len(findings)}")
    print("Status: ❌ FAILED")








def generate_json_report(files_scanned: int,findings: list[Finding]) -> str:

    report = {
        "status": "failed" if findings else "passed",
        "files_scanned": files_scanned,
        "findings": [
            asdict(finding)
            for finding in findings
        ]
    }

    return json.dumps(
        report,
        indent=2
    )







def severity_to_sarif_level(severity: str) -> str:

    mapping = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
    }

    return mapping.get(
        severity,
        "warning"
    )




def generate_sarif_report(files_scanned: int,findings: list[Finding]) -> dict:
    """
    Generate a SARIF 2.1.0 report.
    """

    results = []

    for finding in findings:

        results.append({
            "ruleId": finding.secret_type,
            "level": severity_to_sarif_level(finding.severity),
            "message": {
                "text": (
                    f"{finding.secret_type} detected "
                    f"with {finding.confidence} confidence."
                )
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file
                        },
                        "region": {
                            "startLine": finding.line
                        }
                    }
                }
            ]
        })

    return {
        "$schema": (
            "https://json.schemastore.org/"
            "sarif-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "GitGuard",
                        "version": "0.1.0",
                        "informationUri": ("https://github.com/""Vipin216/GitGuard")
                    }
                },
                "results": results
            }
        ]
    }











def write_sarif_report(files_scanned: int,findings: list[Finding],output_path: str) -> None:

    report = generate_sarif_report(files_scanned,findings)

    with open(output_path,"w",encoding="utf-8") as file:

        json.dump(report,file,indent=2)