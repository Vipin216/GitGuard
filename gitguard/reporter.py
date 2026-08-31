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