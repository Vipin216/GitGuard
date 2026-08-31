import subprocess
from gitguard.detectors import detect_secrets,aggregate_findings


def get_staged_files(repo_path: str) -> list[str]:
    """
    Return files currently staged for commit.
    """

    result = subprocess.run(
        [
            "git",
            "-C",
            repo_path,
            "diff",
            "--cached",
            "--name-only",
            "--diff-filter=ACMR",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    return [
        file
        for file in result.stdout.splitlines()
        if file
    ]









def get_staged_file_content(repo_path: str,file_path: str) -> str | None:
    """
    Return the staged version of a file.
    """

    result = subprocess.run(
        [
            "git",
            "-C",
            repo_path,
            "show",
            f":{file_path}",
        ],
        capture_output=True,
        text=False,
        check=False,
    )

    if result.returncode != 0:
        return None

    try:
        return result.stdout.decode("utf-8")
    except UnicodeDecodeError:
        return None











def scan_staged_files(repo_path: str):
    """
    Scan only files currently staged for commit.
    """

    files = get_staged_files(repo_path)

    all_findings = []

    for file_path in files:

        content = get_staged_file_content(
            repo_path,
            file_path
        )

        if content is None:
            continue

        findings = detect_secrets(
            content,
            file_path
        )

        all_findings.extend(findings)

    return aggregate_findings(all_findings)