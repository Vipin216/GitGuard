import subprocess
from gitguard.detectors import detect_secrets,aggregate_findings


def get_commit_hashes(repo_path: str) -> list[str]:
   

    result = subprocess.run(
        [
            "git",
            "-C",
            repo_path,
            "log",
            "--all",
            "--pretty=format:%H",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    return [
        commit
        for commit in result.stdout.splitlines()
        if commit
    ]




def get_commit_files(repo_path: str,commit_hash: str) -> list[str]:
    

    result = subprocess.run(
        [
            "git",
            "-C",
            repo_path,
            "diff-tree",
            "--root",
            "--no-commit-id",
            "--name-only",
            "-r",
            commit_hash,
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











def get_file_from_commit(repo_path: str,commit_hash: str,file_path: str) -> str | None:
    

    result = subprocess.run(
        [
            "git",
            "-C",
            repo_path,
            "show",
            f"{commit_hash}:{file_path}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        return None

    return result.stdout










def scan_git_history(repo_path: str):
    

    commits = get_commit_hashes(repo_path)

    all_findings = []

    for commit in commits:

        files = get_commit_files(repo_path,commit)

        for file_path in files:

            content = get_file_from_commit(repo_path,commit,file_path)

            if content is None:
                continue

            findings = detect_secrets(
                content,
                f"{commit[:8]}:{file_path}"
            )

            all_findings.extend(findings)

    return aggregate_findings(all_findings)