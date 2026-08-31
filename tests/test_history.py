import subprocess

from gitguard.history import scan_git_history


def run_git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
    )


def test_history_detects_old_secret(tmp_path):

    repo = tmp_path / "repo"
    repo.mkdir()

    run_git(repo, "init")

    config = repo / "config.py"

    secret = "AKIA" + "IOSFODNN7EXAMPLE"

    config.write_text(
        f'AWS_ACCESS_KEY_ID = "{secret}"',
        encoding="utf-8"
    )

    run_git(repo, "add", "config.py")

    run_git(
        repo,
        "-c",
        "user.name=Test User",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-m",
        "add config"
    )

    config.write_text(
        "AWS_ACCESS_KEY_ID = None",
        encoding="utf-8"
    )

    run_git(repo, "add", "config.py")

    run_git(
        repo,
        "-c",
        "user.name=Test User",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-m",
        "remove secret"
    )

    findings = scan_git_history(str(repo))

    assert any(
        finding.secret_type == "AWS Access Key"
        for finding in findings
    )