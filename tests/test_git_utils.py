import subprocess

from gitguard.git_utils import (
    get_staged_files,
    get_staged_file_content,
)


def run_git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
    )


def test_staged_file_functions(tmp_path):

    repo = tmp_path / "repo"
    repo.mkdir()

    run_git(repo, "init")

    file_path = repo / "config.txt"

    file_path.write_text(
        "hello world",
        encoding="utf-8"
    )

    run_git(repo, "add", "config.txt")

    files = get_staged_files(str(repo))

    assert files == ["config.txt"]

    content = get_staged_file_content(
        str(repo),
        "config.txt"
    )

    assert content == "hello world"