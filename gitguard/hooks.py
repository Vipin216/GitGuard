from pathlib import Path
import sys


def install_pre_commit_hook(repo_path: str) -> None:
    """
    Install GitGuard as a pre-commit hook
    in the specified repository.
    """

    repo = Path(repo_path)

    git_directory = repo / ".git"

    if not git_directory.exists():
        raise ValueError(
            f"{repo_path} is not a Git repository."
        )

    hooks_directory = git_directory / "hooks"
    hooks_directory.mkdir(exist_ok=True)

    hook_path = hooks_directory / "pre-commit"

    python_executable = Path(sys.executable)

    hook_content = f'''#!/bin/sh

"{python_executable}" -m gitguard.cli staged .
exit $?
'''

    hook_path.write_text(
        hook_content,
        encoding="utf-8"
    )

    print(
        "✅ GitGuard pre-commit hook installed."
    )