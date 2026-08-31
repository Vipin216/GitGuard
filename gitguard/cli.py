import argparse
import subprocess

from gitguard.scanner import scan_repository
from gitguard.reporter import (
    print_terminal_report,
    generate_json_report,
)
from gitguard.history import scan_git_history
from gitguard.hooks import install_pre_commit_hook
from gitguard.git_utils import scan_staged_files




def main():

    parser = argparse.ArgumentParser(description="GitGuard - Secret Detection & Prevention Tool")

    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan",help="Scan a repository for potential secrets")
    scan_parser.add_argument("path",help="Path to the repository")
    scan_parser.add_argument("--format",choices=["text", "json"],default="text",help="Output format")

    history_parser = subparsers.add_parser("history",help="Scan Git history for potential secrets")
    history_parser.add_argument("path",help="Path to the repository")


    install_parser = subparsers.add_parser("install",help="Install GitGuard pre-commit hook")
    install_parser.add_argument("path",nargs="?",default=".",help="Path to the Git repository")


    staged_parser = subparsers.add_parser("staged",help="Scan staged files for potential secrets")
    staged_parser.add_argument("path",nargs="?",default=".",help="Path to the Git repository")


    args = parser.parse_args()


    if args.command == "scan":

        try:
            files_scanned, findings = scan_repository(args.path)

        except (FileNotFoundError,NotADirectoryError) as error:

            print(f"Error: {error}")

            return 2

        if args.format == "json":

            print(
                generate_json_report(files_scanned,findings)
            )

        else:

            print_terminal_report(files_scanned,findings)

        if findings:
            return 1

        return 0

    

    elif args.command == "history":

        try:

            findings = scan_git_history(args.path)

        except subprocess.CalledProcessError:

            print("Error: path is not a Git repository.")

            return 2

        if findings:

            print()
            print("GitGuard Git History Scan")
            print("────────────────────────────────")
            print()

            print("🚨 HISTORICAL FINDINGS")
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

          

            print(
                f"Historical findings: {len(findings)}"
            )

            return 1

        print()
        print("Git history is clean.")
        print()

        return 0


    elif args.command == "install":

        try:

            install_pre_commit_hook(args.path)

        except ValueError as error:

            print(f"Error: {error}")

            return 2

        return 0



    elif args.command == "staged":

        try:
            findings = scan_staged_files(args.path)

        except subprocess.CalledProcessError:
            print("Error: path is not a Git repository.")
            return 2

        if findings:

            print()
            print("GitGuard Staged File Scan")
            print("────────────────────────────────")
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

            print(
                f"Findings: {len(findings)}"
            )

            return 1

        print()
        print("Staged files are clean.")
        print()

        return 0

    
    

    parser.print_help()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())