from pathlib import Path
from gitguard.detectors import Finding, detect_secrets,aggregate_findings




TEXT_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".java",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".go",
    ".rs",
    ".php",
    ".rb",
    ".swift",
    ".kt",
    ".html",
    ".css",
    ".scss",
    ".json",
    ".yaml",
    ".yml",
    ".xml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".env",
    ".txt",
    ".md",
    ".sh",
    ".bash",
    ".zsh",
    ".sql",
}




IGNORED_DIRECTORIES={
    ".git",
    "venv",
    ".venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
}


def should_ignore(path:Path)->bool:
    return any(part in IGNORED_DIRECTORIES for part in path.parts)



def is_likely_text_file(path:Path) -> bool:
    if path.suffix.lower() in TEXT_EXTENSIONS:
        return True

    try:
        chunk=path.read_bytes()[:8192]
    except PermissionError:
        return False


    return b"\x00" not in chunk




def get_files_to_scan(root_path:str)-> list[Path]:
    root = Path(root_path)

    if not root.exists():
        raise FileNotFoundError(
            f"Path does not exist:{root_path}"
        )

    if not root.is_dir():
        raise NotADirectoryError(
            f"Path is not a directory:{root_path}"
        )

    files=[]

    for path in root.rglob("*"):
        if path.is_file() and not should_ignore(path) and is_likely_text_file(path):
            files.append(path)

    return files




def scan_repository(root_path:str)->tuple[int,list[Finding]]:

    files=get_files_to_scan(root_path)

    all_findings = []
    files_scanned = 0


    for file_path in files:

        try:
            content = file_path.read_text(encoding="utf-8")
        except (UnicodeDecodeError,PermissionError):
            continue

        files_scanned+=1

        findings = detect_secrets(
            content,
            str(file_path)
        )

        all_findings.extend(findings)


    final_findings = aggregate_findings(all_findings)
    return files_scanned, final_findings
