from dataclasses import dataclass
import re
from gitguard.entropy import calculate_entropy




@dataclass
class Finding:
    file:str
    line:int
    secret_type:str
    severity:str
    confidence:str
    match:str = "[REDACTED]"


AWS_ACCESS_KEY_PATTERN = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
PASSWORD_PATTERN = re.compile(r"""(?ix)\b(password|passwd|pwd)\s*[:=]\s*["']([^"']+)["']""")
DATABASE_URL_PATTERN = re.compile(r"\b(?:postgresql|postgres|mysql|mongodb(?:\+srv)?)://"r"[^\s\"']+")
JWT_PATTERN = re.compile(r"\beyJ[a-zA-Z0-9_-]+\."r"[a-zA-Z0-9_-]+\."r"[a-zA-Z0-9_-]+\b")
SUSPICIOUS_ASSIGNMENT_PATTERN = re.compile(
    r"""(?ix)
    \b(
        api[_-]?key |
        api[_-]?token |
        access[_-]?token |
        auth[_-]?token |
        secret |
        secret[_-]?key |
        private[_-]?key |
        client[_-]?secret |
        encryption[_-]?key
    )
    \s*[:=]\s*
    ["']([^"']+)["']
    """
)

PLACEHOLDER_VALUES = {
    "password",
    "passwd",
    "example",
    "changeme",
    "your_password",
    "yourpassword",
    "secret",
    "test",
    "testing",
    "dummy",
    "placeholder",
}



CONFIDENCE_SCORE = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
}


SEVERITY_SCORE = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}



def is_placeholder(value: str) -> bool:
    return value.strip().lower() in PLACEHOLDER_VALUES







def detect_aws_access_keys(content:str,file_path:str,) -> list[Finding]:
    findings = []

    for line_number, line in enumerate(content.splitlines(),start=1):
        matches = AWS_ACCESS_KEY_PATTERN.finditer(line)

        for match in matches:


            findings.append(
                Finding(
                    file=file_path,
                    line=line_number,
                    secret_type="AWS Access Key",
                    severity="CRITICAL",
                    confidence="HIGH",
                    match="[REDACTED]"
                )
            )


    return findings




def detect_private_keys(content: str,file_path: str) -> list[Finding]:

    findings = []

    for line_number, line in enumerate(content.splitlines(),start=1):
        if PRIVATE_KEY_PATTERN.search(line):
            findings.append(
                Finding(
                    file=file_path,
                    line=line_number,
                    secret_type="Private Key",
                    severity="CRITICAL",
                    confidence="HIGH",
                    match="PRIVATE KEY"
                )
            )

    return findings




def detect_passwords(content: str,file_path: str) -> list[Finding]:

    findings = []

    for line_number, line in enumerate(content.splitlines(),start=1):
        matches = PASSWORD_PATTERN.finditer(line)

        for match in matches:

            value = match.group(2)
            if is_placeholder(value):
                continue


            findings.append(
                Finding(
                    file=file_path,
                    line=line_number,
                    secret_type="Hardcoded Password",
                    severity="HIGH",
                    confidence="MEDIUM",
                    match="[REDACTED]"
                )
            )

    return findings




def detect_database_urls(content: str,file_path: str) -> list[Finding]:

    findings = []

    for line_number, line in enumerate(content.splitlines(),start=1):
        matches = DATABASE_URL_PATTERN.finditer(line)

        for match in matches:
            findings.append(
                Finding(
                    file=file_path,
                    line=line_number,
                    secret_type="Database Connection String",
                    severity="CRITICAL",
                    confidence="HIGH",
                    match="[REDACTED]"
                )
            )

    return findings




def detect_jwts(content:str,file_path:str)->list[Finding]:

    findings=[]

    for line_number,line in enumerate(content.splitlines(),start=1):

        matches=JWT_PATTERN.finditer(line)

        for match in matches:
            findings.append(
                Finding(
                    file=file_path,
                    line=line_number,
                    secret_type="JWT",
                    severity="HIGH",
                    confidence="HIGH",
                    match="[REDACTED]"
                )
            )

    return findings



def detect_high_entropy_secrets(content:str,file_path:str)->list[Finding]:

    findings=[]

    for line_number,line in enumerate(content.splitlines(),start=1):

        matches=SUSPICIOUS_ASSIGNMENT_PATTERN.finditer(line)

        for match in matches:
            secret_value = match.group(2)

            if len(secret_value) < 12:
                continue

            entropy = calculate_entropy(secret_value)

            if entropy >= 3.5:
                findings.append(
                    Finding(
                        file=file_path,
                        line=line_number,
                        secret_type="High-Entropy Secret",
                        severity="HIGH",
                        confidence="MEDIUM",
                        match="[REDACTED]"
                    )
                )

    return findings





def detect_secrets(content:str,file_path:str)->list[Finding]:
    findings=[]

    detectors = [
        detect_aws_access_keys,
        detect_private_keys,
        detect_database_urls,
        detect_passwords,
        detect_jwts,
        detect_high_entropy_secrets,
    ]


    for detector in detectors:
        findings.extend(
            detector(content,file_path)
        )

    return findings











def aggregate_findings(findings: list[Finding]) -> list[Finding]:

    unique_findings = {}

    for finding in findings:

        key = (finding.file,finding.line)

        existing = unique_findings.get(key)

        if existing is None:
            unique_findings[key] = finding
            continue

        if (SEVERITY_SCORE[finding.severity]> SEVERITY_SCORE[existing.severity]):
            unique_findings[key] = finding

        elif (SEVERITY_SCORE[finding.severity]== SEVERITY_SCORE[existing.severity] and CONFIDENCE_SCORE[finding.confidence]> CONFIDENCE_SCORE[existing.confidence]):
            unique_findings[key] = finding

    return list(unique_findings.values())