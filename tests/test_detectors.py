from gitguard.detectors import (
    detect_secrets,
    aggregate_findings,
)
from gitguard.entropy import calculate_entropy


def test_detect_aws_access_key():
    secret = "AKIA" + "IOSFODNN7EXAMPLE"

    content = f'AWS_ACCESS_KEY_ID = "{secret}"'

    findings = detect_secrets(
        content,
        "test.py"
    )

    assert any(
        finding.secret_type == "AWS Access Key"
        for finding in findings
    )


def test_detect_private_key():
    private_key_header = "-----BEGIN " + "RSA PRIVATE KEY-----"
    private_key_footer = "-----END " + "RSA PRIVATE KEY-----"

    content = f"""{private_key_header}
fake-private-key-content
{private_key_footer}"""

    findings = detect_secrets(
        content,
        "keys.txt"
    )

    assert any(
        finding.secret_type == "Private Key"
        for finding in findings
    )


def test_detect_jwt():
    token = (
        "eyJ"
        + "hbGciOiJIUzI1NiJ9."
        + "eyJ1c2VyIjoiMTIzIn0."
        + "fake-signature"
    )

    content = f'token = "{token}"'

    findings = detect_secrets(
        content,
        "auth.py"
    )

    assert any(
        finding.secret_type == "JWT"
        for finding in findings
    )


def test_placeholder_password_is_ignored():
    key = "pass" + "word"

    content = f'{key} = "changeme"'

    findings = detect_secrets(
        content,
        "config.py"
    )

    assert not any(
        finding.secret_type == "Hardcoded Password"
        for finding in findings
    )


def test_real_password_is_detected():
    key = "pass" + "word"

    content = f'{key} = "SuperSecret123!"'

    findings = detect_secrets(
        content,
        "config.py"
    )

    assert any(
        finding.secret_type == "Hardcoded Password"
        for finding in findings
    )


def test_entropy():
    assert calculate_entropy(
        "aaaaaaaaaaaaaaaa"
    ) == 0.0

    assert calculate_entropy(
        "abcdefghijklmnop"
    ) == 4.0


def test_high_entropy_secret():
    value = "a8F92kLmP7xQ4zT1"

    content = f'API_TOKEN = "{value}"'

    findings = detect_secrets(
        content,
        "config.py"
    )

    assert any(
        finding.secret_type == "High-Entropy Secret"
        for finding in findings
    )


def test_clean_content():
    content = """
def hello():
    print("Hello World")

x = 10
"""

    findings = detect_secrets(
        content,
        "app.py"
    )

    assert findings == []


def test_duplicate_findings_are_aggregated():
    findings = detect_secrets(
        'API_KEY = "AKIA' + 'IOSFODNN7EXAMPLE"',
        "config.py"
    )

    aggregated = aggregate_findings(findings)

    assert len(aggregated) <= len(findings)