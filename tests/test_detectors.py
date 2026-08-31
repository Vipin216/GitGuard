from gitguard.detectors import detect_secrets


def test_detect_aws_key():
    content = """
    AWS_ACCESS_KEY_ID=
    """

    findings = detect_secrets(
        content,
        "config.py"
    )

    assert len(findings) == 1
    assert findings[0].secret_type == "AWS Access Key"
    assert findings[0].severity == "CRITICAL"