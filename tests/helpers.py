import re

# Placeholders look like [PERSON_1] or [PROTECTED_CLIENT_1]. Regex-layer labels keep their
# punctuation, e.g. [ADDRESS_(US)_1] or [WEBSITE_/_URL_1], so allow any non-space characters.
TOKEN = re.compile(r"\[[A-Z][^\[\]\s]*_\d+\]")


def assert_no_leak(text: str, secrets):
    leaked = [s for s in secrets if s.lower() in text.lower()]
    assert not leaked, f"Sensitive values survived redaction: {leaked}"
