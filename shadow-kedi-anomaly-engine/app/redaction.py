import re
from typing import Any

_HEADER_RE = re.compile(r"(authorization|x-api-key|token|password)=?[^\s,;]+", re.IGNORECASE)
_AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")


def redact_log_value(value: Any) -> str:
    """Safe structured-log representation; never emit authorization or DLP values."""
    text = str(value)
    text = _HEADER_RE.sub(r"\1=[REDACTED]", text)
    return _AWS_KEY_RE.sub("[REDACTED_AWS_KEY]", text)
