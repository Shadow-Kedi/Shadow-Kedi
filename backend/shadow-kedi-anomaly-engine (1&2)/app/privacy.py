import hashlib
import hmac


def domain_hash(domain: str, secret: str) -> str:
    """Return a keyed, deterministic domain token; never store the clear domain."""
    return hmac.new(secret.encode(), domain.encode(), hashlib.sha256).hexdigest()
