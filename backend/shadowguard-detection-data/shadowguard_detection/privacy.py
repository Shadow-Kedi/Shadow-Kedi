import hashlib
import hmac


def hmac_domain(domain: str, key: str) -> str:
    return hmac.new(key.encode(), domain.lower().strip().rstrip(".").encode(), hashlib.sha256).hexdigest()
