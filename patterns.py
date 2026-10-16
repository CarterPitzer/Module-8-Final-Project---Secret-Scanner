import re

PATTERNS = [
    {
        "id": "jwt",
        "description": "JSON Web Token",
        "regex": re.compile(r"\bey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9/_-]{10,}\.[A-Za-z0-9/_-]{10,}")
    },
    {
        "id": "pem_private_key",
        "description": "PEM private key",
        "regex": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----")
    },
    {
        "id": "github_token",
        "description": "GitHub personal access token",
        "regex": re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")
    },
    {
        "id": "aws_access_key",
        "description": "AWS access key",
        "regex": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")
    },
    {
        "id": "generic_password_assignment",
        "description": "Password assignment",
        "regex": re.compile(r"(?i)\b(password|passwd|pwd)\b\s*[:=]\s*['\"]([^'\"]{6,})['\"]")
    }
]
