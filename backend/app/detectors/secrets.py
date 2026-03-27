"""
secrets.py
Detects hardcoded secrets using regex (no AST needed — applies to all languages).

Severity:
  HIGH  — clearly identifiable active credential (API key, AWS key, password)
  MEDIUM — suspicious long string or env-var fallback
"""

import re
from typing import List, Dict


SECRET_NAMES = (
    r"(?:api[_-]?key|apikey|secret[_-]?key|secret|token|access[_-]?token"
    r"|auth[_-]?token|password|passwd|pwd|private[_-]?key|client[_-]?secret"
    r"|db[_-]?pass(?:word)?|database[_-]?url|connection[_-]?string)"
)

PATTERNS = [
    # const API_KEY = "abc123..." or password = 'hunter2'
    (
        rf'(?i){SECRET_NAMES}\s*(?:=|:)\s*["\'][^"\'{{]{{6,}}["\']',
        "Hardcoded credential detected — move this value to an environment variable.",
        "HIGH",
    ),
    # process.env.X || "hardcoded_fallback"
    (
        r'process\.env\.\w+\s*\|\|\s*["\'][^"\']{6,}["\']',
        "Hardcoded fallback for environment variable — remove the default value.",
        "MEDIUM",
    ),
    # AWS Access Key ID
    (
        r'AKIA[0-9A-Z]{16}',
        "AWS Access Key ID found in source code — rotate this key immediately.",
        "HIGH",
    ),
    # Long base64 / hex string on a suspicious variable
    (
        rf'(?i){SECRET_NAMES}\s*(?:=|:)\s*["\'][A-Za-z0-9+/]{{32,}}={0,2}["\']',
        "Long hardcoded string on a sensitive-looking variable — likely a secret.",
        "MEDIUM",
    ),
]


def detect(code: str, language: str) -> List[Dict]:
    issues = []
    for line_num, line in enumerate(code.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "#", "*")):
            continue
        for pattern, message, severity in PATTERNS:
            if re.search(pattern, line):
                issues.append({
                    "type": "HARDCODED_SECRET",
                    "line": line_num,
                    "severity": severity,
                    "message": message,
                    "code_snippet": stripped,
                })
                break  # one issue per line
    return issues
