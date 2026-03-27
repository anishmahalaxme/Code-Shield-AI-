"""
scanner.py
Orchestrates all detectors and combines results.
Assigns unique IDs to each issue.
"""

import uuid
from typing import List, Dict

from app.detectors import sql_injection, xss, secrets, path_traversal, cmd_injection

SUPPORTED_LANGUAGES = {"javascript", "python"}


def run_scan(code: str, language: str) -> List[Dict]:
    """
    Run all applicable detectors for the given language.
    Returns combined list of raw issues.
    """
    lang = language.lower()
    
    # Map React/TypeScript to JavaScript for AST parsing
    if lang in ["typescript", "ts", "tsx", "jsx", "javascriptreact", "typescriptreact"]:
        lang = "javascript"

    raw: List[Dict] = []

    if lang not in SUPPORTED_LANGUAGES:
        return []  # Caller checks this to return early

    # SQL Injection — JS + Python
    raw += sql_injection.detect(code, lang)

    # XSS — JS only
    raw += xss.detect(code, lang)

    # Hardcoded Secrets — JS + Python
    raw += secrets.detect(code, lang)

    # Path Traversal — JS + Python
    raw += path_traversal.detect(code, lang)

    # Command Injection — JS + Python
    raw += cmd_injection.detect(code, lang)

    # Assign unique IDs
    for issue in raw:
        issue["id"] = str(uuid.uuid4())

    return raw
