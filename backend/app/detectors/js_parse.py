"""
Parse JavaScript / ECMAScript modules for AST-based detectors.
Tries script goal then module goal so more sources parse successfully.
"""

from typing import Any, Optional

try:
    import esprima

    _ESPRIMA = True
except ImportError:
    _ESPRIMA = False


def parse_js(code: str) -> Optional[Any]:
    """
    Return esprima AST or None if parsing fails or esprima is unavailable.
    """
    if not _ESPRIMA:
        return None
    for parser in (esprima.parseScript, esprima.parseModule):
        try:
            return parser(code, tolerant=True, loc=True)
        except Exception:
            continue
    return None
