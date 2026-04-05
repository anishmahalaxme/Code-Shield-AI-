"""
sql_injection.py
Detects SQL Injection vulnerabilities.

  JavaScript -> AST-based with taint tracking (esprima + taint.py):
    - Tracks variables tainted from user input (req.*, userInput, etc.)
    - Detects BinaryExpression (+) where SQL string + tainted variable
    - Detects TemplateLiteral in query calls with tainted interpolation
    - Keyword match anywhere in string (not just startswith)
    - Real code snippets from source lines
    - Deduplication by (line, type) key
    - Reports confidence: HIGH (direct) or MEDIUM (via tainted variable)
    - Fallback to regex if AST parsing fails

  Python -> regex-based.
"""

import re
from typing import List, Dict, Set

from app.detectors.js_parse import parse_js
from app.detectors.taint import build_taint_set, walk, references_tainted, is_seed_source


SQL_KEYWORDS = {"select", "insert", "update", "delete", "drop", "alter", "create", "where", "join"}

# ── Python patterns ───────────────────────────────────────────────────────────
PY_PATTERNS = [
    (r'execute\s*\(\s*["\'].*\+',           "SQL execute() with string concatenation — use parameterized queries."),
    (r'execute\s*\(\s*f["\'].*\{',          "SQL execute() with f-string interpolation — SQL injection risk."),
    (r'["\'](?:SELECT|INSERT|UPDATE|DELETE).*["\'].*(%).*\(', "SQL query with % formatting — use parameterized queries."),
    # JS-like patterns as fallback
    (r'["\']SELECT|INSERT|UPDATE|DELETE.*["\'\`]\s*\+\s*\w', "SQL string concatenated with a variable — SQL injection risk."),
]


# ── AST helpers ───────────────────────────────────────────────────────────────

def _is_sql_string(node) -> bool:
    """Detect SQL Literal strings — keyword presence ANYWHERE in string (not just prefix)."""
    if node.type == "Literal" and isinstance(node.value, str):
        low = node.value.lower()
        return any(kw in low for kw in SQL_KEYWORDS)
    return False


def _template_quasis_sql_text(node) -> str:
    """Lowercased text from TemplateLiteral static segments (for SQL keyword match)."""
    chunks = []
    for q in node.quasis or []:
        val = getattr(q, "value", None)
        if val is None:
            continue
        chunks.append(getattr(val, "cooked", None) or getattr(val, "raw", None) or "")
    return "".join(chunks).lower()


def _real_snippet(code: str, line: int) -> str:
    """Return the actual source line for display — realistic and demo-ready."""
    lines = code.splitlines()
    if 1 <= line <= len(lines):
        return lines[line - 1].strip()
    return f"(line {line})"


def _detect_js_sql_heuristic(code: str) -> List[Dict]:
    """Last-resort line scan when esprima is missing or cannot parse the file."""
    issues: List[Dict] = []
    seen: Set[tuple] = set()
    for line_num, line in enumerate(code.splitlines(), start=1):
        s = line.strip()
        if not s or s.startswith("//") or s.startswith("/*") or s.startswith("*"):
            continue
        low = line.lower()
        if not any(kw in low for kw in SQL_KEYWORDS):
            continue
        # Pattern A: template literal  `SELECT ... ${expr}`
        has_template = "${" in line and "`" in line
        # Pattern B: SQL keyword + any concat with an identifier
        # Catches both: "SELECT ..." + var  AND  "WHERE '" + var + "'"
        has_concat = bool(re.search(r"\+\s*[a-zA-Z_$]", line))
        risky = has_template or has_concat
        if not risky:
            continue
        key = (line_num, "SQL_INJECTION")
        if key not in seen:
            seen.add(key)
            issues.append({
                "type": "SQL_INJECTION",
                "line": line_num,
                "severity": "HIGH",
                "confidence": "LOW",
                "message": (
                    "Possible SQL injection — query text is mixed with dynamic data "
                    "(heuristic; AST unavailable or unparsable). Use parameterized queries."
                ),
                "code_snippet": s,
            })
    return issues


def _detect_js_ast(code: str) -> List[Dict]:
    tree = parse_js(code)
    if tree is None:
        return _detect_js_sql_heuristic(code)

    # Build taint set before detection pass
    tainted, _ = build_taint_set(tree)

    issues: List[Dict] = []
    seen: Set[tuple] = set()  # deduplication: (line, vuln_type)

    def _add_issue(vuln_type: str, line: int, conf: str, message: str, snippet: str):
        key = (line, vuln_type)
        if key not in seen:
            seen.add(key)
            issues.append({
                "type": vuln_type,
                "line": line,
                "severity": "HIGH",
                "confidence": conf,
                "message": message,
                "code_snippet": snippet,
            })

    def visit(node):
        # ── Pattern 1: "... SQL ..." + variable ──────────────────────────────
        if node.type == "BinaryExpression" and node.operator == "+":
            left, right = node.left, node.right

            sql_side, var_side = None, None
            if _is_sql_string(left):
                sql_side, var_side = left, right
            elif _is_sql_string(right):
                sql_side, var_side = right, left

            if sql_side is not None and var_side is not None:
                is_direct   = is_seed_source(var_side)
                is_indirect = references_tainted(var_side, tainted)

                if is_direct or is_indirect:
                    line = node.loc.start.line if node.loc else 1
                    conf = "HIGH" if is_direct else "MEDIUM"
                    flow = "direct user input" if is_direct else "tainted variable"
                    snippet = _real_snippet(code, line)
                    _add_issue(
                        "SQL_INJECTION", line, conf,
                        f"SQL query built with {flow} — SQL injection risk. (confidence: {conf})",
                        snippet,
                    )

        # ── Pattern 1b: const q = `SELECT ... ${user} ...` (not only inside query()) ──
        if node.type == "TemplateLiteral" and node.expressions:
            qtxt = _template_quasis_sql_text(node)
            if any(kw in qtxt for kw in SQL_KEYWORDS):
                for expr in node.expressions:
                    if is_seed_source(expr) or references_tainted(expr, tainted):
                        line = node.loc.start.line if node.loc else 1
                        is_direct = is_seed_source(expr)
                        conf = "HIGH" if is_direct else "MEDIUM"
                        flow = "direct user input" if is_direct else "tainted variable"
                        snippet = _real_snippet(code, line)
                        _add_issue(
                            "SQL_INJECTION", line, conf,
                            f"SQL template literal interpolates {flow} — SQL injection risk. (confidence: {conf})",
                            snippet,
                        )
                        break

        # ── Pattern 2: query/execute(`...${taintedVar}...`) ──────────────────
        if node.type == "CallExpression":
            callee_name = ""
            if node.callee.type == "MemberExpression" and hasattr(node.callee.property, "name"):
                callee_name = node.callee.property.name
            elif node.callee.type == "Identifier":
                callee_name = node.callee.name

            if callee_name.lower() in (
                "query", "execute", "run", "all", "get", "prepare",
                "raw",  # Sequelize / ORMs
            ):
                for arg in (node.arguments or []):
                    if arg.type == "TemplateLiteral" and arg.expressions:
                        for expr in arg.expressions:
                            if is_seed_source(expr) or references_tainted(expr, tainted):
                                line = node.loc.start.line if node.loc else 1
                                is_direct = is_seed_source(expr)
                                conf = "HIGH" if is_direct else "MEDIUM"
                                flow = "direct user input" if is_direct else "tainted variable"
                                snippet = _real_snippet(code, line)
                                _add_issue(
                                    "SQL_INJECTION", line, conf,
                                    f"SQL template literal interpolates {flow} — SQL injection risk. (confidence: {conf})",
                                    snippet,
                                )
                                break  # one issue per call arg

                # ── Pattern 2b: db.query(dynamicSqlVar) — SQL built earlier, passed as identifier ──
                args = node.arguments or []
                if args and args[0].type == "Identifier" and references_tainted(args[0], tainted):
                    line = node.loc.start.line if node.loc else 1
                    snippet = _real_snippet(code, line)
                    _add_issue(
                        "SQL_INJECTION", line, "MEDIUM",
                        "Database API called with a tainted SQL string — likely built from user input; use parameterized queries. (confidence: MEDIUM)",
                        snippet,
                    )

    walk(tree, visit)
    return issues


# ── Python regex detection ────────────────────────────────────────────────────

def _detect_python_regex(code: str) -> List[Dict]:
    issues: List[Dict] = []
    seen: Set[tuple] = set()
    for line_num, line in enumerate(code.splitlines(), start=1):
        s = line.strip()
        if not s or s.startswith(("#", "//")):
            continue
        for pattern, message in PY_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                key = (line_num, "SQL_INJECTION")
                if key not in seen:
                    seen.add(key)
                    issues.append({
                        "type": "SQL_INJECTION",
                        "line": line_num,
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "message": f"{message} (confidence: HIGH)",
                        "code_snippet": s,
                    })
                break
    return issues


# ── Public API ────────────────────────────────────────────────────────────────

def detect(code: str, language: str) -> List[Dict]:
    if language == "javascript":
        return _detect_js_ast(code)
    elif language == "python":
        return _detect_python_regex(code)
    return []
