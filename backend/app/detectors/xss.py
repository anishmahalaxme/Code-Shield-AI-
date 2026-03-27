"""
xss.py
Detects Cross-Site Scripting (XSS) vulnerabilities via AST-based analysis.

JavaScript sinks detected:
  DOM write sinks       -> innerHTML, outerHTML, insertAdjacentHTML
  Document sinks        -> document.write, document.writeln
  Dangerous eval sinks  -> eval(), setTimeout(string), setInterval(string)
  Navigation sinks      -> location.href, location.replace(), location.assign()
  URL attribute sinks   -> setAttribute('href'|'src'|'action', tainted)
  jQuery sinks          -> .html(), .append(), .prepend(), .after(), .before()
  React sink            -> dangerouslySetInnerHTML (regex only — not AST)

Improvements over v1:
  - Real code snippets from source lines
  - Deduplication by (line, type) key
  - Confidence level in message (HIGH/MEDIUM)
  - Fallback regex if AST parse fails
  - Per-sink message explaining exactly WHY it's dangerous

Python -> not applicable (no DOM APIs), returns [].
"""

import re
from typing import List, Dict, Set

try:
    import esprima
    ESPRIMA_AVAILABLE = True
except ImportError:
    ESPRIMA_AVAILABLE = False

from app.detectors.taint import build_taint_set, walk, references_tainted, is_seed_source


# ── Sink definitions ──────────────────────────────────────────────────────────

# Properties whose assignment renders unsanitized HTML
SINK_PROPERTIES = {
    "innerHTML":            "Assigns raw HTML — any injected script will execute.",
    "outerHTML":            "Replaces the element with raw HTML — XSS execution risk.",
}

# insertAdjacentHTML(position, htmlString) — 2nd arg is the unsafe one
SINK_ADJACENT = {"insertAdjacentHTML"}

# document.write / document.writeln
SINK_DOC_CALLS = {"write", "writeln"}

# eval-like sinks — first arg treated as code if it's a string/variable
SINK_EVAL = {"eval"}

# Timer-based code execution — first arg can be a string of code
SINK_TIMERS = {"setTimeout", "setInterval"}

# Navigation sinks — if tainted value ends up in URL, could redirect to evil.com
SINK_LOCATION_PROPS = {"href", "hash", "search"}
SINK_LOCATION_CALLS = {"replace", "assign"}

# Dangerous setAttribute values (URL injection / event handler injection)
DANGEROUS_ATTRS = {"href", "src", "action", "formaction", "data", "onclick",
                   "onerror", "onload", "srcdoc"}

# jQuery sink methods — any arg injected as raw HTML
SINK_JQUERY = {"html", "append", "prepend", "after", "before", "replaceWith",
               "wrap", "wrapInner"}

# Express / Node server-side reflected XSS sinks
# res.send(taint), res.write(taint), res.end(taint), res.json(taint)
SINK_RES_METHODS = {"send", "write", "end", "json"}
SINK_RES_ROOTS   = {"res", "response", "resp"}

# ── Regex fallback (covers dangerouslySetInnerHTML + basic cases) ─────────────
FALLBACK_PATTERNS = [
    (r'\.innerHTML\s*=\s*(?!["\'])',
        "innerHTML assigned from a variable — XSS risk."),
    (r'\.outerHTML\s*=\s*(?!["\'])',
        "outerHTML assigned from a variable — XSS risk."),
    (r'document\.write\s*\(\s*(?!["\'])',
        "document.write() with a variable injects unsanitized HTML."),
    (r'dangerouslySetInnerHTML\s*=\s*\{\s*\{',
        "React dangerouslySetInnerHTML bypasses React's XSS protection."),
    (r'\beval\s*\(\s*(?!["\'])',
        "eval() executes a variable as code — never use with user input."),
    (r'(setTimeout|setInterval)\s*\(\s*(?!["\'\(])',
        "Timer called with a variable string executes arbitrary code."),
    # Server-side reflected XSS (Express / Node)
    (r'\bres\s*\.\s*(send|write|end)\s*\(\s*[`"].*\$\{',
        "res.send/write() with a template literal containing user input — reflected XSS."),
]


# ── AST helpers ───────────────────────────────────────────────────────────────

def _real_snippet(code: str, line: int) -> str:
    lines = code.splitlines()
    return lines[line - 1].strip() if 1 <= line <= len(lines) else f"(line {line})"


def _detect_js_ast(code: str) -> List[Dict]:
    if not ESPRIMA_AVAILABLE:
        return _detect_js_regex(code)

    try:
        tree = esprima.parseScript(code, tolerant=True, loc=True)
    except Exception:
        return _detect_js_regex(code)

    tainted, _ = build_taint_set(tree)
    issues: List[Dict] = []
    seen: Set[tuple] = set()

    def _add(line: int, conf: str, message: str, sink: str):
        key = (line, "XSS", sink)
        if key not in seen:
            seen.add(key)
            flow = "direct user input" if conf == "HIGH" else "tainted variable"
            issues.append({
                "type": "XSS",
                "line": line,
                "severity": "MEDIUM",
                "confidence": conf,
                "message": f"{message} Input is {flow}. (confidence: {conf})",
                "code_snippet": _real_snippet(code, line),
            })

    def _conf(node) -> str:
        return "HIGH" if is_seed_source(node) else "MEDIUM"

    def _tainted(node) -> bool:
        return is_seed_source(node) or references_tainted(node, tainted)

    def visit(node):
        # ── 1. AssignmentExpression: element.innerHTML = tainted ──────────────
        if node.type == "AssignmentExpression" and node.operator == "=":
            left, right = node.left, node.right
            if (left.type == "MemberExpression"
                    and hasattr(left.property, "name")
                    and left.property.name in SINK_PROPERTIES):

                prop = left.property.name
                base_msg = SINK_PROPERTIES[prop]
                line = node.loc.start.line if node.loc else 1

                # ── 1a. Direct identifier / MemberExpression (existing) ───────
                if right.type not in ("TemplateLiteral", "Literal") and _tainted(right):
                    _add(line, _conf(right), base_msg, prop)

                # ── 1b. Template literal: `<div>${expr}</div>` ────────────────
                # Check each interpolated expression individually so we can
                # report the correct confidence per expression.
                elif right.type == "TemplateLiteral":
                    for expr in (right.expressions or []):
                        if is_seed_source(expr):
                            _add(line, "HIGH",
                                 f"Template literal assigned to .{prop} contains direct user input — "
                                 f"injected scripts inside `${{...}}` will execute in the browser.",
                                 f"{prop}-template-direct")
                            break
                        elif references_tainted(expr, tainted):
                            _add(line, "MEDIUM",
                                 f"Template literal assigned to .{prop} interpolates a tainted variable — "
                                 f"attacker-controlled data inside `${{...}}` enables XSS.",
                                 f"{prop}-template-tainted")
                            break

            # location.href = tainted
            if (left.type == "MemberExpression"
                    and hasattr(left.property, "name")
                    and left.property.name in SINK_LOCATION_PROPS):
                obj = left.object
                is_location = (
                    (obj.type == "Identifier" and obj.name == "location") or
                    (obj.type == "MemberExpression"
                     and hasattr(obj.property, "name")
                     and obj.property.name == "location")
                )
                if is_location and _tainted(right):
                    line = node.loc.start.line if node.loc else 1
                    _add(line, _conf(right),
                         "Assigning tainted input to location.href enables open redirect or javascript: URI injection.",
                         "location.href")

        # ── 2. CallExpression sinks ───────────────────────────────────────────
        if node.type == "CallExpression":
            callee = node.callee
            args = node.arguments or []
            line = node.loc.start.line if node.loc else 1

            # document.write(tainted)
            if (callee.type == "MemberExpression"
                    and callee.object.type == "Identifier"
                    and callee.object.name == "document"
                    and hasattr(callee.property, "name")
                    and callee.property.name in SINK_DOC_CALLS
                    and args and _tainted(args[0])):
                fn = callee.property.name
                _add(line, _conf(args[0]),
                     f"document.{fn}() renders unsanitized input as HTML — scripts will execute.",
                     f"document.{fn}")

            # element.insertAdjacentHTML(pos, tainted)
            if (callee.type == "MemberExpression"
                    and hasattr(callee.property, "name")
                    and callee.property.name in SINK_ADJACENT
                    and len(args) >= 2 and _tainted(args[1])):
                _add(line, _conf(args[1]),
                     "insertAdjacentHTML() with tainted second argument renders it as raw HTML.",
                     "insertAdjacentHTML")

            # eval(tainted)
            if (callee.type == "Identifier"
                    and callee.name in SINK_EVAL
                    and args and _tainted(args[0])):
                _add(line, _conf(args[0]),
                     "eval() called with user-controlled input executes it as JavaScript code.",
                     "eval")

            # setTimeout / setInterval with tainted string
            if (callee.type == "Identifier"
                    and callee.name in SINK_TIMERS
                    and args):
                first = args[0]
                if first.type != "FunctionExpression" and first.type != "ArrowFunctionExpression":
                    if _tainted(first):
                        _add(line, _conf(first),
                             f"{callee.name}() called with a tainted string executes arbitrary code after a delay.",
                             callee.name)

            # location.replace(tainted) / location.assign(tainted)
            if (callee.type == "MemberExpression"
                    and hasattr(callee.property, "name")
                    and callee.property.name in SINK_LOCATION_CALLS
                    and args and _tainted(args[0])):
                obj = callee.object
                is_loc = obj.type == "Identifier" and obj.name == "location"
                if is_loc:
                    fn = callee.property.name
                    _add(line, _conf(args[0]),
                         f"location.{fn}() with tainted input enables open redirect or javascript: URI injection.",
                         f"location.{fn}")

            # element.setAttribute('href'|'src'|..., tainted)
            if (callee.type == "MemberExpression"
                    and hasattr(callee.property, "name")
                    and callee.property.name == "setAttribute"
                    and len(args) >= 2):
                attr_node = args[0]
                val_node  = args[1]
                if (attr_node.type == "Literal"
                        and isinstance(attr_node.value, str)
                        and attr_node.value.lower() in DANGEROUS_ATTRS
                        and _tainted(val_node)):
                    attr = attr_node.value
                    _add(line, _conf(val_node),
                         f"setAttribute('{attr}', tainted) — attacker can inject javascript: URIs or event handlers.",
                         f"setAttribute-{attr}")

            # jQuery: $(sel).html(tainted), .append(tainted), etc.
            if (callee.type == "MemberExpression"
                    and hasattr(callee.property, "name")
                    and callee.property.name in SINK_JQUERY
                    and args and _tainted(args[0])):
                fn = callee.property.name
                _add(line, _conf(args[0]),
                     f"jQuery .{fn}() with tainted input renders raw HTML — equivalent to innerHTML.",
                     f"jquery.{fn}")

            # Express server-side: res.send(`<h1>${userInput}</h1>`) etc.
            if (callee.type == "MemberExpression"
                    and hasattr(callee.property, "name")
                    and callee.property.name in SINK_RES_METHODS
                    and args):
                root = _root_name(callee.object) if callee.object else ""
                if root in SINK_RES_ROOTS:
                    first = args[0]
                    # Template literal with tainted expression
                    if first.type == "TemplateLiteral":
                        for expr in (first.expressions or []):
                            if is_seed_source(expr):
                                fn = callee.property.name
                                _add(line, "HIGH",
                                     f"res.{fn}() sends a template literal containing direct user input as HTML — "
                                     f"reflected XSS: attacker can inject scripts that execute in the victim's browser.",
                                     f"res.{fn}-template-direct")
                                break
                            elif references_tainted(expr, tainted):
                                fn = callee.property.name
                                _add(line, "MEDIUM",
                                     f"res.{fn}() sends a template literal with tainted data as HTML — "
                                     f"reflected XSS risk.",
                                     f"res.{fn}-template-tainted")
                                break
                    # Concatenation: res.send('<h1>' + userInput + '</h1>')
                    elif first.type == "BinaryExpression" and _tainted(first):
                        fn = callee.property.name
                        _add(line, _conf(first),
                             f"res.{fn}() concatenates user input into the HTTP response — reflected XSS.",
                             f"res.{fn}-concat")

    walk(tree, visit)
    return issues


# ── Regex fallback (catches dangerouslySetInnerHTML + AST parse failures) ─────

def _detect_js_regex(code: str) -> List[Dict]:
    issues: List[Dict] = []
    seen: Set[tuple] = set()
    for line_num, line in enumerate(code.splitlines(), start=1):
        s = line.strip()
        if not s or s.startswith("//"):
            continue
        for pattern, message in FALLBACK_PATTERNS:
            if re.search(pattern, line):
                key = (line_num, "XSS", pattern[:20])
                if key not in seen:
                    seen.add(key)
                    issues.append({
                        "type": "XSS",
                        "line": line_num,
                        "severity": "MEDIUM",
                        "confidence": "MEDIUM",
                        "message": f"{message} (confidence: MEDIUM)",
                        "code_snippet": s,
                    })
                break
    return issues


# ── Public API ────────────────────────────────────────────────────────────────

def detect(code: str, language: str) -> List[Dict]:
    if language == "javascript":
        return _detect_js_ast(code)
    return []  # XSS detection is JavaScript-only
