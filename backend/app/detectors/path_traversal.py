"""
path_traversal.py
Detects Path Traversal vulnerabilities.

Path Traversal occurs when user-controlled input is used to construct
file system paths, allowing an attacker to escape the intended directory
and access arbitrary files (e.g., ../../etc/passwd).

JavaScript -> AST-based (esprima + taint.py):
  Sinks detected:
    fs.*         -> readFile, readFileSync, writeFile, writeFileSync,
                    appendFile, appendFileSync, unlink, unlinkSync,
                    rmdir, rmdirSync, stat, statSync, lstat, access,
                    createReadStream, createWriteStream, open, openSync
    path.*       -> path.join(), path.resolve() with tainted segment
    require()    -> dynamic require with tainted module path
    express      -> res.sendFile(), res.download() with tainted path
    url parsing  -> new URL(tainted), URL.pathname taint

Python -> regex-based:
  open(), os.path.join(), os.listdir(), os.remove(), shutil.*,
  pathlib.Path() with user-controlled input
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

# fs module methods — any argument that is a file path and is tainted
FS_READ_METHODS  = {"readFile", "readFileSync", "createReadStream",
                    "stat", "statSync", "lstat", "lstatSync",
                    "access", "accessSync", "open", "openSync"}

FS_WRITE_METHODS = {"writeFile", "writeFileSync", "appendFile", "appendFileSync",
                    "createWriteStream"}

FS_DELETE_METHODS = {"unlink", "unlinkSync", "rmdir", "rmdirSync",
                     "rm", "rmSync", "rename", "renameSync"}

ALL_FS_METHODS = FS_READ_METHODS | FS_WRITE_METHODS | FS_DELETE_METHODS

# path.join / path.resolve — dangerous if any segment is tainted
PATH_METHODS = {"join", "resolve", "normalize"}

# Express response methods that serve files
EXPRESS_FILE_METHODS = {"sendFile", "download", "sendfile"}

# Severity per method category
def _severity(method: str) -> str:
    if method in FS_DELETE_METHODS:
        return "HIGH"   # deletion/rename is critical
    if method in FS_WRITE_METHODS:
        return "HIGH"   # writing to arbitrary paths
    return "MEDIUM"     # reading — still serious but less destructive


# ── Python regex patterns ─────────────────────────────────────────────────────

PY_PATTERNS = [
    # open() with user input
    (r'\bopen\s*\(\s*(?:request\.|req\.|user|form|param|input|data)',
     "open() called with user-controlled path — path traversal risk.", "HIGH"),
    (r'\bopen\s*\(\s*f["\'].*\{',
     "open() uses f-string interpolation for the path — path traversal risk.", "HIGH"),
    (r'\bopen\s*\(\s*["\']?.*["\']?\s*\+\s*\w',
     "open() with concatenated path — attacker may inject ../ sequences.", "MEDIUM"),

    # os.path operations
    (r'os\.path\.(join|abspath|realpath)\s*\(.*(?:request\.|req\.|user|input|param)',
     "os.path function called with user-controlled path component.", "MEDIUM"),
    (r'os\.(listdir|remove|unlink|rmdir|rename|stat|open)\s*\(.*(?:request\.|user|input|param)',
     "os filesystem function called with user-controlled path.", "HIGH"),

    # pathlib
    (r'Path\s*\(\s*(?:request\.|req\.|user|form|input)',
     "pathlib.Path() constructed from user-controlled input — path traversal risk.", "MEDIUM"),

    # shutil
    (r'shutil\.(copy|move|rmtree|copyfile)\s*\(.*(?:request\.|user|input|param)',
     "shutil function called with user input — arbitrary file access/destruction.", "HIGH"),
]

# ── JavaScript regex fallback patterns ───────────────────────────────────────
JS_PATTERNS = [
    # fs.readFile / readFileSync with template literal or concat
    (r'\bfs\.read(?:File|FileSync)\s*\([^,)]*[+`]',
     "fs.readFile() called with a dynamic path — path traversal risk.", "HIGH"),
    (r'\bfs\.readFileSync\s*\([^,)]*[+`]',
     "fs.readFileSync() called with a dynamic path — attacker can read arbitrary files.", "HIGH"),
    # fs.writeFile with template literal or concat
    (r'\bfs\.write(?:File|FileSync)\s*\([^,)]*[+`]',
     "fs.writeFile() called with a dynamic path — attacker can write to arbitrary files.", "HIGH"),
    # path.join with req.* / user input
    (r'path\.(?:join|resolve)\s*\(.*(?:req\.|request\.|userInput|user_input|input|param)',
     "path.join/resolve() uses user-controlled input — ../ traversal can escape the base dir.", "MEDIUM"),
    # res.sendFile with dynamic path
    (r'res\.(?:sendFile|download)\s*\([^)]*(?:req\.|\$\{|\+)',
     "res.sendFile/download() with user-controlled path — serves arbitrary files to the client.", "HIGH"),
    # Generic: fs.* with req.* in args
    (r'\bfs\.\w+\s*\(.*req\.',
     "fs filesystem method called with a value from the HTTP request — path traversal risk.", "HIGH"),
    # readFileSync with req body/query/params
    (r'readFileSync\s*\(.*(?:req\.body|req\.query|req\.params)',
     "readFileSync() uses HTTP request data as path — directory traversal vulnerability.", "HIGH"),
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

    def _add(line: int, sev: str, conf: str, message: str, sink: str):
        key = (line, "PATH_TRAVERSAL", sink)
        if key not in seen:
            seen.add(key)
            flow = "direct user input" if conf == "HIGH" else "tainted variable"
            issues.append({
                "type": "PATH_TRAVERSAL",
                "line": line,
                "severity": sev,
                "confidence": conf,
                "message": f"{message} Input is {flow}. (confidence: {conf})",
                "code_snippet": _real_snippet(code, line),
            })

    def _conf(node) -> str:
        return "HIGH" if is_seed_source(node) else "MEDIUM"

    def _tainted(node) -> bool:
        return is_seed_source(node) or references_tainted(node, tainted)

    def visit(node):
        if node.type != "CallExpression":
            return

        callee = node.callee
        args   = node.arguments or []
        line   = node.loc.start.line if node.loc else 1

        # ── Pattern 1: fs.readFile(taintedPath, ...) ─────────────────────────
        if (callee.type == "MemberExpression"
                and hasattr(callee.property, "name")):

            method    = callee.property.name
            obj       = callee.object

            # fs.method(path, ...) — first arg is the path
            is_fs_obj = (obj.type == "Identifier" and obj.name == "fs")
            if is_fs_obj and method in ALL_FS_METHODS and args and _tainted(args[0]):
                sev = _severity(method)
                conf = _conf(args[0])
                _add(line, sev, conf,
                     f"fs.{method}() called with user-controlled path — attacker may traverse to any file.",
                     f"fs.{method}")

            # path.join(base, tainted) / path.resolve(tainted)
            is_path_obj = (obj.type == "Identifier" and obj.name == "path")
            if is_path_obj and method in PATH_METHODS:
                for arg in args:
                    if _tainted(arg):
                        _add(line, "MEDIUM", _conf(arg),
                             f"path.{method}() includes user-controlled segment — ../ sequences can escape the base directory.",
                             f"path.{method}")
                        break

            # res.sendFile(taintedPath) / res.download(taintedPath)
            is_res = (obj.type == "Identifier" and obj.name == "res")
            if is_res and method in EXPRESS_FILE_METHODS and args and _tainted(args[0]):
                _add(line, "HIGH", _conf(args[0]),
                     f"res.{method}() called with user-controlled path — serves arbitrary files to the client.",
                     f"res.{method}")

        # ── Pattern 2: require(taintedPath) ──────────────────────────────────
        if (callee.type == "Identifier"
                and callee.name == "require"
                and args and _tainted(args[0])):
            _add(line, "HIGH", _conf(args[0]),
                 "require() called with user-controlled module path — arbitrary code load risk.",
                 "require")

        # ── Pattern 3: new URL(tainted) — tainted URL construction ───────────
        if (node.type == "CallExpression"
                and callee.type == "Identifier"
                and callee.name == "URL"
                and args and _tainted(args[0])):
            _add(line, "MEDIUM", _conf(args[0]),
                 "URL constructed from user input — path traversal or SSRF risk depending on usage.",
                 "URL")

    walk(tree, visit)

    # If AST found nothing, run JS regex fallback
    if not issues:
        issues = _detect_js_regex(code)

    return issues


# ── JavaScript regex fallback ─────────────────────────────────────────────────

def _detect_js_regex(code: str) -> List[Dict]:
    issues: List[Dict] = []
    seen: Set[tuple] = set()
    for line_num, line in enumerate(code.splitlines(), start=1):
        s = line.strip()
        if not s or s.startswith("//"):
            continue
        for pattern, message, severity in JS_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                key = (line_num, "PATH_TRAVERSAL")
                if key not in seen:
                    seen.add(key)
                    issues.append({
                        "type": "PATH_TRAVERSAL",
                        "line": line_num,
                        "severity": severity,
                        "confidence": "HIGH",
                        "message": f"{message} (confidence: HIGH)",
                        "code_snippet": s,
                    })
                break
    return issues


def _detect_python_regex(code: str) -> List[Dict]:
    issues: List[Dict] = []
    seen: Set[tuple] = set()
    for line_num, line in enumerate(code.splitlines(), start=1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        for pattern, message, severity in PY_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                key = (line_num, "PATH_TRAVERSAL")
                if key not in seen:
                    seen.add(key)
                    issues.append({
                        "type": "PATH_TRAVERSAL",
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
