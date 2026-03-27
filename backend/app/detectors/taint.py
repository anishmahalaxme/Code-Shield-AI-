"""
taint.py
Lightweight taint analysis for JavaScript AST (esprima).

Provides:
  build_taint_set(tree) -> (tainted: set, confidence: dict)

Algorithm (3 passes, no deep graph traversal):
  Pass 1  Collect all function parameters -> tainted HIGH
  Pass 2  Find direct seed assignments (req.*, userInput, etc.) -> tainted HIGH
  Pass 3  Propagate: if RHS references a tainted var -> LHS tainted MEDIUM
          (repeated up to 3 times to handle chains: a -> b -> c)
"""

from typing import Set, Dict, Tuple

# ── Known user-input seed identifiers ────────────────────────────────────────
# Variables with these names are treated as tainted at creation.
SEED_IDENTIFIERS: Set[str] = {
    "userInput", "user_input", "userinput",
    "formData",  "formdata",   "form_data",
    "userData",  "user_data",
    "input",     "payload",
}

# Object roots whose MemberExpression children are tainted sources.
# e.g. req.params.id, req.body.username, request.query.x
SEED_OBJECTS: Set[str] = {"req", "request"}


# ── Shared AST walker ─────────────────────────────────────────────────────────

def walk(node, callback):
    """Recursively visit every node in an esprima AST."""
    if node is None:
        return
    if isinstance(node, list):
        for item in node:
            walk(item, callback)
        return
    if not hasattr(node, "type"):
        return
    callback(node)
    for key, value in vars(node).items():
        if key in ("type", "loc", "range"):
            continue
        walk(value, callback)


# ── Taint helpers ─────────────────────────────────────────────────────────────

def _root_name(node) -> str:
    """
    Drill down a MemberExpression chain and return the root Identifier name.
    NOTE: esprima sets `object = None` as default on all node types, so we
    must check the VALUE is not None, not just whether the attribute exists.
    """
    while node is not None and getattr(node, "object", None) is not None:
        node = node.object
    if node is None or not hasattr(node, "type"):
        return ""
    return node.name if node.type == "Identifier" else ""


def is_seed_source(node) -> bool:
    """Return True if node is a direct user-input source (seed)."""
    if node is None:
        return False
    if node.type == "Identifier" and node.name in SEED_IDENTIFIERS:
        return True
    if node.type == "MemberExpression":
        root = _root_name(node)
        return root in SEED_OBJECTS
    return False


def references_tainted(node, tainted: Set[str]) -> bool:
    """
    Return True if the expression node references any variable in `tainted`
    OR is a direct seed source.
    Handles: Identifier, MemberExpression, BinaryExpression, TemplateLiteral.
    """
    if node is None:
        return False

    t = node.type

    if t == "Identifier":
        return node.name in tainted or node.name in SEED_IDENTIFIERS

    if t == "MemberExpression":
        root = _root_name(node)
        return root in tainted or root in SEED_OBJECTS

    if t == "BinaryExpression":
        return (references_tainted(node.left,  tainted) or
                references_tainted(node.right, tainted))

    if t == "TemplateLiteral":
        return any(references_tainted(e, tainted) for e in (node.expressions or []))

    if t == "CallExpression":
        # Treat function call result as tainted if any argument is tainted
        return any(references_tainted(a, tainted) for a in (node.arguments or []))

    return False


# ── Public API ────────────────────────────────────────────────────────────────

def build_taint_set(tree) -> Tuple[Set[str], Dict[str, str]]:
    """
    Analyse the AST and return all tainted variable names.

    Returns:
        tainted    : set of tainted variable names
        confidence : {var_name: "HIGH" | "MEDIUM"}
            HIGH   = direct assignment from a seed source or function param
            MEDIUM = transitively tainted (a = userInput; b = a; ...)
    """
    tainted: Set[str] = set()
    confidence: Dict[str, str] = {}

    # ── Pass 1: Function parameters (all are potentially user-controlled) ─────
    def collect_params(node):
        if node.type in ("FunctionDeclaration", "FunctionExpression",
                         "ArrowFunctionExpression"):
            for param in (node.params or []):
                if param.type == "Identifier":
                    tainted.add(param.name)
                    confidence[param.name] = "HIGH"
                elif param.type == "ObjectPattern":
                    # function({ id, name }) destructured params
                    for prop in (param.properties or []):
                        val = getattr(prop, "value", None)
                        if val and val.type == "Identifier":
                            tainted.add(val.name)
                            confidence[val.name] = "HIGH"

    walk(tree, collect_params)

    # ── Pass 2: Direct seed assignments ───────────────────────────────────────
    def collect_seeds(node):
        # const id = req.params.id / userInput
        if node.type == "VariableDeclarator" and node.init is not None:
            if node.id.type == "Identifier" and is_seed_source(node.init):
                tainted.add(node.id.name)
                confidence[node.id.name] = "HIGH"

        # id = req.params.id  (plain assignment, not declaration)
        if node.type == "AssignmentExpression" and node.operator == "=":
            if node.left.type == "Identifier" and is_seed_source(node.right):
                tainted.add(node.left.name)
                confidence[node.left.name] = "HIGH"

    walk(tree, collect_seeds)

    # ── Pass 2b: Function call taint sources ──────────────────────────────────
    # Variables assigned from calls whose name suggests user input are MEDIUM tainted.
    # e.g. const id = getUserInput()  /  const body = readBody()
    TAINT_CALL_KEYWORDS = {
        "input", "get", "read", "fetch", "receive", "parse",
        "param", "query", "body", "form", "request", "user",
    }

    def collect_call_sources(node):
        if node.type == "VariableDeclarator" and node.init is not None:
            if node.id.type != "Identifier" or node.id.name in tainted:
                return
            init = node.init
            fn_name = ""
            if init.type == "CallExpression":
                callee = init.callee
                if callee.type == "Identifier":
                    fn_name = callee.name.lower()
                elif callee.type == "MemberExpression" and hasattr(callee.property, "name"):
                    fn_name = callee.property.name.lower()

            # Only taint if function name suggests user-controlled input
            if fn_name and any(kw in fn_name for kw in TAINT_CALL_KEYWORDS):
                tainted.add(node.id.name)
                confidence[node.id.name] = "MEDIUM"

    walk(tree, collect_call_sources)

    for _ in range(3):
        prev_size = len(tainted)
        snapshot = set(tainted)  # propagate only from what's known so far

        def propagate(node):
            # const b = a   (where a is tainted)
            if node.type == "VariableDeclarator" and node.init is not None:
                if (node.id.type == "Identifier"
                        and node.id.name not in tainted
                        and references_tainted(node.init, snapshot)):
                    tainted.add(node.id.name)
                    confidence[node.id.name] = "MEDIUM"

            # b = a   (plain re-assignment)
            if node.type == "AssignmentExpression" and node.operator == "=":
                if (node.left.type == "Identifier"
                        and node.left.name not in tainted
                        and references_tainted(node.right, snapshot)):
                    tainted.add(node.left.name)
                    confidence[node.left.name] = "MEDIUM"

        walk(tree, propagate)
        if len(tainted) == prev_size:
            break  # fixed point reached — no new tainted vars

    return tainted, confidence
