"""
analyze.py
POST /analyze — primary API endpoint.

Flow:
  1. Validate language → return early if unsupported
  2. Run all detectors via scanner
  3. Enrich each issue: simulation + AI mock placeholder
  4. Compute security score
  5. Return AnalyzeResponse
"""

import logging
import uuid

from fastapi import APIRouter

log = logging.getLogger(__name__)
from app.models.schemas import (
    AnalyzeRequest, AnalyzeResponse,
    Issue, Simulation, AIPlaceholder,
    FixRequest, FixResponse,
    SimulateRequest, SimulateResponse
)
from app.services.scanner import run_scan, SUPPORTED_LANGUAGES, normalize_language
from app.services.simulator import get_simulation
from app.services.gemini_ai import (
    get_ai_explanation, get_ai_fix_code, get_ai_simulation_result
)

router = APIRouter()

SEVERITY_DEDUCTIONS = {"HIGH": 20, "MEDIUM": 10, "LOW": 5}

# ── AI mock placeholders per vulnerability type ───────────────────────────────
# Teammate C will replace these with real LLM responses later.
AI_MOCKS = {
    "SQL_INJECTION": AIPlaceholder(
        explanation=(
            "SQL Injection occurs when user-supplied input is embedded directly "
            "into a SQL query without sanitization. An attacker can alter the "
            "query's logic to bypass authentication, extract data, or corrupt the database."
        ),
        fix="Use parameterized queries (prepared statements) instead of string concatenation.",
    ),
    "XSS": AIPlaceholder(
        explanation=(
            "Cross-Site Scripting (XSS) happens when unsanitized user input is "
            "rendered as HTML in the browser. An attacker can inject malicious scripts "
            "that steal session cookies, redirect users, or perform actions on their behalf."
        ),
        fix=(
            "Use textContent instead of innerHTML for plain text. "
            "If HTML rendering is needed, sanitize with a library like DOMPurify."
        ),
    ),
    "HARDCODED_SECRET": AIPlaceholder(
        explanation=(
            "Hardcoding secrets (API keys, passwords, tokens) in source code exposes "
            "them to anyone with repository access or who can inspect the binary. "
            "They also persist in version history even after deletion."
        ),
        fix=(
            "Store secrets in environment variables and access them via "
            "process.env.SECRET_NAME (JS) or os.getenv('SECRET_NAME') (Python). "
            "Use a .env file locally and a secrets manager in production."
        ),
    ),
    "PATH_TRAVERSAL": AIPlaceholder(
        explanation=(
            "Path Traversal (also called Directory Traversal) occurs when user-controlled "
            "input is used to build a file system path without sanitization. "
            "An attacker can inject ../ sequences to escape the intended directory "
            "and read or write arbitrary files (e.g., ../../../../etc/passwd)."
        ),
        fix=(
            "Never concatenate user input directly into file paths. "
            "Use path.basename() to strip directory components, then validate against "
            "an allowlist of permitted filenames. "
            "Resolve the final path with path.resolve() and verify it starts with the "
            "expected base directory (e.g., if (!resolved.startsWith(BASE_DIR)) throw Error)."
        ),
    ),
    "COMMAND_INJECTION": AIPlaceholder(
        explanation=(
            "Command Injection occurs when user-supplied input is passed unsanitized to "
            "a shell execution function (exec, execSync, os.system, subprocess). "
            "An attacker can terminate the intended command and append arbitrary OS commands "
            "using separators like ;, &&, ||, or | — leading to full Remote Code Execution (RCE)."
        ),
        fix=(
            "Never pass user input to shell execution functions as a string. "
            "For JS: use execFile() or spawn() with an argument array instead of exec(). "
            "For Python: use subprocess.run([cmd, arg1, arg2], shell=False) — never shell=True with user input. "
            "If shell commands are unavoidable, use a strict allowlist for permitted values and "
            "escape with a library like shell-escape (JS) or shlex.quote() (Python)."
        ),
    ),
}


DEFAULT_AI = AIPlaceholder(
    explanation="This vulnerability allows attackers to manipulate input and compromise the system.",
    fix="Review this code and apply proper input validation or secure coding practices.",
)


@router.post("/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest):
    # Must match run_scan: TS/TSX/JSX scan as javascript (extension sends "typescript" for .ts)
    lang = normalize_language(request.language)

    # ── Unsupported language ──────────────────────────────────────────────────
    if lang not in SUPPORTED_LANGUAGES:
        return AnalyzeResponse(issues=[], score=100, message="Unsupported language")

    # ── Detect ────────────────────────────────────────────────────────────────
    raw_issues = run_scan(request.code, lang)

    # ── Enrich ────────────────────────────────────────────────────────────────
    enriched: list[Issue] = []
    for raw in raw_issues:
        vuln_type = raw.get("type", "UNKNOWN")
        sim_data = get_simulation(vuln_type)
        try:
            ai_data = get_ai_explanation(
                vuln_type=vuln_type,
                code_snippet=raw.get("code_snippet", "") or "",
                message=raw.get("message", ""),
                language=request.language.lower(),
            )
            if not isinstance(ai_data, dict):
                ai_data = {"explanation": DEFAULT_AI.explanation, "fix": DEFAULT_AI.fix}
            ai_placeholder = AIPlaceholder(
                explanation=str(ai_data.get("explanation", DEFAULT_AI.explanation)),
                fix=str(ai_data.get("fix", DEFAULT_AI.fix)),
            )
            enriched.append(Issue(
                id=raw.get("id") or str(uuid.uuid4()),
                type=vuln_type,
                line=int(raw.get("line", 1)),
                severity=str(raw.get("severity", "MEDIUM")),
                confidence=str(raw.get("confidence", "HIGH")),
                message=str(raw.get("message", "")),
                code_snippet=str(raw.get("code_snippet", "") or "(no snippet)"),
                simulation=Simulation(**sim_data),
                ai=ai_placeholder,
            ))
        except Exception:
            log.exception("Enrich failed for issue type=%s — using static AI/sim defaults", vuln_type)
            mock_ai = AI_MOCKS.get(vuln_type, DEFAULT_AI)
            enriched.append(Issue(
                id=raw.get("id") or str(uuid.uuid4()),
                type=vuln_type,
                line=int(raw.get("line", 1)),
                severity=str(raw.get("severity", "MEDIUM")),
                confidence=str(raw.get("confidence", "HIGH")),
                message=str(raw.get("message", "")),
                code_snippet=str(raw.get("code_snippet", "") or "(no snippet)"),
                simulation=Simulation(**sim_data),
                ai=mock_ai,
            ))

    # ── Score ─────────────────────────────────────────────────────────────────
    score = 100
    for issue in enriched:
        score -= SEVERITY_DEDUCTIONS.get(issue.severity, 0)
    score = max(0, score)

    return AnalyzeResponse(issues=enriched, score=score)


@router.post("/fix", response_model=FixResponse)
def fix(request: FixRequest):
    """
    Endpoint to trigger an automated code replacement fix using the Groq AI engine.
    """
    fixed_code = get_ai_fix_code(
        vuln_type=request.issue_type,
        code_snippet=request.code_snippet,
        message=request.message,
        language=request.language
    )
    return FixResponse(fixed_code=fixed_code)


@router.post("/simulate", response_model=SimulateResponse)
def simulate(request: SimulateRequest):
    """
    Endpoint to trigger a dynamic AI-powered security simulation for a specific payload.
    """
    res = get_ai_simulation_result(
        vuln_type=request.vuln_type,
        payload=request.payload,
        code_snippet=request.code_snippet,
        language=request.language
    )
    return SimulateResponse(**res)
