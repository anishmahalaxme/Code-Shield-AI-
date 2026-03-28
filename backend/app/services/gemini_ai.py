"""
gemini_ai.py
Generates context-aware AI explanations and fix suggestions.
Updated to use the Groq API (Llama 3.3 70B Fast) instead of Gemini, 
due to strict Gemini free-tier rate limits. 

Maintains the exact same interface `get_ai_explanation` for analyze.py.
"""

import os
import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

# backend/.env (works no matter what cwd uvicorn was started from)
_BACKEND_ENV = Path(__file__).resolve().parents[2] / ".env"

# ── Import Groq SDK ───────────────────────────────────────────────────────────
try:
    from groq import Groq
    from dotenv import load_dotenv
    _SDK_AVAILABLE = True
except ImportError:
    _SDK_AVAILABLE = False
    log.warning("groq or python-dotenv not installed — AI disabled.")

# ── Configure ─────────────────────────────────────────────────────────────────
if _SDK_AVAILABLE:
    load_dotenv(_BACKEND_ENV)
    load_dotenv()
    
_API_KEY = os.getenv("GROQ_API_KEY") or os.getenv("GEMINI_API_KEY")
_CLIENT = None
if _SDK_AVAILABLE and _API_KEY:
    try:
        _CLIENT = Groq(api_key=_API_KEY)
    except Exception as e:
        log.warning("Failed to create Groq client: %s", e)
else:
    if _SDK_AVAILABLE and not _API_KEY:
        log.warning("GROQ_API_KEY not set — AI disabled.")

_MODELS = [
    "llama-3.3-70b-versatile",   # Primary: Llama 3.3 70B (fast, high-quality)
    "llama-3.1-8b-instant",      # Fallback: Llama 3.1 8B (fast, rate-limit resilient)
]

# ── Fallbacks ─────────────────────────────────────────────────────────────────
FALLBACK_EXPLANATIONS = {
    "SQL_INJECTION": (
        "SQL Injection occurs when user-supplied input is embedded directly "
        "into a SQL query without sanitization. An attacker can alter the "
        "query's logic to bypass authentication, extract data, or corrupt the database."
    ),
    "XSS": (
        "Cross-Site Scripting (XSS) happens when unsanitized user input is "
        "rendered as HTML in the browser. An attacker can inject malicious scripts "
        "that steal session cookies, redirect users, or perform actions on their behalf."
    ),
    "HARDCODED_SECRET": (
        "Hardcoding secrets (API keys, passwords, tokens) in source code exposes "
        "them to anyone with repository access. They also persist in version history."
    ),
    "PATH_TRAVERSAL": (
        "Path Traversal occurs when user-controlled input is used to build a file "
        "system path without sanitization. An attacker can inject ../ sequences to "
        "escape the intended directory and read arbitrary files."
    ),
    "COMMAND_INJECTION": (
        "Command Injection occurs when user-supplied input is passed unsanitized to "
        "a shell execution function. An attacker can append arbitrary OS commands "
        "using separators like ; && || — leading to full Remote Code Execution."
    ),
}

FALLBACK_FIXES = {
    "SQL_INJECTION": "Use parameterized queries (prepared statements) instead of string concatenation.",
    "XSS": "Use textContent instead of innerHTML for plain text. Sanitize HTML with DOMPurify if needed.",
    "HARDCODED_SECRET": "Store secrets in environment variables (process.env / os.getenv). Use a .env file locally.",
    "PATH_TRAVERSAL": "Use path.basename() to strip directory components, then validate against the expected base directory.",
    "COMMAND_INJECTION": "Use execFile() / spawn() with an argument array (JS) or subprocess.run([cmd, arg], shell=False) (Python).",
}

DEFAULT_EXPLANATION = "This vulnerability allows attackers to manipulate input and compromise the system."
DEFAULT_FIX = "Apply proper input validation and follow secure coding practices for this pattern."

# ── Prompt builder ────────────────────────────────────────────────────────────

def _build_prompt(vuln_type: str, code_snippet: str, message: str, language: str) -> str:
    friendly = vuln_type.replace("_", " ").title()
    return f"""You are a senior security engineer reviewing a {language} codebase.

A vulnerability scanner detected a **{friendly}** on this line of code:

```{language}
{code_snippet}
```

Scanner message: {message}

Respond in exactly this format — no markdown headers, no extra text:

EXPLANATION:
<2-3 sentences explaining why THIS specific code is vulnerable and what an attacker can do>

FIX:
<1-3 sentences with a concrete fix for THIS specific code — include code syntax if helpful>"""

def _build_fix_prompt(vuln_type: str, code_snippet: str, message: str, language: str) -> str:
    friendly = vuln_type.replace("_", " ").title()
    return f"""You are an automated code repair agent. 

A vulnerability scanner detected a **{friendly}** on this line of {language} code:

```{language}
{code_snippet}
```

Scanner message: {message}

Provide EXACTLY the fixed version of this code snippet. 
Do not include ANY markdown blocks, no conversational text, no explanations. 
Just the pure, raw code that replaces the snippet exactly line-for-line where possible.
"""


def _build_simulation_prompt(vuln_type: str, code_snippet: str, payload: str, language: str) -> str:
    friendly = vuln_type.replace("_", " ").title()
    return f"""You are a security simulation engine. 
A developer is testing a **{friendly}** vulnerability in this {language} code:
```{language}
{code_snippet}
```

The developer provided this test payload: `{payload}`

Imagine and describe what the result of this execution would be in a real-world vulnerable server.
Respond in exactly this format — no markdown headers, no extra text:

RECONSTRUCTED_QUERY:
<The final string or command as it would be executed after injection>

ATTACK_RESULT:
<The console output, data dump, or error. If it's a mock table, use markdown table. Max 5 lines.>

ATTACK_CLASS:
<2-3 words category>

IMPACT:
<1 sentence summary of risk>

IS_ATTACK:
<TRUE if the payload triggers the vuln, FALSE if it was harmless>"""


# ── Public API ────────────────────────────────────────────────────────────────

def get_ai_explanation(
    vuln_type: str,
    code_snippet: str,
    message: str,
    language: str,
) -> dict:
    """
    Call Groq (Llama 3.3) for explanation + fix specific to the given snippet.
    Returns {"explanation": str, "fix": str} always — falls back on any error.
    """
    fallback_exp = FALLBACK_EXPLANATIONS.get(vuln_type, DEFAULT_EXPLANATION)
    fallback_fix = FALLBACK_FIXES.get(vuln_type, DEFAULT_FIX)

    if not _CLIENT:
        return {"explanation": fallback_exp, "fix": fallback_fix}

    prompt = _build_prompt(vuln_type, code_snippet or "(no snippet)", message, language)

    # Try each model in order
    last_error = None
    for model_name in _MODELS:
        try:
            response = _CLIENT.chat.completions.create(
                model=model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
                max_tokens=350,
            )
            text = response.choices[0].message.content or ""
            if text:
                explanation, fix = _parse_response(text, fallback_exp, fallback_fix)
                log.info("Groq (%s) explanation OK for %s", model_name, vuln_type)
                return {"explanation": explanation, "fix": fix}
        except Exception as exc:
            last_error = exc
            err_str = str(exc).lower()
            if "429" in str(exc) or "rate limit" in err_str:
                log.warning("Groq %s rate limit exceeded — trying next model.", model_name)
                continue
            log.warning("Groq %s failed (%s) — using fallback.", model_name, exc)
            break

    if last_error:
        log.warning("All Groq models failed for %s — using fallback.", vuln_type)
    return {"explanation": fallback_exp, "fix": fallback_fix}


def get_ai_fix_code(
    vuln_type: str,
    code_snippet: str,
    message: str,
    language: str,
) -> str:
    """
    Call Groq to generate EXACTLY the replacement raw code for a single snippet.
    Falls back to returning the original snippet on error.
    """
    if not _CLIENT or not code_snippet.strip():
        return code_snippet

    prompt = _build_fix_prompt(vuln_type, code_snippet, message, language)

    # Try models
    for model_name in _MODELS:
        try:
            response = _CLIENT.chat.completions.create(
                model=model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
                max_tokens=250,
            )
            text = response.choices[0].message.content or ""
            text = text.strip()
            # Strip markdown code blocks if the LLM leaked them
            if text.startswith("```"):
                lines = text.splitlines()
                if len(lines) >= 2 and lines[0].startswith("```") and lines[-1].startswith("```"):
                    text = "\\n".join(lines[1:-1]).strip()
            return text
        except Exception as exc:
            err_str = str(exc).lower()
            if "429" in str(exc) or "rate limit" in err_str:
                continue
            break

    return code_snippet


def get_ai_simulation_result(
    vuln_type: str,
    payload: str,
    code_snippet: str,
    language: str,
) -> dict:
    """
    Call Groq to imagine the result of an exploit test.
    Returns {query, attack_result, attack_class, impact, is_attack}.
    """
    default_res = {
        "query": f"Input: {payload}",
        "attack_result": "Simulation skipped (AI service offline).",
        "attack_class": "Unknown",
        "impact": "Security risk unknown.",
        "is_attack": False
    }

    if not _CLIENT:
        return default_res

    prompt = _build_simulation_prompt(vuln_type, code_snippet, payload, language)

    # Try models
    for model_name in _MODELS:
        try:
            response = _CLIENT.chat.completions.create(
                model=model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=400,
            )
            text = response.choices[0].message.content or ""
            parsed = _parse_simulation_response(text)
            if parsed:
                return parsed
        except Exception as exc:
            err_str = str(exc).lower()
            if "429" in str(exc) or "rate limit" in err_str:
                continue
            break

    return default_res


def _parse_simulation_response(text: str) -> Optional[dict]:
    """Parse the structured simulation response from the LLM."""
    try:
        res = {
            "query": "",
            "attack_result": "",
            "attack_class": "",
            "impact": "",
            "is_attack": False
        }
        mode = None
        for line in text.splitlines():
            s = line.strip()
            if not s: continue
            U = s.upper()
            if U.startswith("RECONSTRUCTED_QUERY:"): mode = "q"
            elif U.startswith("ATTACK_RESULT:"): mode = "res"
            elif U.startswith("ATTACK_CLASS:"): mode = "cls"
            elif U.startswith("IMPACT:"): mode = "imp"
            elif U.startswith("IS_ATTACK:"): mode = "is"
            else:
                val = s
                if mode == "q": res["query"] += (val + " ")
                elif mode == "res": res["attack_result"] += (val + "\n")
                elif mode == "cls": res["attack_class"] += (val + " ")
                elif mode == "imp": res["impact"] += (val + " ")
                elif mode == "is": res["is_attack"] = ("TRUE" in U)

        # Cleanup
        for k in ["query", "attack_result", "attack_class", "impact"]:
            res[k] = res[k].strip()
        
        return res if res["query"] else None
    except Exception:
        return None

def _parse_response(text: str, fallback_exp: str, fallback_fix: str):
    """Parse Llama 3's EXPLANATION: / FIX: structured response."""
    explanation = fallback_exp
    fix = fallback_fix

    try:
        mode = None
        exp_lines, fix_lines = [], []

        for line in text.splitlines():
            stripped = line.strip()
            if stripped.upper().startswith("EXPLANATION:"):
                mode = "exp"
                after = stripped[len("EXPLANATION:"):].strip()
                if after:
                    exp_lines.append(after)
            elif stripped.upper().startswith("FIX:"):
                mode = "fix"
                after = stripped[len("FIX:"):].strip()
                if after:
                    fix_lines.append(after)
            elif mode == "exp":
                if stripped: exp_lines.append(stripped)
            elif mode == "fix":
                if stripped: fix_lines.append(stripped)

        if exp_lines:
            explanation = " ".join(exp_lines)
        if fix_lines:
            fix = " ".join(fix_lines)

    except Exception:
        pass

    return explanation, fix
