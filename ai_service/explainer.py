"""
explainer.py — AI explanation module.
Called directly by backend/app/services/scanner.py (no HTTP, just import).

Teammate C owns this file.
"""

import os
from ai_service.prompts import build_prompt

# Uncomment whichever LLM you are using:
# from openai import OpenAI
# import google.generativeai as genai


def explain(vuln_type: str, code_snippet: str) -> dict:
    """
    Given a vulnerability type and the offending code snippet,
    returns an AI-generated explanation and fix suggestion.

    Args:
        vuln_type:     e.g. "sql_injection", "xss", "hardcoded_secret"
        code_snippet:  The raw line(s) of code flagged by the detector

    Returns:
        {
            "explanation": "Why this is dangerous and how it can be exploited.",
            "fix":         "Safe alternative code snippet."
        }
    """
    prompt = build_prompt(vuln_type, code_snippet)

    # ── OpenAI ──────────────────────────────────────────────────
    # client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    # response = client.chat.completions.create(
    #     model="gpt-4o-mini",
    #     messages=[{"role": "user", "content": prompt}],
    # )
    # raw = response.choices[0].message.content

    # ── Google Gemini ────────────────────────────────────────────
    # genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
    # model = genai.GenerativeModel("gemini-1.5-flash")
    # raw = model.generate_content(prompt).text

    # ── STUB (remove when LLM is wired up) ──────────────────────
    raw = _stub_response(vuln_type)

    return _parse_response(raw)


def _parse_response(raw: str) -> dict:
    """Parse LLM output into explanation + fix fields."""
    explanation, fix = "", ""
    for line in raw.splitlines():
        if line.startswith("EXPLANATION:"):
            explanation = line.replace("EXPLANATION:", "").strip()
        elif line.startswith("FIX:"):
            fix = line.replace("FIX:", "").strip()
    return {"explanation": explanation or raw.strip(), "fix": fix}


def _stub_response(vuln_type: str) -> str:
    """Temporary stub — replace with real LLM call."""
    stubs = {
        "sql_injection": (
            "EXPLANATION: Concatenating user input into SQL queries allows attackers to alter query logic.\n"
            "FIX: Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))"
        ),
        "xss": (
            "EXPLANATION: Inserting unsanitized data into innerHTML lets attackers inject executable scripts.\n"
            "FIX: Use textContent instead of innerHTML, or sanitize with DOMPurify."
        ),
        "hardcoded_secret": (
            "EXPLANATION: Hardcoded secrets in source code can be extracted from version history or binaries.\n"
            "FIX: Load secrets from environment variables using os.getenv('API_KEY')."
        ),
    }
    return stubs.get(vuln_type, "EXPLANATION: Potential security issue detected.\nFIX: Review this code carefully.")
