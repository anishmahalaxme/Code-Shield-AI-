"""
prompts.py — Prompt templates for each vulnerability type.
Teammate C can tune these to improve AI output quality.
"""


def build_prompt(vuln_type: str, code_snippet: str) -> str:
    """Build a structured prompt for the LLM."""
    base = (
        f"You are a cybersecurity expert. A vulnerability of type '{vuln_type}' "
        f"was detected in the following code:\n\n"
        f"```\n{code_snippet}\n```\n\n"
        "Respond ONLY in this exact format (no extra text):\n"
        "EXPLANATION: <one sentence explaining why this is dangerous>\n"
        "FIX: <one line of safe replacement code>\n"
    )
    return base
