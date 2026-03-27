from pydantic import BaseModel
from typing import List, Optional


# ── Request ───────────────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    code: str
    language: str  # "javascript" | "python" | anything else


# ── Sub-models ────────────────────────────────────────────────────────────────

class Simulation(BaseModel):
    payload: str
    result: str
    impact: str


class AIPlaceholder(BaseModel):
    explanation: str = ""
    fix: str = ""


class Issue(BaseModel):
    id: str
    type: str          # "SQL_INJECTION" | "XSS" | "HARDCODED_SECRET"
    line: int
    severity: str      # "LOW" | "MEDIUM" | "HIGH"
    confidence: str    # "HIGH" (direct) | "MEDIUM" (via tainted variable)
    message: str
    code_snippet: str
    simulation: Simulation
    ai: AIPlaceholder


# ── Response ──────────────────────────────────────────────────────────────────

class AnalyzeResponse(BaseModel):
    issues: List[Issue]
    score: int
    message: Optional[str] = None  # Used for unsupported language
