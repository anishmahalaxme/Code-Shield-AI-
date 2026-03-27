from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes.analyze import router as analyze_router

app = FastAPI(
    title="CodeShield API",
    description="AI-Powered Secure Coding Assistant — vulnerability detection backend",
    version="1.0.0",
)

# ── CORS ──────────────────────────────────────────────────────────────────────
# Allows the VS Code Extension (running as localhost) to reach this API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict to specific origin in production
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# ── Routes ────────────────────────────────────────────────────────────────────
app.include_router(analyze_router)


@app.get("/")
def health():
    return {"status": "CodeShield backend is running", "version": "1.0.0"}
