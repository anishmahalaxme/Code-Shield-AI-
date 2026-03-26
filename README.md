# CodeShield – AI-Powered Secure Coding Assistant

> Real-time vulnerability detection inside VS Code, powered by AI.

---

## 🧱 Project Structure

```
codeshield/
├── backend/        # FastAPI — detection, simulation, scoring (Teammate A)
├── frontend/       # VS Code Extension — UI, highlights (Teammate B)
├── ai-service/     # AI explanation module via LLM (Teammate C)
└── docs/           # API contracts shared by all teammates
```

---

## 🚀 Quick Start

### Backend
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Frontend (VS Code Extension)
```bash
cd frontend
npm install
# Press F5 in VS Code to launch Extension Development Host
```

### AI Service
> The AI service is a Python module imported directly by the backend. No separate server needed.

---

## 🔗 API

See [`docs/api_contract.md`](docs/api_contract.md) for the full request/response schema.

Base URL (local): `http://localhost:8000`

| Method | Endpoint  | Description               |
|--------|-----------|---------------------------|
| POST   | /analyze  | Analyze code for vulnerabilities |

---

## 👥 Team

| Role        | Component    |
|-------------|--------------|
| Teammate A  | `backend/`   |
| Teammate B  | `frontend/`  |
| Teammate C  | `ai-service/`|

---

## ⚠️ Important

- Do **not** change `docs/api_contract.md` without team agreement.
- Never commit `.env` files.
- Always branch off `main` (`git checkout -b backend/feature-name`).
