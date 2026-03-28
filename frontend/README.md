# CodeShield – AI-Powered Secure Coding Assistant

Real-time vulnerability detection inside VS Code, powered by AI.

## 🚀 Features

- **AI-Powered Analysis**: Scans your code for vulnerabilities using state-of-the-art LLMs.
- **Dynamic Simulation**: Interactive attack playground to see exploits in action.
- **Auto-Fix**: One-click remediation for detected security issues.
- **Visual Highlights**: Intuitive UI for identifying and managing security risks.

## 🛠️ Usage

1. Open a workspace in VS Code.
2. The extension activates automatically for supported languages (JavaScript, TypeScript, Python, etc.).
3. Click the **CodeShield** icon in the Activity Bar to open the security panel.
4. Run a scan using the "Run CodeShield Scan" command or via the sidebar.

## 🧱 Backend Integration

This extension requires the CodeShield backend to be running for analysis and simulation.

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

## 👥 Team

- Teammate A: Backend
- Teammate B: Frontend (VS Code Extension)
- Teammate C: AI Service

---
Part of the [CodeShield AI](https://github.com/anishmahalaxme/Code-Shield-AI-) project.
