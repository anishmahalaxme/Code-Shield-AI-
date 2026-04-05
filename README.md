# CodeShield AI Security

> **Real-time vulnerability detection, automated patching, and interactive exploit simulations inside VS Code.**

CodeShield acts as your personal AppSec engineer. It scans active files for vulnerabilities (SQLi, XSS, Path Traversal, Command Injection, etc.), explains *why* the code is vulnerable, simulates real-world exploits, and offers 1-click patches powered by Groq's high-speed AI models.

---

## ✨ Features

- **⚡ Instant Vulnerability Detection:** Fast AST-based scanning and taint tracking, working seamlessly with Python, JavaScript, and TypeScript.
- **🔌 Offline-Ready Local Scanner:** Even without an active backend, CodeShield's fallback regex scanner runs entirely locally in your VS Code to ensure you get immediate warnings without exposing code.
- **🛡️ Interactive Exploit Sandbox:** Simulates actual attack execution flows directly in the sidebar, demonstrating the exact risk.
- **✨ 1-Click Automated Fixes:** Highlights insecure code and provides actionable, context-aware patches that you can apply with one click.
- **📊 Security Dashboard:** A clear, intuitive UI outlining your security score, risks, and health status.

---

## 🛠️ Architecture

CodeShield is decoupled into two primary components:

1. **Frontend (VS Code Extension):** Manages the user interface, diagnostics, local scanning, and communicates with the API. 
2. **Backend (FastAPI Engine):** Orchestrates deep AST vulnerability detection, handles Gemini/Groq LLM coordination, and runs simulated exploit verifications. 

---

## 🚀 Installation & Deployment

CodeShield requires a running Python backend to power the advanced AI features. You can run the backend locally or host it easily in the cloud.

### Option 1: Cloud Deployment (Recommended)
Host the backend for free on Render so all extension users can connect without manual setup.

1. The repository includes a `render.yaml` configuration.
2. Connect your GitHub repository to [Render](https://render.com/).
3. Add your `GROQ_API_KEY` (or `GEMINI_API_KEY`) when prompted in the Render dashboard.
4. Update `frontend/package.json` with the new Render URL:
   ```json
   "codeshield.backendUrl": {
     "default": "https://your-codeshield-backend.onrender.com"
   }
   ```

### Option 2: Local Deployment
Run the backend server on your local machine.

```bash
cd backend
pip install -r requirements.txt

# Set your API Key
export GROQ_API_KEY="gsk_your_api_key_here"

# Start the API server
uvicorn app.main:app --port 8000
```
> The extension connects to `http://127.0.0.1:8000` by default.

---

## 📦 Extension Setup

Ensure you have Node.js and npm installed.

```bash
cd frontend
npm install
npm run compile
```
- Open the project in VS Code, go to the Run panel, and hit **F5** to launch the Extension Development Host.
- Or package it into a `.vsix` extension file using `vsce package`.
