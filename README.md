# CodeShield AI Security

> **Real-time vulnerability detection, automated patching, and interactive exploit simulations inside VS Code.**

CodeShield acts as your personal AppSec engineer. It scans active files for vulnerabilities (SQLi, XSS, Path Traversal, Command Injection, etc.), explains *why* the code is vulnerable, simulates real-world exploits, and offers 1-click patches powered by Groq's high-speed AI models.

---

## ✨ Features

- **⚡ Instant Vulnerability Detection:** Fast AST-based scanning and taint tracking, working seamlessly with Python, JavaScript, and TypeScript.
- **🔌 Offline-Ready Local Scanner:** Even without an active backend, CodeShield's fallback regex scanner runs entirely locally in your VS Code to ensure you always get immediate security warnings.
- **🛡️ Interactive Exploit Sandbox:** Simulates actual attack execution flows directly in the sidebar, demonstrating the exact risk.
- **✨ 1-Click Automated Fixes:** Highlights insecure code and provides actionable, context-aware patches that you can apply with one click.
- **📊 Security Dashboard:** A clear, intuitive UI outlining your security score, risks, and health status.

---

## 🛠️ Architecture Overview

CodeShield is decoupled into two primary components to allow running the AI-intensive tasks separately:
1. **Frontend (VS Code Extension):** Manages the user interface, diagnostics, local fallback scanning, and communicates with the backend API.
2. **Backend (Python FastAPI Engine):** Orchestrates deep AST vulnerability detection, handles Gemini/Groq LLM coordination, and runs simulated exploit verifications.

---

## 🚀 Getting Started

If you downloaded the CodeShield extension from the marketplace, you will need to set up the **Python Backend** locally to unlock the advanced AI analysis, explanations, and automatic fixes.

### Step 1: Clone the CodeShield Repository
The backend code lives alongside the extension. Download it to your machine:
```bash
git clone https://github.com/anishmahalaxme/Code-Shield-AI-.git
cd "Code-Shield-AI-/backend"
```

### Step 2: Get a Free API Key
CodeShield uses the blazing-fast Groq AI to process vulnerabilities.
1. Go to the [Groq Console](https://console.groq.com/).
2. Create a free account and generate an API key.

### Step 3: Install Backend Requirements
Make sure you have Python 3.9 or higher installed. Inside the `backend` folder, install the required packages:
```bash
pip install -r requirements.txt
```

### Step 4: Start the Backend Server
Set your API key as an environment variable and start the FastAPI server. The VS Code extension expects to find this server running on `http://127.0.0.1:8000`.

**On Windows (PowerShell):**
```powershell
$env:GROQ_API_KEY="gsk_your_api_key_here"
uvicorn app.main:app --port 8000
```

**On Mac / Linux (Bash):**
```bash
export GROQ_API_KEY="gsk_your_api_key_here"
uvicorn app.main:app --port 8000
```

> **Note:** As long as this terminal is running, your CodeShield extension in VS Code will have full access to its AI powers!

---

## 💻 Usage Instructions

1. **Activate:** Open any supported file (`.ts`, `.js`, `.py`, etc.) in VS Code. CodeShield will immediately analyze the code.
2. **Review:** Check the VS Code Status Bar in the bottom right corner (`CodeShield: SCANNING`, `CodeShield: RISK`, or `CodeShield: SAFE`).
3. **Analyze:** Click the **CodeShield icon** in the Activity Bar to open the detailed security dashboard.
4. **Fix:** Hover over an error squiggle and click **Quick Fix**, or use the **Auto-Fix Code** button in the sidebar.
5. **Simulate:** Click **Run simulation** on a vulnerability card to see a mock execution of an exploit payload.
