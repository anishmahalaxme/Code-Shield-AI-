# CodeShield AI Security

> **Real-time vulnerability detection, automated patching, and interactive exploit simulations inside VS Code—powered by Groq AI.**


CodeShield is a next-generation AI security assistant integrated directly into your editor. Stop vulnerabilities before they reach production with blazingly fast, context-aware AI analysis that acts as your personal AppSec engineer.

---

## ✨ Features

- **⚡ Real-Time AI Vulnerability Detection:** Get instant security feedback as you type. Our integration with Groq's `llama3-70b-8192` model identifies complex vulnerabilities (XSS, SQLi, Command Injection) with extreme accuracy and speed.
- **🛡️ Interactive Exploit Sandbox:** Learn *why* your code is vulnerable. The built-in playground lets you simulate payloads locally and provides a visual, step-by-step breakdown of how the exploit functions.
- **✨ Automated 1-Click Patching:** Fix insecure code instantly. CodeShield provides secure, context-aware code replacements right in VS Code using AI-generated Quick Fixes and a sidebar "Apply Fix" button.
- **📊 Dynamic Security Dashboard:** A sleek, high-contrast UI highlighting your current file's security score, severity breakdowns (Critical, High, Medium, Low), and confidence metrics.
- **🔌 Auto-Healing Backend Integration:** The extension seamlessly manages the local FastAPI/Uvicorn backend, automatically starting the AI engine if it isn't running.

---

## 🛠️ Architecture

CodeShield operates on a robust, decoupled architecture for speed and privacy:
- **Frontend (VS Code Extension):** Written in TypeScript. Handles active file scanning, custom Webview UI components (Sidebar), Quick Fix Providers, and Diagnostics integration.
- **Backend (Python FastAPI):** Serves as an offline-first or local API using `uvicorn`. It orchestrates security validation logic, normalizes prompts, and integrates securely with Groq LLM APIs.

---

## ⚙️ Prerequisites

To develop or run CodeShield from source, you need:
- **Node.js 18+** & **npm**
- **Python 3.9+**
- **VS Code 1.85+**
- A [Groq API Key](https://console.groq.com/) for lightning-fast AI inference.

---

## 🚀 Installation & Setup

### 1. Backend Setup
The backend powers the actual analysis and connects to the Groq AI service.
```bash
cd backend
pip install -r requirements.txt

# Set your API Key
export GROQ_API_KEY="gsk_your_api_key_here"

# Start the API server
uvicorn app.main:app --reload --port 8000
```
> *(Alternative: Let the VS Code Extension auto-start the backend for you!)*

### 2. Frontend Extension (Developer Mode)
```bash
cd frontend
npm install

# Build the extension
npm run compile
```
- Open the project in VS Code and press **F5** to launch an Extension Development Host window.

### 3. Install from Package (.vsix)
If you have generated or downloaded the `.vsix` package:
```bash
# Example version
code --install-extension frontend/codeshield-ai-security-0.1.6.vsix
```

---

## 💻 Usage

1. **Activate:** Open any supported file (`.ts`, `.js`, `.py`, `.java`, `.go`, `.html`, etc.). CodeShield automatically starts analyzing.
2. **Review:** Check the VS Code Status Bar in the bottom right. It will display `CodeShield: SCANNING`, `CodeShield: RISK`, or `CodeShield: SAFE`. It also assigns inline error squiggles to problematic code.
3. **Analyze:** Open the **CodeShield** panel in the Activity Bar (Shield Icon) for an in-depth dashboard.
4. **Fix:** Hover over a squiggly line and click **Quick Fix**, or use the **Apply Fix** button in the sidebar panel.
5. **Simulate:** Click **Simulate Attack** on a vulnerability card in the sidebar to test payloads against the flawed code.

---

## 👥 Contributors

- **Adhiraj Patil** & **Anish Mahalaxme** (Code Shield Team)
- Originally developed through modular iterations (Backend, Frontend, AI Integration) and modernized into a singular cohesive AI tool.
