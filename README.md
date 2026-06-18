# 🛡️ CodeShield AI — Secure Coding Assistant

[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com)
[![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?style=for-the-badge&logo=typescript)](https://www.typescriptlang.org)
[![Groq AI](https://img.shields.io/badge/Groq%20AI-F59E0B?style=for-the-badge)](https://console.groq.com)
[![VS Code Extension](https://img.shields.io/badge/VS%20Code-Extension-blue?style=for-the-badge&logo=visual-studio-code)](https://code.visualstudio.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

CodeShield AI acts as your local, autonomous Application Security (AppSec) engineer. It scans active files in VS Code for common vulnerabilities, visually explains why code is insecure, runs safe mock exploits in an interactive sandbox, and generates 1-click patches powered by Groq's high-speed Llama 3.3 (70B) AI model.

---

## 📖 Table of Contents
1. [System Architecture](#-system-architecture)
2. [How It Works (Under the Hood)](#-how-it-works-under-the-hood)
3. [Supported Vulnerability Classes](#-supported-vulnerability-classes)
4. [Folder Structure](#-folder-structure)
5. [Getting Started (Local Installation)](#-getting-started-local-installation)
    * [Step 1: Install Python Backend](#step-1-install-python-backend)
    * [Step 2: Configure Environment Variable](#step-2-configure-environment-variable)
    * [Step 3: Run FastAPI Server](#step-3-run-fastapi-server)
    * [Step 4: Load Extension in VS Code](#step-4-load-extension-in-vs-code)
6. [Production Deployment (Render)](#-production-deployment-render)
7. [Usage Guide](#-usage-guide)
8. [API Contract Specifications](#-api-contract-specifications)
9. [Troubleshooting & FAQs](#-troubleshooting--faqs)

---

## 🗺️ System Architecture

CodeShield is split into an editor client and an analysis engine. This keeps code editing responsive and lets you run resource-intensive static analysis and LLM calls in a separate service.

```mermaid
graph TD
    A[VS Code Editor] <-->|JSON over HTTP| B[FastAPI Engine (Port 8000)]
    A <-->|Local Fallback Scanner| C[Regex Scanner (runs locally)]
    B <-->|AST Detection & Taint Tracking| D[Rules Scanner]
    B <-->|AI Enrichment & Fix generation| E[Groq API (Llama 3.3 70B)]
```

*   **Frontend (VS Code Extension):** Manages code highlighting, status diagnostics, registers hover providers, displays quick-fix code actions, and renders webviews.
*   **Backend (FastAPI Engine):** Performs Abstract Syntax Tree (AST) parsing, traces variable taints, compiles attack execution simulations, and communicates with Groq.

---

## ⚙️ How It Works (Under the Hood)

### 1. AST-Based Static Analysis & Taint Tracking
When you save a file, CodeShield's backend translates your source code into an Abstract Syntax Tree (AST). The parser tracks variables from their definitions (**Sources**, such as `input()`, `getQueryParams()`, or `req.query`) to execution blocks (**Sinks**, such as `execute()`, `exec()`, or `innerHTML`). If user-controlled data reaches a sink without passing through a sanitization function, CodeShield triggers a vulnerability diagnostic.

### 2. The Offline Fallback Loop
If the backend is not running, CodeShield will automatically switch to **Local Scan** mode. The extension relies on local regex-based pattern matching (e.g., checking for string concatenation in SQL strings or direct DOM manipulation) to alert you of potential risks, ensuring your coding flow remains protected even offline.

### 3. AI-Remediation and Exploit Sandboxing
For every detected issue, the API requests Groq's high-speed model to:
*   Write a natural language description explaining why that specific block is vulnerable.
*   Generate a clean, secure drop-in replacement snippet.
*   Simulate an interactive terminal executing a safe exploit payload to show real-world impact.

---

## 🛡️ Supported Vulnerability Classes

CodeShield covers five critical vulnerability classes:

### 1. SQL Injection (`SQL_INJECTION`)
*   **The Risk:** Unsanitized user inputs are concatenated directly into database queries, allowing attackers to read, manipulate, or delete tables.
*   **Vulnerable Code Example:**
    ```python
    query = "SELECT * FROM users WHERE username = '" + username_input + "'"
    cursor.execute(query)
    ```
*   **Remediated Code Example:**
    ```python
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username_input,))
    ```

### 2. Command Injection (`COMMAND_INJECTION`)
*   **The Risk:** Passing user input strings directly into system shell calls lets attackers execute arbitrary terminal commands.
*   **Vulnerable Code Example:**
    ```javascript
    const { exec } = require('child_process');
    exec("ping -c 3 " + ipAddress);
    ```
*   **Remediated Code Example:**
    ```javascript
    const { execFile } = require('child_process');
    execFile("/bin/ping", ["-c", "3", ipAddress]);
    ```

### 3. Cross-Site Scripting (`XSS`)
*   **The Risk:** Rendering raw user input inside HTML elements lets attackers execute malicious scripts in client browsers.
*   **Vulnerable Code Example:**
    ```javascript
    element.innerHTML = "<p>Welcome, " + username + "</p>";
    ```
*   **Remediated Code Example:**
    ```javascript
    element.textContent = "Welcome, " + username;
    ```

### 4. Path Traversal (`PATH_TRAVERSAL`)
*   **The Risk:** Using unvalidated paths with directory separators (`../`) allows attackers to escape directory roots and read arbitrary system files.
*   **Vulnerable Code Example:**
    ```python
    file_path = os.path.join(BASE_DIR, request.args.get("file"))
    open(file_path, 'r')
    ```
*   **Remediated Code Example:**
    ```python
    safe_filename = os.path.basename(request.args.get("file"))
    file_path = os.path.join(BASE_DIR, safe_filename)
    open(file_path, 'r')
    ```

### 5. Hardcoded Secrets (`HARDCODED_SECRET`)
*   **The Risk:** Committing sensitive api keys, tokens, or private passwords inside code deposits them in git history, making them visible to anyone with repository access.
*   **Vulnerable Code Example:**
    ```javascript
    const api_key = "AKIAIOSFODNN7EXAMPLE";
    ```
*   **Remediated Code Example:**
    ```javascript
    const api_key = process.env.API_KEY;
    ```

---

## 📁 Folder Structure

```
CodeShield AI/
├── backend/                   # FastAPI Backend Source
│   ├── app/
│   │   ├── detectors/         # AST & Taint detectors (SQLi, XSS, Path Traversal, etc.)
│   │   ├── models/            # Pydantic schemas and API contracts
│   │   ├── routes/            # REST API endpoints (/analyze, /fix, /simulate)
│   │   └── services/          # Groq LLM integration and simulation orchestrators
│   ├── .env.example           # Template environment config
│   ├── requirements.txt       # Backend dependencies
│   └── start.sh               # Bash script to run backend
├── docs/                      # General API Documentation
└── frontend/                  # VS Code Extension Source
    ├── codeshield-ai-security-0.1.7.vsix # Compiled extension installer
    ├── src/                   # Extension entry point, providers, and clients
    └── webview-ui/            # Webview sidebar dashboard (React + TS + Vite)
```

---

## 🚀 Getting Started (Local Installation)

Follow these steps to run the complete CodeShield engine locally.

### Step 1: Install Python Backend
Ensure Python 3.9+ is installed. Run the following in the `backend/` directory:

#### On Windows (PowerShell):
```powershell
# Create Virtual Environment
python -m venv .venv
# Activate Environment
.venv\Scripts\Activate.ps1
# Install Requirements
pip install -r requirements.txt
```

#### On MacOS / Linux (Bash):
```bash
# Create Virtual Environment
python -m venv .venv
# Activate Environment
source .venv/bin/activate
# Install Requirements
pip install -r requirements.txt
```

### Step 2: Configure Environment Variable
1. Get a free API Key from the [Groq Console](https://console.groq.com/).
2. Copy `backend/.env.example` to `backend/.env`.
3. Add your key inside the `.env` file:
```env
GROQ_API_KEY=gsk_your_api_key_here
```

### Step 3: Run FastAPI Server
Start the backend server on port `8000`:
```bash
# Verify virtual environment is active, then run:
python -m uvicorn app.main:app --port 8000
```
*   The API server will listen on `http://127.0.0.1:8000`. Keep this terminal running!

### Step 4: Load Extension in VS Code
You can install the pre-compiled Extension package directly:
1. Open VS Code.
2. Open the command palette (`Ctrl+Shift+P` on Windows/Linux or `Cmd+Shift+P` on macOS).
3. Select **Extensions: Install from VSIX...**.
4. Browse to the repository folder: `frontend/codeshield-ai-security-0.1.7.vsix` and select it.
5. Click **Install**. Alternatively, run this command in your terminal:
```bash
code --install-extension frontend/codeshield-ai-security-0.1.7.vsix
```

---

## 🌐 Production Deployment (Render)

Instead of requiring users to run the backend engine locally, you can deploy the FastAPI service for free on **Render** to run permanently:

1. Push your repository changes to your **GitHub** account.
2. Log in to the [Render Dashboard](https://render.com/).
3. Click **New +** and select **Web Service**.
4. Connect the GitHub repository containing CodeShield AI.
5. Configure the build and start commands as follows:
   * **Name:** `codeshield-backend` (or a name of your choice)
   * **Runtime:** `Python`
   * **Build Command:** `pip install -r backend/requirements.txt`
   * **Start Command:** `cd backend && uvicorn app.main:app --host 0.0.0.0 --port 10000`
6. Add the following environment variable in the **Advanced** section:
   * **Key:** `GROQ_API_KEY`
   * **Value:** `gsk_your_actual_groq_api_key_here`
7. Click **Create Web Service**. Your API will build and deploy to a public URL (e.g., `https://codeshield-backend.onrender.com`).

> **Note:** Once deployed, make sure to update the default `codeshield.backendUrl` inside `frontend/package.json` with your new public URL so extension users connect to it automatically.

---

## 💻 Usage Guide

1. **Scan on Save:** Open any supported codebase in VS Code. Simply edit and save a file to automatically trigger a security scan.
2. **Review Status:** Look at the status bar at the bottom right:
    *   `CodeShield: SAFE` ✅ — Code has no obvious issues.
    *   `CodeShield: RISK` 🛑 — Vulnerability detected.
    *   `CodeShield: LOCAL SCAN` ⚠️ — Backend offline, running local patterns.
3. **Hover Explanations:** Hover over squiggled code elements to see a concise explanation of the security risk.
4. **Apply Fixes:** Open the hover tooltip, select **Quick Fix**, and click **⚡ Auto-Fix Code** to rewrite the line securely.
5. **Simulate Attack:** Click the CodeShield icon in the activity bar, open the sidebar list, click **Run simulation** on an issue to experiment with input payloads in the Sandbox panel.

---

## 🔌 API Contract Specifications

The extension communicates with the backend via the following HTTP endpoints:

### 1. `POST /analyze`
Scans a code block and returns enriched vulnerability diagnostics.
*   **Request Format:**
    ```json
    {
      "language": "python",
      "filename": "app.py",
      "code": "query = 'SELECT * FROM users WHERE id=' + user_input"
    }
    ```
*   **Response Format:**
    ```json
    {
      "score": 70,
      "issues": [
        {
          "id": "unique-uuid",
          "type": "SQL_INJECTION",
          "line": 1,
          "severity": "HIGH",
          "message": "SQL string concatenated with a variable",
          "code_snippet": "query = 'SELECT * FROM users WHERE id=' + user_input",
          "simulation": {
            "payload": "' OR '1'='1' --",
            "result": "SELECT * FROM users WHERE id='' OR '1'='1' --",
            "impact": "Authentication bypass, data leak."
          },
          "ai": {
            "explanation": "Concatenation of user-supplied variables enables SQL query modification...",
            "fix": "Use prepared queries like: execute('SELECT * FROM users WHERE id=?', (val,))"
          }
        }
      ]
    }
    ```

### 2. `POST /fix`
Generates an AI-suggested secure replacement block for a snippet.
*   **Request Format:**
    ```json
    {
      "language": "javascript",
      "issue_type": "XSS",
      "code_snippet": "element.innerHTML = 'Hello ' + name",
      "message": "User input rendering raw HTML"
    }
    ```
*   **Response Format:**
    ```json
    {
      "fixed_code": "element.textContent = 'Hello ' + name"
    }
    ```

### 3. `POST /simulate`
Evaluates the risk of a specific payload in the sandbox container.
*   **Request Format:**
    ```json
    {
      "language": "python",
      "vuln_type": "SQL_INJECTION",
      "code_snippet": "query = 'SELECT * FROM users WHERE id=' + user_input",
      "payload": "' OR '1'='1"
    }
    ```
*   **Response Format:**
    ```json
    {
      "query": "SELECT * FROM users WHERE id='' OR '1'='1'",
      "attack_result": "| id | username |\n| 1 | admin |",
      "attack_class": "SQL Injection",
      "impact": "Bypasses lookup parameters returning all database rows.",
      "is_attack": true
    }
    ```

---

## ❓ Troubleshooting & FAQs

### Q: Why does the status bar show `CodeShield: NO API`?
The VS Code extension cannot connect to the Python server at `http://127.0.0.1:8000`. Ensure that you ran `python -m uvicorn app.main:app --port 8000` in your terminal and that the server is still running.

### Q: Why does the backend show `GROQ_API_KEY not set — AI disabled`?
The API key is missing or the `.env` file is not located in the `backend/` root folder. Verify that `backend/.env` exists and contains `GROQ_API_KEY=gsk_...`.

### Q: How do I test that the connection works?
In VS Code, run the command **"CodeShield: Test API Connection"** from the Command Palette. You should see a success notification: `"CodeShield: API OK at http://127.0.0.1:8000"`.

---
*Developed with ❤️ as part of the CodeShield AppSec Suite.*
