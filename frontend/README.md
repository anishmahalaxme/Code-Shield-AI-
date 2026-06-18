# 🛡️ CodeShield Security — AI-Powered Secure Coding Assistant

> **Real-time vulnerability detection, interactive exploit simulations, and 1-click automated patches directly in VS Code.**

CodeShield acts as your personal AppSec engineer. It scans active files for common vulnerabilities (SQL Injection, Cross-Site Scripting, Path Traversal, Command Injection, and Hardcoded Secrets), details *why* the code is insecure, runs safe mock exploits in a sandbox, and offers 1-click patches powered by high-speed cloud AI.

---

## ⚡ Core Features

*   **🔍 Out-of-the-Box Cloud Engine:** No complex setup required! The extension automatically connects to the hosted CodeShield Cloud API (`https://code-shield-ai.onrender.com`) for high-speed AST analysis and AI enrichment.
*   **🔌 Local Fallback Scanner:** Works offline! If you have no internet access, CodeShield's local fallback scanner runs inside VS Code to ensure you always get immediate security warnings.
*   **🧪 Interactive Exploit Sandbox:** Runs safe mock exploits inside a dedicated tab. Enter custom input payloads to see how an attacker could bypass authentication, exfiltrate data, or execute commands.
*   **🛠️ 1-Click Auto-Fixes:** Provides context-aware security patches. Hover over squiggled code issues and click **Quick Fix** to secure the line instantly.
*   **📊 Security Dashboard:** Opens a visual overview of your workspace showing your security health score, issue severities, and remediation advice.

---

## 💻 How to Use

1.  **Open Code:** Open any directory or file in VS Code. CodeShield automatically scans files on open and save.
2.  **Inspect Squiggles:** Hover over highlighted security issues to see inline warnings, explanations, and suggested remediations.
3.  **Apply Fixes:** Open the hover tooltip, select **Quick Fix**, and click **⚡ Auto-Fix Code** to rewrite the line securely.
4.  **Simulate Exploits:** Click the **CodeShield icon** in the Activity Bar to open the dashboard. Under any vulnerability card, click **Run simulation** to explore attack flows inside the sandbox.

---

## ⚙️ Supported Languages
*   **JavaScript & TypeScript** (`.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`)
*   **Python** (`.py`, `.pyw`, `.pyi`)

---

## 🔒 Privacy & Safety
All static code analysis is performed securely. Code is scanned strictly to identify AST patterns and trace data flows. 

*For the complete open-source code, local deployment instructions, or to contribute to the engine, please visit the [CodeShield AI GitHub Repository](https://github.com/anishmahalaxme/Code-Shield-AI-).*
