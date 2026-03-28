import * as vscode from 'vscode';
import { Issue, AnalyzeResponse } from './apiClient';
import { SimulationPanel } from './simulationPanel';

export class CodeShieldSidebarProvider implements vscode.WebviewViewProvider {
    public static readonly viewType = 'codeshield.sidebar';
    private _view?: vscode.WebviewView;
    private currentScore: number = 100;
    private currentIssues: Issue[] = [];

    constructor(private readonly _extensionUri: vscode.Uri) { }

    public resolveWebviewView(
        webviewView: vscode.WebviewView,
        _context: vscode.WebviewViewResolveContext,
        _token: vscode.CancellationToken
    ) {
        this._view = webviewView;
        webviewView.webview.options = { enableScripts: true, localResourceRoots: [this._extensionUri] };
        webviewView.webview.onDidReceiveMessage((data) => {
            if (data.type === 'navigateToLine') {
                const editor = vscode.window.activeTextEditor;
                if (editor) {
                    const line = Math.max(0, data.value - 1);
                    const pos = new vscode.Position(line, 0);
                    editor.selection = new vscode.Selection(pos, pos);
                    editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
                }
            } else if (data.type === 'openSimulation') {
                const idx = data.value;
                if (this.currentIssues[idx]) {
                    SimulationPanel.createOrShow(this._extensionUri, this.currentIssues[idx]);
                }
            } else if (data.type === 'applyFix') {
                const idx = data.value;
                const issue = this.currentIssues[idx];
                const editor = vscode.window.activeTextEditor;
                if (editor && issue) {
                    const line = Math.max(0, issue.line - 1);
                    const range = editor.document.lineAt(line).range;
                    vscode.commands.executeCommand('codeshield.applyFix', editor.document, range, issue);
                } else {
                    vscode.window.showErrorMessage('Please open the file associated with this vulnerability first.');
                }
            }
        });
        this.updateView();
    }

    public updateData(response: AnalyzeResponse) {
        this.currentScore = response.score;
        this.currentIssues = response.issues;
        this.updateView();
    }

    private updateView() {
        if (this._view) {
            this._view.webview.html = this.getHtmlForWebview(this.currentScore, this.currentIssues);
        }
    }

    private esc(s: string): string {
        return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    private toBullets(text: string): string {
        const sents = text.split(/(?<=\.)\s+/).filter(s => s.trim());
        if (sents.length <= 1) { return sents[0] || text; }
        return '<ul style="padding-left:14px;margin:2px 0">' +
            sents.map(s => `<li>${s.trim()}</li>`).join('') + '</ul>';
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

    private getNonce() {
        let text = '';
        const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        for (let i = 0; i < 32; i++) { text += possible.charAt(Math.floor(Math.random() * possible.length)); }
        return text;
    }

    private renderSimBlock(title: string, icon: string, text: string, bg: string, border: string, color: string): string {
        if (!text) return '';
        return `
        <div class="sim-node">
          <div class="sim-dot"></div>
          <div class="sim-title">${icon} ${title}</div>
          <div class="sim-box" style="background:${bg}; border: 1px solid ${border}; color:${color};">${this.esc(text)}</div>
        </div>
        `;
    }

    private getHtmlForWebview(score: number, issues: Issue[]): string {
        const nonce = this.getNonce();

        // Native Semantic mapping
        const sevMap: Record<string, { icon: string; color: string }> = {
            critical: { icon: '🛑', color: '#f43f5e' },
            high: { icon: '⚠️', color: '#f43f5e' },
            medium: { icon: 'ℹ️', color: '#f59e0b' },
            low: { icon: '✅', color: '#22c55e' }
        };

        const scC = score >= 80 ? 'var(--vscode-testing-iconPassed)' : score >= 50 ? '#f59e0b' : '#f43f5e';

        const cardsHtml = issues.map((issue, i) => {
            const sev = sevMap[issue.severity.toLowerCase()] || sevMap.medium;

            return `
<div class="issue-wrap" style="margin-bottom: 24px;">
  <!-- Issue Details Box -->
  <div class="icard" style="margin-bottom: 8px;">
    <div class="ihdr" data-action="nav" data-line="${issue.line}">
      <div class="ihdr-flex">
        <div class="ihdr-icon">${sev.icon}</div>
        <div style="flex:1;">
          <div class="ihdr-title" style="color:${sev.color}">${this.esc(issue.type)}</div>
          <div class="ihdr-sub">Line ${issue.line}</div>
        </div>
        <div class="ihdr-badge" style="background:${sev.color};color:#FFF;">${issue.severity}</div>
      </div>
    </div>
    <div class="ibody">
      <div class="iss-msg">${this.esc(issue.message)}</div>

      <div class="idetails" id="det-${i}">
        ${issue.ai?.explanation ? `<div class="kv-k">Explanation</div><div class="kv-v">${this.toBullets(issue.ai.explanation)}</div>` : ''}
        ${issue.ai?.fix ? `<div class="kv-k" style="margin-top:10px">Recommended Fix</div><pre class="cblk">${this.esc(issue.ai.fix)}</pre>` : ''}
      </div>
      
      <button class="btn-ghost" data-action="tog" data-idx="${i}">Open details <span class="ico">▼</span></button>
    </div>
  </div>

  <!-- Simulation Timeline Box -->
  <div class="icard" style="margin-bottom: 8px; padding: 12px 20px;">
    <div class="sim-view">
      <button class="btn-ghost" style="color:#3b82f6; justify-content:flex-start; padding: 0; border:none; width:auto; text-transform:none;" data-action="togglesim" data-idx="${i}">
        <span class="sim-ico" id="simico-${i}" style="font-size:12px; margin-right:4px;">▶</span>
        <span id="simtext-${i}" style="font-size: 16px; font-weight: 700;">Show Simulation</span>
      </button>
      <div class="sim-timeline" id="sim-${i}" style="display:none; margin-top: 16px;">
        ${issue.simulation ? `
          ${this.renderSimBlock('INPUT', '🕹️', issue.simulation.payload, '#1e1e1e', '#333333', '#d4d4d4')}
          ${this.renderSimBlock('CODE', '⬇️', issue.code_snippet, '#0f172a', '#1e3a8a', '#93c5fd')}
          ${this.renderSimBlock('RESULT', '⬇️', issue.simulation.result, '#2e1403', '#713f12', '#fef08a')}
          ${this.renderSimBlock('IMPACT', '💥', issue.simulation.impact, '#2a0505', '#7f1d1d', '#fca5a5')}
        ` : `<div style="font-size:13px;color:var(--vscode-descriptionForeground);padding-top:8px;">No simulation data available on backend.</div>`}
      </div>
    </div>
  </div>

  <!-- Action Buttons Box -->
  <div class="icard" style="margin-bottom: 0; padding: 16px 20px;">
    <div class="btn-row" style="margin-top: 0;">
      <button class="btn-primary" style="background:${sev.color};color:#FFF;" data-action="autofix" data-idx="${i}">Auto-Fix Code</button>
      <button class="btn-secondary" style="background:#0F4C81;color:#FFF;border:none;" data-action="opensb" data-idx="${i}">Run simulation</button>
    </div>
  </div>
</div>`;
        }).join('');

        const pgData = issues.map(iss => ({
            type: iss.type || '',
            payload: iss.simulation?.payload || this.defaultPayload(iss.type),
            sim: iss.simulation?.result || '',
            impact: iss.simulation?.impact || ''
        }));
        const pgJson = JSON.stringify(pgData).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026');

        return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<style>
/* ─── VS Code Native + Modern Tokens ─── */
:root {
  --cs-radius: 12px;
  --cs-pill: 99px;
  --cs-trans: all 0.2s cubic-bezier(0.2, 0.8, 0.2, 1);
}
*{box-sizing:border-box;margin:0;padding:0}
body {
  font-family: var(--vscode-font-family, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif);
  padding: 16px;
  background: var(--vscode-editor-background);
  color: #ffffff;
  font-size: 15px;
  line-height: 1.5;
}

/* ─── Score Card ─── */
.score-card {
  background: var(--vscode-editorWidget-background);
  border: 1px solid var(--vscode-widget-border, rgba(128,128,128,0.2));
  border-radius: var(--cs-radius);
  padding: 20px;
  margin-bottom: 24px;
  display: flex; align-items: center; gap: 16px;
  box-shadow: 0 4px 12px var(--vscode-widget-shadow, rgba(0,0,0,0.1));
}
.score-circle-wrap { position: relative; width: 64px; height: 64px; flex-shrink: 0; }
.score-circle-bg { fill: none; stroke: var(--vscode-editorGroup-border, rgba(128,128,128,0.2)); stroke-width: 5; }
.score-circle-fg { fill: none; stroke-width: 5; stroke-linecap: round; transition: stroke-dashoffset 1.2s cubic-bezier(0.22, 1, 0.36, 1); transform: rotate(-90deg); transform-origin: 50% 50%; }
.score-text { position: absolute; inset:0; display:flex; align-items:center; justify-content:center; font-size: 20px; font-weight: 800; }
.score-info { flex:1; display:flex; flex-direction:column; justify-content:center; }
.score-title { font-size: 16px; font-weight: 700; margin-bottom: 2px; }
.score-sub { font-size: 14px; color: var(--vscode-descriptionForeground, #9ca3af); }

/* ─── Issue Cards ─── */
.icard {
  background: var(--vscode-editorWidget-background);
  border: 1px solid var(--vscode-widget-border, rgba(128,128,128,0.2));
  border-radius: var(--cs-radius);
  margin-bottom: 16px;
  transition: var(--cs-trans);
}
.icard:hover {
  border-color: var(--vscode-focusBorder, rgba(0,122,204,0.5));
  transform: translateY(-1px);
  box-shadow: 0 4px 12px var(--vscode-widget-shadow, rgba(0,0,0,0.1));
}
.ihdr { padding: 16px 20px 12px; cursor: pointer; }
.ihdr-flex { display: flex; align-items: flex-start; gap: 12px; }
.ihdr-icon { font-size: 18px; flex-shrink: 0; margin-top: 2px; }
.ihdr-title { font-size: 16px; font-weight: 600; margin-bottom: 2px; word-break:break-word; color: #ffffff; }
.ihdr-sub { font-size: 13px; color: var(--vscode-descriptionForeground); font-weight: 600; text-transform: uppercase; }
.ihdr-badge {
  display: inline-block; padding: 4px 10px; border-radius: var(--cs-pill);
  font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 2px;
}
.ibody { padding: 0 20px 16px; }
.iss-msg { font-size: 14px; line-height: 1.5; color: #ffffff; word-break:break-word; font-weight: 500;}

/* ─── Details Body ─── */
.idetails { max-height: 0; overflow: hidden; transition: max-height 0.4s ease; }
.idetails.open { max-height: 5000px; margin-top: 16px; padding-top: 16px; border-top: 1px solid var(--vscode-widget-border, rgba(128,128,128,0.2)); }
.kv-k { font-size: 12px; font-weight: 700; color: var(--vscode-descriptionForeground); text-transform: uppercase; margin-bottom: 6px; }
.kv-v { font-size: 14px; font-weight: 500; }
.cblk { 
  background: var(--vscode-textCodeBlock-background, rgba(0,0,0,0.05)); border: 1px solid var(--vscode-widget-border, rgba(128,128,128,0.2));
  padding: 12px; border-radius: 8px; font-family: var(--vscode-editor-font-family, monospace); font-size: 13px; white-space: pre-wrap; word-break: break-all; margin-top: 4px; overflow-x: auto;
}

/* ─── Timeline ─── */
.sim-timeline {
  position: relative; margin-top: 12px; padding-left: 16px;
  border-left: 2px solid #3b82f6;
}
.sim-node { position: relative; margin-bottom: 16px; }
.sim-node:last-child { margin-bottom: 0; }
.sim-dot {
  position: absolute; left: -22px; top: 4px; width: 10px; height: 10px;
  border-radius: 50%; background: var(--vscode-editor-background); border: 2px solid #64748b;
}
.sim-title { font-size: 12px; font-weight: 800; text-transform: uppercase; color: #ffffff; display: flex; align-items: center; gap: 6px; margin-bottom: 6px; padding-left: 2px; }
.sim-ico { font-size: 10px; }
.sim-box {
  border-radius: 6px; padding: 10px 12px; font-family: var(--vscode-editor-font-family, monospace); font-size: 13px; white-space: pre-wrap; word-break: break-all; line-height: 1.5;
}

/* ─── Buttons ─── */
.btn-row { display: flex; gap: 12px; margin-top: 20px; }
.btn-primary {
  flex: 1; padding: 10px; border-radius: var(--cs-pill); border: none;
  font-size: 12px; font-weight: 600; cursor: pointer; text-align: center;
  transition: var(--cs-trans); font-family: inherit;
}
.btn-primary:hover { filter: brightness(0.9); transform: translateY(-1px); }
.btn-secondary {
  flex: 1; padding: 10px; border-radius: var(--cs-pill);
  font-size: 12px; font-weight: 600; cursor: pointer; text-align: center;
  transition: var(--cs-trans); font-family: inherit;
}
.btn-secondary:hover { filter: brightness(0.9); transform: translateY(-1px); }

.btn-ghost {
  display: flex; align-items: center; justify-content: center; gap: 8px;
  width: 100%; text-align: center; padding: 12px; margin-top: 16px;
  font-size: 12px; font-weight: 700; cursor: pointer;
  background: transparent; color: var(--vscode-descriptionForeground, #9ca3af); border: none; font-family: inherit;
  transition: var(--cs-trans); border-top: 1px dashed var(--vscode-widget-border, rgba(128,128,128,0.2));
}
.btn-ghost:hover { color: var(--vscode-foreground); }

/* ─── Safe State ─── */
.safe-state { 
  background: var(--vscode-editorWidget-background); border: 1px solid var(--vscode-widget-border, rgba(128,128,128,0.2));
  border-radius: var(--cs-radius); padding: 40px 20px; text-align: center; 
}
.safe-icon { font-size: 40px; margin-bottom: 16px; }
.safe-title { font-size: 18px; font-weight: 700; color: #ffffff; margin-bottom: 8px; }
.safe-sub { font-size: 14px; color: var(--vscode-descriptionForeground); line-height: 1.5; font-weight: 500; }
</style>
</head>
<body>

<div class="score-card">
  <div class="score-circle-wrap">
    <svg width="64" height="64" viewBox="0 0 52 52">
      <circle class="score-circle-bg" cx="26" cy="26" r="23"></circle>
      <!-- Circumference = 144.5 -->
      <circle class="score-circle-fg" id="scoreCircle" cx="26" cy="26" r="23" stroke="${scC}" stroke-dasharray="144.5" stroke-dashoffset="144.5"></circle>
    </svg>
    <div class="score-text" style="color:${scC}">${score}</div>
  </div>
  <div class="score-info">
    <div class="score-title">Security Confidence</div>
    <div class="score-sub">${issues.length} ${issues.length === 1 ? 'vulnerability' : 'vulnerabilities'} detected</div>
  </div>
</div>

<div id="list">
${issues.length ? cardsHtml : `
<div class="safe-state">
  <div class="safe-icon">✅</div>
  <div class="safe-title">All Systems Secure</div>
  <div class="safe-sub">Your code is currently free of analyzed vulnerabilities.</div>
</div>`}
</div>

<script nonce="${nonce}">
var vsc = acquireVsCodeApi();
var pg  = ${pgJson};

requestAnimationFrame(function() {
  setTimeout(function() {
    var circle = document.getElementById('scoreCircle');
    if (circle) {
      var offset = 144.5 - (144.5 * ${score} / 100);
      circle.style.strokeDashoffset = offset;
    }
  }, 100);
});

document.addEventListener('click', function(e) {
  var el = e.target;
  var actionEl = el.closest ? el.closest('[data-action]') : el;
  if (!actionEl) {
    while (el && el !== document.body && !el.getAttribute('data-action')) { el = el.parentElement; }
    actionEl = el;
  }
  if (actionEl && actionEl !== document.body) {
    var action = actionEl.getAttribute('data-action');
    if (action) {
      var idx = parseInt(actionEl.getAttribute('data-idx') || '-1', 10);
      if (action === 'nav')     { vsc.postMessage({ type: 'navigateToLine', value: parseInt(actionEl.getAttribute('data-line'), 10) }); return; }
      if (action === 'togglesim') { 
        e.stopPropagation();
        var simDiv = document.getElementById('sim-' + idx);
        var simIco = document.getElementById('simico-' + idx);
        var simTxt = document.getElementById('simtext-' + idx);
        if (simDiv && simIco && simTxt) {
          if (simDiv.style.display === 'none') {
            simDiv.style.display = 'block';
            simIco.textContent = '▼';
            simTxt.textContent = 'Hide Simulation';
          } else {
            simDiv.style.display = 'none';
            simIco.textContent = '▶';
            simTxt.textContent = 'Show Simulation';
          }
        }
        return; 
      }
      if (action === 'tog')     { toggleSim(idx); return; }
      if (action === 'opensb')  { e.stopPropagation(); vsc.postMessage({ type: 'openSimulation', value: idx }); return; }
      if (action === 'autofix') { e.stopPropagation(); vsc.postMessage({ type: 'applyFix', value: idx }); return; }
    }
  }
});

function toggleSim(i) {
  var body = document.getElementById('det-' + i);
  if (!body) { return; }
  var open = body.classList.toggle('open');
  var btns = document.querySelectorAll('[data-action="tog"][data-idx="' + i + '"]');
  btns.forEach(function(b) {
    b.innerHTML = open ? 'Close details <span class="ico">▲</span>' : 'Open details <span class="ico">▼</span>';
  });
}
</script>
</body>
</html>`;
    }
}
