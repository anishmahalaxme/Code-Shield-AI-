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
        if (sents.length <= 1) { return `<p style="font-size:12px;line-height:1.5">${text}</p>`; }
        return '<ul style="padding-left:16px;margin:2px 0">' + sents.map(s => `<li style="font-size:12px;margin-bottom:2px">${s.trim()}</li>`).join('') + '</ul>';
    }

    private buildStepFlow(issue: Issue): string {
        const items: string[] = [];
        if (issue.simulation?.payload) { items.push(this.stepItem('📥 Input', issue.simulation.payload, 'si')); }
        if (issue.simulation?.result) { items.push(this.stepItem('⬇️ Code', issue.simulation.result, 'sc')); }
        if (issue.ai?.explanation) { items.push(this.stepItem('⬇️ Result', issue.ai.explanation.split('.')[0] + '.', 'sr')); }
        if (issue.simulation?.impact) { items.push(this.stepItem('💥 Impact', issue.simulation.impact, 'sx')); }
        if (!items.length) { return '<p style="font-size:12px;opacity:.6">No simulation data.</p>'; }
        return `<div style="position:relative;padding-left:18px">${items.join('')}</div>`;
    }

    private stepItem(label: string, content: string, cls: string): string {
        const colors: Record<string, string> = {
            si: 'rgba(150,150,150,.1)',
            sc: 'rgba(24,144,255,.1)',
            sr: 'rgba(250,219,20,.1)',
            sx: 'rgba(255,77,79,.1)'
        };
        const borders: Record<string, string> = {
            si: 'rgba(150,150,150,.25)',
            sc: 'rgba(24,144,255,.25)',
            sr: 'rgba(250,219,20,.25)',
            sx: 'rgba(255,77,79,.25)'
        };
        return `<div style="position:relative;margin-bottom:10px">
            <div style="position:absolute;left:-15px;top:6px;width:10px;height:10px;border-radius:50%;border:2px solid var(--vscode-panel-border);background:var(--vscode-sideBar-background)"></div>
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px">${label}</div>
            <div style="border-radius:5px;padding:8px 10px;font-family:monospace;font-size:11px;white-space:pre-wrap;word-break:break-all;line-height:1.4;background:${colors[cls]};border:1px solid ${borders[cls]}">${this.esc(content)}</div>
        </div>`;
    }

    private defaultPayload(type: string): string {
        const t = (type || '').toLowerCase();
        if (t.includes('sql')) { return "' UNION SELECT id, username, password FROM users --"; }
        if (t.includes('xss') || t.includes('cross') || t.includes('script')) { return '<svg/onload=alert(1)>'; }
        if (t.includes('command') || t.includes('exec')) { return '127.0.0.1; whoami'; }
        if (t.includes('path') || t.includes('traversal') || t.includes('lfi')) { return '../../../etc/passwd%00'; }
        if (t.includes('secret') || t.includes('hardcoded') || t.includes('key') || t.includes('credential')) { return 'AKIAIOSFODNN7EXAMPLE'; }
        if (t.includes('random') || t.includes('crypto') || t.includes('weak')) { return '0.7381'; }
        return 'malicious_input';
    }


    private getNonce() {
        let text = '';
        const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        for (let i = 0; i < 32; i++) {
            text += possible.charAt(Math.floor(Math.random() * possible.length));
        }
        return text;
    }

    private getHtmlForWebview(score: number, issues: Issue[]): string {
        const nonce = this.getNonce();
        const sevC: Record<string, { c: string; bg: string }> = {
            critical: { c: '#ff4d4f', bg: 'rgba(255,77,79,0.12)' },
            high: { c: '#fa8c16', bg: 'rgba(250,140,22,0.12)' },
            medium: { c: '#fadb14', bg: 'rgba(250,219,20,0.12)' },
            low: { c: '#1890ff', bg: 'rgba(24,144,255,0.12)' }
        };
        const scC = score >= 80 ? '#52c41a' : score >= 50 ? '#fadb14' : '#ff4d4f';

        // Build cards — inline sandbox per card
        const cardsHtml = issues.map((issue, i) => {
            const sev = sevC[issue.severity.toLowerCase()] || sevC.medium;
            return `
<div class="icard" style="border-left:4px solid ${sev.c}; box-shadow: 0 0 0 1px ${sev.bg}, 0 0 12px ${sev.bg};">
  <div class="icard-hdr" data-action="nav" data-line="${issue.line}">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
      <span style="font-size:10px;font-weight:700;padding:2px 7px;border-radius:10px;letter-spacing:.5px;background:${sev.bg};color:${sev.c}">${issue.severity.toUpperCase()}</span>
      <span style="font-size:13px;font-weight:600">${this.esc(issue.type)}</span>
    </div>
    <div style="font-size:11px;color:var(--vscode-descriptionForeground)">Line ${issue.line} · ${this.esc(issue.message)}</div>
  </div>
  ${issue.ai?.explanation ? `<div class="isec"><div class="slbl">Explanation</div>${this.toBullets(issue.ai.explanation)}</div>` : ''}
  ${issue.ai?.fix ? `<div class="isec"><div class="slbl">🔧 Suggested Fix</div><pre class="cblk">${this.esc(issue.ai.fix)}</pre></div>` : ''}
  <div class="itog" data-action="tog" data-idx="${i}"><span class="itog-arrow">▶</span> <span class="itog-lbl">Show Simulation</span></div>
  <div class="ibody" id="ib-${i}">
    ${this.buildStepFlow(issue)}
    <button class="osbtn" style="background:linear-gradient(135deg,#52c41a,#389e0d);margin-top:10px;margin-bottom:8px" data-action="autofix" data-idx="${i}">⚡ Auto-Fix Code</button>
    <button class="osbtn" data-action="opensb" data-idx="${i}">🔌 Run Interactive Simulation ▶</button>

  </div>
</div>`;
        }).join('');

        // Playground data — safely serialized
        const pgData = issues.map(iss => ({
            type: iss.type || '',
            payload: iss.simulation?.payload || this.defaultPayload(iss.type),
            sim: iss.simulation?.result || '',
            impact: iss.simulation?.impact || ''
        }));
        const pgJson = JSON.stringify(pgData)
            .replace(/</g, '\\u003c')
            .replace(/>/g, '\\u003e')
            .replace(/&/g, '\\u0026');

        return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--vscode-font-family);padding:12px;color:var(--vscode-foreground);background:var(--vscode-sideBar-background)}
.icard{background:var(--vscode-editor-background);border-radius:6px;margin-bottom:12px;box-shadow:0 1px 4px rgba(0,0,0,.18);overflow:hidden;border:1px solid var(--vscode-panel-border)}
.icard-hdr{padding:10px 12px;cursor:pointer}
.icard-hdr:hover{background:var(--vscode-list-hoverBackground)}
.isec{padding:8px 12px;border-top:1px solid var(--vscode-panel-border)}
.slbl{font-size:11px;font-weight:600;margin-bottom:4px;opacity:.85}
.cblk{background:var(--vscode-textCodeBlock-background);padding:8px;border-radius:4px;font-family:monospace;font-size:11px;white-space:pre-wrap;word-break:break-all;line-height:1.45;margin-top:4px}
.itog{padding:6px 12px;font-size:11px;font-weight:600;cursor:pointer;color:var(--vscode-textLink-foreground);border-top:1px solid var(--vscode-panel-border);user-select:none}
.itog:hover{background:var(--vscode-list-hoverBackground)}
.ibody{max-height:0;overflow:hidden;transition:max-height .35s ease;padding:0 12px}
.ibody.open{max-height:900px;padding:10px 12px 12px}
.osbtn{display:block;width:100%;padding:8px;margin-top:10px;background:linear-gradient(135deg,#1890ff,#096dd9);color:#fff;border:none;border-radius:5px;font-size:12px;font-weight:600;cursor:pointer}
.osbtn:hover{opacity:.9}
.mbg{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.62);z-index:1000;padding:14px;overflow-y:auto}
.mbg.open{display:block}
.mbox{background:var(--vscode-editor-background);border:1px solid var(--vscode-panel-border);border-radius:8px;padding:16px;position:relative;max-width:540px;margin:0 auto;box-shadow:0 8px 32px rgba(0,0,0,.4)}
.mclose{position:absolute;top:10px;right:14px;cursor:pointer;font-size:18px;color:var(--vscode-descriptionForeground);background:none;border:none}
.mtitle{font-size:14px;font-weight:700;margin-bottom:14px}
.plbl{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;opacity:.7}
.pinput{width:100%;background:var(--vscode-input-background);color:var(--vscode-input-foreground);border:1.5px solid rgba(150,150,150,.3);border-radius:5px;padding:8px 10px;font-family:monospace;font-size:12px;outline:none;resize:vertical;transition:border .2s}
.pinput:focus{border-color:#1890ff}
.runbtn{display:block;width:100%;padding:9px;background:linear-gradient(135deg,#52c41a,#389e0d);color:#fff;border:none;border-radius:5px;font-size:13px;font-weight:700;cursor:pointer;margin:10px 0 14px}
.runbtn:hover{opacity:.9}
.pbox{border-radius:5px;padding:10px 12px;font-family:monospace;font-size:11px;white-space:pre-wrap;word-break:break-all;line-height:1.5;min-height:36px}
.pblue  {background:rgba(24,144,255,.08); border:1px solid rgba(24,144,255,.2)}
.pyellow{background:rgba(250,219,20,.08); border:1px solid rgba(250,219,20,.2)}
.pred   {background:rgba(255,77,79,.08);  border:1px solid rgba(255,77,79,.2)}
.pgreen {background:rgba(82,196,26,.08);  border:1px solid rgba(82,196,26,.2)}
.warn{background:rgba(255,77,79,.1);border:1px solid rgba(255,77,79,.3);border-radius:5px;padding:8px 12px;font-size:12px;font-weight:600;color:#ff4d4f;text-align:center;margin-top:8px}
.ok{background:rgba(82,196,26,.1);border:1px solid rgba(82,196,26,.3);border-radius:5px;padding:8px 12px;font-size:12px;font-weight:600;color:#52c41a;text-align:center;margin-top:8px}
.ftbl{width:100%;border-collapse:collapse;font-size:11px}
.ftbl th,.ftbl td{border:1px solid var(--vscode-panel-border);padding:4px 8px;text-align:left}
.ftbl th{background:rgba(24,144,255,.12);font-weight:600}
.arr{text-align:center;color:var(--vscode-descriptionForeground);font-size:16px;margin:6px 0}
.safe{text-align:center;padding:24px 12px}
#errBox{display:none;background:#ff4d4f;color:#fff;padding:8px;font-size:11px;font-family:monospace;white-space:pre-wrap;margin-bottom:8px;border-radius:4px}
@keyframes pglow { 0% { opacity: 0.85; filter: brightness(1); } 50% { opacity: 1; filter: brightness(1.2) drop-shadow(0 0 4px rgba(255,255,255,0.4)); } 100% { opacity: 0.85; filter: brightness(1); } }
@keyframes pstripe { 0% { background-position: 0 0; } 100% { background-position: 40px 0; } }
.pbar-anim {
    animation: pglow 2.5s ease-in-out infinite;
    position: relative;
    overflow: hidden;
}
.pbar-anim::after {
    content: "";
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    background: linear-gradient(45deg, rgba(255,255,255,0.15) 25%, transparent 25%, transparent 50%, rgba(255,255,255,0.15) 50%, rgba(255,255,255,0.15) 75%, transparent 75%, transparent);
    background-size: 40px 40px;
    animation: pstripe 1s linear infinite;
    border-radius: inherit;
}
</style>
</head>
<body>

<div id="errBox"></div>
<h2 style="font-size:15px;font-weight:600;margin-bottom:8px;display:flex;align-items:center;gap:6px">🛡️ CodeShield Security <span style="font-size:9px;opacity:.35;font-weight:400">v4</span></h2>
<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
  <div style="flex:1;height:10px;background:var(--vscode-input-background);border-radius:5px;overflow:hidden;box-shadow:inset 0 1px 3px rgba(0,0,0,0.2)">
    <div class="pbar-anim" style="height:100%;border-radius:5px;width:${score}%;background:${scC}"></div>
  </div>
  <div style="font-size:22px;font-weight:700;min-width:60px;text-align:right;color:${scC}">${score}/100</div>
</div>
<div style="font-size:12px;color:var(--vscode-descriptionForeground);margin-bottom:12px">${issues.length} ${issues.length === 1 ? 'vulnerability' : 'vulnerabilities'} detected</div>
<hr style="border:none;border-top:1px solid var(--vscode-panel-border);margin-bottom:12px"/>

<div id="list">
${issues.length ? cardsHtml : '<div class="safe"><div style="font-size:36px;margin-bottom:8px">✅</div><div style="font-size:13px;color:var(--vscode-descriptionForeground)">No vulnerabilities found.<br/>Your code looks secure!</div></div>'}
</div>


<script nonce="${nonce}">
// ── Error display ─────────────────────────────────────────────────
window.onerror = function(msg, src, line) {
  var b = document.getElementById('errBox');
  b.style.display = 'block';
  b.textContent = 'JS Error: ' + msg + ' (line ' + line + ')';
};

// ── Data ──────────────────────────────────────────────────────────
var vsc = acquireVsCodeApi();
var pg  = ${pgJson};

// ── Event delegation — ALL clicks handled here ────────────────────
document.addEventListener('click', function(e) {
  var el = e.target;
  var actionEl = el.closest ? el.closest('[data-action]') : el;
  if (!actionEl) {
    while (el && el !== document.body && !el.getAttribute('data-action')) el = el.parentElement;
    actionEl = el;
  }
  if (actionEl && actionEl !== document.body) {
    var action = actionEl.getAttribute('data-action');
    if (action) {
      var idx = parseInt(actionEl.getAttribute('data-idx') || '-1', 10);
      if (action === 'nav')    { vsc.postMessage({type:'navigateToLine', value: parseInt(actionEl.getAttribute('data-line'), 10)}); return; }
      if (action === 'tog')    { toggleSim(idx); return; }
      if (action === 'opensb') { vsc.postMessage({type:'openSimulation', value: idx}); return; }
      if (action === 'autofix'){ vsc.postMessage({type:'applyFix', value: idx}); return; }
    }
  }
});

// ── Simulation toggle ─────────────────────────────────────────────
function toggleSim(i) {
  var body = document.getElementById('ib-' + i);
  if (!body) return;
  var open = body.classList.toggle('open');
  // Find the toggle container
  var togs = document.querySelectorAll('[data-action="tog"][data-idx="' + i + '"]');
  togs.forEach(function(t) {
    var ar  = t.querySelector('.itog-arrow');
    var lbl = t.querySelector('.itog-lbl');
    if (ar)  ar.textContent  = open ? '▼' : '▶';
    if (lbl) lbl.textContent = open ? ' Hide Simulation' : ' Show Simulation';
  });
}


</script>
    </body>
    </html>`;
    }
}
