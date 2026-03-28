import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { spawn } from 'child_process';
import { configureApiClient, probeBackendBaseUrl } from './apiClient';

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function probeCandidates(configured: string): string[] {
  return [
    configured,
    'http://127.0.0.1:8000',
    'http://localhost:8000',
    'http://[::1]:8000',
  ];
}

/** Avoid spawning uvicorn repeatedly if the workspace keeps triggering scans. */
let spawnedBackendThisSession = false;

function workspaceBackendRoot(): string | null {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders?.length) {
    return null;
  }
  for (const folder of folders) {
    const backendDir = path.join(folder.uri.fsPath, 'backend');
    const mainPy = path.join(backendDir, 'app', 'main.py');
    if (fs.existsSync(mainPy)) {
      return backendDir;
    }
  }
  return null;
}

async function spawnLocalBackend(outputChannel: vscode.OutputChannel): Promise<boolean> {
  const backendDir = workspaceBackendRoot();
  if (!backendDir) {
    return false;
  }

  const startSh = path.join(backendDir, 'start.sh');
  if (process.platform === 'win32') {
    const uvicornBat = path.join(backendDir, '.venv', 'Scripts', 'uvicorn.exe');
    if (!fs.existsSync(uvicornBat)) {
      outputChannel.appendLine(
        '[CodeShield] Auto-start: create backend\\.venv and run pip install -r requirements.txt'
      );
      return false;
    }
    try {
      const child = spawn(
        uvicornBat,
        ['app.main:app', '--host', '127.0.0.1', '--port', '8000', '--reload'],
        {
          cwd: backendDir,
          detached: true,
          stdio: 'ignore',
        }
      );
      child.unref();
      outputChannel.appendLine('[CodeShield] Auto-start: launched uvicorn (Windows venv).');
      return true;
    } catch (e) {
      outputChannel.appendLine(`[CodeShield] Auto-start failed: ${String(e)}`);
      return false;
    }
  }

  if (!fs.existsSync(startSh)) {
    return false;
  }
  try {
    fs.chmodSync(startSh, 0o755);
  } catch {
    /* ignore */
  }
  try {
    const child = spawn('/bin/bash', [startSh], {
      cwd: backendDir,
      detached: true,
      stdio: 'ignore',
      env: { ...process.env },
    });
    child.on('error', (err) => {
      outputChannel.appendLine(`[CodeShield] Auto-start spawn error: ${err.message}`);
    });
    child.unref();
    outputChannel.appendLine('[CodeShield] Auto-start: launched backend/start.sh');
    return true;
  } catch (e) {
    outputChannel.appendLine(`[CodeShield] Auto-start failed: ${String(e)}`);
    return false;
  }
}

/**
 * If the API is already up, returns its base URL. Otherwise optionally starts backend from workspace and waits.
 */
export async function resolveBackendUrl(
  outputChannel: vscode.OutputChannel,
  configured: string,
  autoStart: boolean
): Promise<string | null> {
  const urls = probeCandidates(configured);
  let found = await probeBackendBaseUrl(urls);
  if (found) {
    return found;
  }

  if (!autoStart || spawnedBackendThisSession) {
    return null;
  }

  if (!workspaceBackendRoot()) {
    return null;
  }

  spawnedBackendThisSession = true;
  const launched = await spawnLocalBackend(outputChannel);
  if (!launched) {
    spawnedBackendThisSession = false;
    return null;
  }

  for (let i = 0; i < 30; i++) {
    await sleep(500);
    found = await probeBackendBaseUrl(urls);
    if (found) {
      configureApiClient(found);
      outputChannel.appendLine(`[CodeShield] API ready at ${found}`);
      return found;
    }
  }

  outputChannel.appendLine('[CodeShield] Auto-start: server did not respond in time. Check Python deps: pip install -r backend/requirements.txt');
  return null;
}
