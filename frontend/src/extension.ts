import * as vscode from 'vscode';
import { analyzeCode, configureApiClient, generateFix, Issue, normalizeBaseUrl, probeBackendBaseUrl } from './apiClient';
import { updateDiagnostics, CODE_SHIELD_DIAGNOSTIC_SOURCE } from './diagnostics';
import { CodeShieldHoverProvider } from './hoverProvider';
import { CodeShieldSidebarProvider } from './sidebarProvider';
import { CodeShieldFixProvider } from './fixProvider';
import { debounce, getLanguageId } from './utils';
import { resolveBackendUrl } from './backendLauncher';
import { localScan } from './localScanner';

function backendUrlFromConfig(): string {
    return vscode.workspace.getConfiguration('codeshield').get<string>('backendUrl', 'http://127.0.0.1:8000')
        ?? 'http://127.0.0.1:8000';
}

export async function activate(context: vscode.ExtensionContext) {
    console.log('CodeShield extension is now active!');

    const outputChannel = vscode.window.createOutputChannel('CodeShield');
    const extVersion = context.extension.packageJSON.version as string;
    outputChannel.appendLine(
        `[CodeShield] Extension v${extVersion} (loopback via Node http — reload window after install from this repo).`
    );

    const configuredBackend = backendUrlFromConfig();
    configureApiClient(configuredBackend);

    // Setup StatusBar Item
    const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.text = '$(shield) CodeShield: SAFE';
    statusBarItem.color = new vscode.ThemeColor('testing.iconPassed');
    statusBarItem.tooltip = 'CodeShield Security Status';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    // Setup Diagnostic Collection
    const diagnosticCollection = vscode.languages.createDiagnosticCollection(CODE_SHIELD_DIAGNOSTIC_SOURCE);
    context.subscriptions.push(diagnosticCollection);

    // Setup Providers
    const hoverProvider = new CodeShieldHoverProvider();
    context.subscriptions.push(
        vscode.languages.registerHoverProvider('*', hoverProvider)
    );

    const sidebarProvider = new CodeShieldSidebarProvider(context.extensionUri);
    if (!(globalThis as any)._codeshieldSidebarRegistered) {
        (globalThis as any)._codeshieldSidebarRegistered = true;
        context.subscriptions.push(
            vscode.window.registerWebviewViewProvider(CodeShieldSidebarProvider.viewType, sidebarProvider)
        );
    }

    const fixProvider = new CodeShieldFixProvider();
    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider('*', fixProvider, {
            providedCodeActionKinds: [vscode.CodeActionKind.QuickFix]
        })
    );

    const performScan = async (document: vscode.TextDocument) => {
        if (document.languageId === 'Log' || document.uri.scheme !== 'file') return;

        statusBarItem.text = '$(sync~spin) CodeShield: SCANNING';
        statusBarItem.color = new vscode.ThemeColor('statusBarItem.warningBackground');

        const language = getLanguageId(document.fileName, document.languageId);
        const code = document.getText();

        let response = await analyzeCode({
            language,
            filename: document.fileName,
            code
        });

        if (response.apiError) {
            const autoStart = vscode.workspace.getConfiguration('codeshield').get<boolean>('autoStartBackend', true);
            const recovered = await resolveBackendUrl(outputChannel, backendUrlFromConfig(), !!autoStart);
            if (recovered) {
                configureApiClient(recovered);
                response = await analyzeCode({
                    language,
                    filename: document.fileName,
                    code
                });
            }
        }

        if (response.apiError) {
            // ── Offline fallback: run local regex scanner so users still see issues ──
            const localResult = localScan(code, language);
            sidebarProvider.updateData({
                score: localResult.score,
                issues: localResult.issues,
                apiOffline: true,
                apiError: response.apiError,
                isLocalScan: true,
            });
            if (localResult.issues.length > 0) {
                updateDiagnostics(document, diagnosticCollection, localResult.issues);
                hoverProvider.updateIssues(document.uri, localResult.issues);
                fixProvider.updateIssues(document.uri, localResult.issues);
                statusBarItem.text = '$(warning) CodeShield: LOCAL SCAN';
            } else {
                diagnosticCollection.delete(document.uri);
                hoverProvider.updateIssues(document.uri, []);
                fixProvider.updateIssues(document.uri, []);
                statusBarItem.text = '$(plug) CodeShield: NO API';
            }
            statusBarItem.color = new vscode.ThemeColor('statusBarItem.warningBackground');
            statusBarItem.tooltip = response.apiError;
            outputChannel.appendLine(`[scan] ${response.apiError}`);
            startBackendPolling();
            return;
        }

        updateDiagnostics(document, diagnosticCollection, response.issues);
        hoverProvider.updateIssues(document.uri, response.issues);
        fixProvider.updateIssues(document.uri, response.issues);
        sidebarProvider.updateData(response);

        if (response.issues.length > 0) {
            statusBarItem.text = '$(shield) CodeShield: RISK';
            statusBarItem.color = new vscode.ThemeColor('testing.iconFailed');
        } else {
            statusBarItem.text = '$(shield) CodeShield: SAFE';
            statusBarItem.color = new vscode.ThemeColor('testing.iconPassed');
        }
    };

    // ── Backend polling: auto-reconnect when API comes back online ──────────
    let retryTimer: NodeJS.Timeout | undefined;
    const startBackendPolling = () => {
        if (retryTimer !== undefined) { return; } // already polling
        outputChannel.appendLine('[CodeShield] Backend offline — polling every 15 s for reconnection.');
        retryTimer = setInterval(async () => {
            const found = await probeBackendBaseUrl([
                backendUrlFromConfig(),
                'http://127.0.0.1:8000',
                'http://localhost:8000',
                'http://[::1]:8000',
            ]);
            if (found) {
                clearInterval(retryTimer);
                retryTimer = undefined;
                configureApiClient(found);
                outputChannel.appendLine(`[CodeShield] Backend reconnected at ${found}.`);
                vscode.window.showInformationMessage(`CodeShield: Backend reconnected ✅`);
                if (vscode.window.activeTextEditor) {
                    void performScan(vscode.window.activeTextEditor.document);
                }
            }
        }, 15000);
        context.subscriptions.push({
            dispose: () => { if (retryTimer) { clearInterval(retryTimer); retryTimer = undefined; } }
        });
    };

    const debouncedScan = debounce(performScan, 1200);

    // Register Event Listeners
    context.subscriptions.push(
        vscode.workspace.onDidChangeTextDocument(event => {
            debouncedScan(event.document);
        })
    );

    context.subscriptions.push(
        vscode.workspace.onDidOpenTextDocument(document => {
            void performScan(document);
        })
    );

    // Register Commands
    const pingApiCommand = vscode.commands.registerCommand('codeshield.pingApi', async () => {
        const configured = backendUrlFromConfig();
        const found = await probeBackendBaseUrl([
            configured,
            'http://127.0.0.1:8000',
            'http://localhost:8000',
            'http://[::1]:8000',
        ]);
        if (found) {
            configureApiClient(found);
            outputChannel.appendLine(`[ping] OK — ${found}`);
            vscode.window.showInformationMessage(`CodeShield: API OK at ${found}`);
            if (vscode.window.activeTextEditor) {
                void performScan(vscode.window.activeTextEditor.document);
            }
        } else {
            const tryStart = vscode.workspace.getConfiguration('codeshield').get<boolean>('autoStartBackend', true);
            const recovered = await resolveBackendUrl(outputChannel, configured, !!tryStart);
            if (recovered) {
                configureApiClient(recovered);
                outputChannel.appendLine(`[ping] OK after auto-start — ${recovered}`);
                vscode.window.showInformationMessage(`CodeShield: API OK at ${recovered}`);
                if (vscode.window.activeTextEditor) {
                    void performScan(vscode.window.activeTextEditor.document);
                }
            } else {
                outputChannel.appendLine('[ping] FAILED — no response on port 8000.');
                vscode.window.showErrorMessage(
                    'CodeShield: API not found. Open the Code Shield repo as workspace, or run backend/start.sh.'
                );
            }
        }
    });
    context.subscriptions.push(pingApiCommand);

    const analyzeCommand = vscode.commands.registerCommand('codeshield.analyze', () => {
        const editor = vscode.window.activeTextEditor;
        if (editor) {
            vscode.window.showInformationMessage('Running CodeShield Scan...');
            performScan(editor.document);
        } else {
            vscode.window.showErrorMessage('No active file to scan.');
        }
    });
    context.subscriptions.push(analyzeCommand);

    const applyFixCommand = vscode.commands.registerCommand('codeshield.applyFix', async (document: vscode.TextDocument, range: vscode.Range, issue: Issue) => {
        try {
            vscode.window.showInformationMessage(`🤖 CodeShield: Generating fix for ${issue.type}...`);
            const fixedCode = await generateFix({
                language: getLanguageId(document.fileName, document.languageId),
                code_snippet: issue.code_snippet,
                issue_type: issue.type,
                message: issue.message
            });

            if (fixedCode) {
                const edit = new vscode.WorkspaceEdit();
                edit.replace(document.uri, range, fixedCode);
                const success = await vscode.workspace.applyEdit(edit);
                if (success) {
                    vscode.window.showInformationMessage('✅ CodeShield: Fix applied successfully!');
                    // Optionally trigger a rescan after fix
                    debouncedScan(document);
                } else {
                    vscode.window.showErrorMessage('❌ CodeShield: Failed to apply code fix edit.');
                }
            } else {
                vscode.window.showErrorMessage('❌ CodeShield: Failed to generate fix code.');
            }
        } catch (err) {
            vscode.window.showErrorMessage('❌ CodeShield error applying fix.');
        }
    });
    context.subscriptions.push(applyFixCommand);
    context.subscriptions.push(outputChannel);

    context.subscriptions.push(
        vscode.workspace.onDidChangeConfiguration(e => {
            if (e.affectsConfiguration('codeshield.backendUrl')) {
                configureApiClient(backendUrlFromConfig());
                if (vscode.window.activeTextEditor) {
                    void performScan(vscode.window.activeTextEditor.document);
                }
            }
        })
    );

    const autoStart = vscode.workspace.getConfiguration('codeshield').get<boolean>('autoStartBackend', true);
    let foundUrl = await probeBackendBaseUrl([
        configuredBackend,
        'http://127.0.0.1:8000',
        'http://localhost:8000',
        'http://[::1]:8000',
    ]);
    if (!foundUrl) {
        foundUrl = await resolveBackendUrl(outputChannel, configuredBackend, !!autoStart);
    }
    if (foundUrl) {
        if (normalizeBaseUrl(foundUrl) !== normalizeBaseUrl(configuredBackend)) {
            outputChannel.appendLine(
                `[CodeShield] API reachable at ${foundUrl} (settings: ${configuredBackend}).`
            );
        }
        configureApiClient(foundUrl);
    } else {
        outputChannel.appendLine(
            '[CodeShield] API not reachable. Open this repo as a workspace folder, or run backend/start.sh, then "CodeShield: Test API Connection".'
        );
        outputChannel.appendLine(
            '[CodeShield] Remote-SSH/WSL: run the API in that environment or set codeshield.backendUrl.'
        );
    }

    if (vscode.window.activeTextEditor) {
        void performScan(vscode.window.activeTextEditor.document);
    }
}

export function deactivate() { }
