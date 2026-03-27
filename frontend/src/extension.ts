import * as vscode from 'vscode';
import { analyzeCode, generateFix, Issue } from './apiClient';
import { updateDiagnostics, CODE_SHIELD_DIAGNOSTIC_SOURCE } from './diagnostics';
import { CodeShieldHoverProvider } from './hoverProvider';
import { CodeShieldSidebarProvider } from './sidebarProvider';
import { CodeShieldFixProvider } from './fixProvider';
import { debounce, getLanguageId } from './utils';

export function activate(context: vscode.ExtensionContext) {
    console.log('CodeShield extension is now active!');

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
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider(CodeShieldSidebarProvider.viewType, sidebarProvider)
    );

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

        const language = getLanguageId(document.fileName);
        const code = document.getText();

        const response = await analyzeCode({
            language,
            filename: document.fileName,
            code
        });

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

    const debouncedScan = debounce(performScan, 3000);

    // Register Event Listeners
    context.subscriptions.push(
        vscode.workspace.onDidChangeTextDocument(event => {
            debouncedScan(event.document);
        })
    );

    context.subscriptions.push(
        vscode.workspace.onDidOpenTextDocument(document => {
            debouncedScan(document);
        })
    );

    // Register Commands
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
                language: getLanguageId(document.fileName),
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

    // Initial scan if there's an active editor
    if (vscode.window.activeTextEditor) {
        debouncedScan(vscode.window.activeTextEditor.document);
    }
}

export function deactivate() { }
