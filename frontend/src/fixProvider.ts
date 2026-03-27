import * as vscode from 'vscode';
import { CODE_SHIELD_DIAGNOSTIC_SOURCE } from './diagnostics';
import { Issue } from './apiClient';

export class CodeShieldFixProvider implements vscode.CodeActionProvider {
    private documentIssues: Map<string, Issue[]> = new Map();

    public updateIssues(uri: vscode.Uri, issues: Issue[]) {
        this.documentIssues.set(uri.toString(), issues);
    }

    public provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        token: vscode.CancellationToken
    ): vscode.ProviderResult<(vscode.Command | vscode.CodeAction)[]> {

        // Filter diagnostics to only include CodeShield ones
        const diagnostics = context.diagnostics.filter(
            d => d.source === CODE_SHIELD_DIAGNOSTIC_SOURCE
        );

        if (diagnostics.length === 0) {
            return [];
        }

        const issues = this.documentIssues.get(document.uri.toString()) || [];
        const actions: vscode.CodeAction[] = [];

        for (const diagnostic of diagnostics) {
            // Find corresponding issue
            // Diagnostic range line is 0-indexed, Issue line is 1-indexed
            const issue = issues.find(i => i.line === diagnostic.range.start.line + 1 && i.type === diagnostic.code);
            if (issue) {
                const action = new vscode.CodeAction(
                    `⚡ Fix with CodeShield AI: ${issue.type}`,
                    vscode.CodeActionKind.QuickFix
                );
                action.diagnostics = [diagnostic];
                action.isPreferred = true; // Makes it the default fix
                action.command = {
                    command: 'codeshield.applyFix',
                    title: 'Apply AI Fix',
                    arguments: [document, diagnostic.range, issue]
                };
                actions.push(action);
            }
        }

        return actions;
    }
}
