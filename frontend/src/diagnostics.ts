import * as vscode from 'vscode';
import { Issue } from './apiClient';

export const CODE_SHIELD_DIAGNOSTIC_SOURCE = 'CodeShield';

export function updateDiagnostics(
    document: vscode.TextDocument,
    collection: vscode.DiagnosticCollection,
    issues: Issue[]
): void {
    if (document) {
        collection.clear();
        const diagnostics: vscode.Diagnostic[] = [];

        issues.forEach((issue) => {
            // Line is 1-indexed from backend, convert to 0-indexed for VS Code
            const lineIndex = Math.max(0, issue.line - 1);

            let lineText = "";
            try {
                lineText = document.lineAt(lineIndex).text;
            } catch (e) {
                // Line out of bounds
                return;
            }

            const range = new vscode.Range(
                lineIndex,
                lineText.length - lineText.trimStart().length,
                lineIndex,
                lineText.length || 1 // ensure range has some width
            );

            let severity: vscode.DiagnosticSeverity;
            switch (issue.severity.toUpperCase()) {
                case 'CRITICAL':
                case 'HIGH':
                    severity = vscode.DiagnosticSeverity.Error;
                    break;
                case 'MEDIUM':
                    severity = vscode.DiagnosticSeverity.Warning;
                    break;
                case 'LOW':
                default:
                    severity = vscode.DiagnosticSeverity.Information;
                    break;
            }

            const diagnostic = new vscode.Diagnostic(range, issue.message, severity);
            diagnostic.code = issue.type;
            diagnostic.source = CODE_SHIELD_DIAGNOSTIC_SOURCE;

            diagnostics.push(diagnostic);
        });

        collection.set(document.uri, diagnostics);
    } else {
        collection.clear();
    }
}
