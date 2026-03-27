import * as vscode from 'vscode';
import { Issue } from './apiClient';

export class CodeShieldHoverProvider implements vscode.HoverProvider {
    private documentIssues: Map<string, Issue[]> = new Map();

    public updateIssues(uri: vscode.Uri, issues: Issue[]) {
        this.documentIssues.set(uri.toString(), issues);
    }

    public provideHover(
        document: vscode.TextDocument,
        position: vscode.Position,
        _token: vscode.CancellationToken
    ): vscode.ProviderResult<vscode.Hover> {
        const issues = this.documentIssues.get(document.uri.toString());
        if (!issues) { return null; }

        // line is 1-indexed in issues, position.line is 0-indexed
        const currentLine = position.line + 1;
        const currentIssues = issues.filter(i => i.line === currentLine);

        if (currentIssues.length === 0) { return null; }

        const markdownParts: vscode.MarkdownString[] = [];

        for (const issue of currentIssues) {
            const md = new vscode.MarkdownString();
            md.isTrusted = true;
            md.supportHtml = true;

            const sevEmoji = this.getSeverityEmoji(issue.severity);
            const sevLabel = issue.severity.toUpperCase();

            md.appendMarkdown(`### 🛡 CodeShield: ${issue.type}\n\n`);
            md.appendMarkdown(`${sevEmoji} **${sevLabel}** · Line ${issue.line}\n\n`);
            md.appendMarkdown(`---\n\n`);

            md.appendMarkdown(`**📋 Issue**\n`);
            md.appendMarkdown(`- ${issue.message}\n\n`);

            if (issue.ai?.explanation) {
                const bullets = this.toBullets(issue.ai.explanation);
                for (const bullet of bullets) {
                    md.appendMarkdown(`- ${bullet}\n`);
                }
                md.appendMarkdown(`\n`);
            }

            // Suggested fix (nested under ai.fix in new schema)
            if (issue.ai?.fix) {
                md.appendMarkdown(`**🔧 Suggested Fix**\n`);
                md.appendCodeblock(issue.ai.fix, document.languageId);
                md.appendMarkdown(`\n`);
            }

            // Simulation preview (nested under simulation.result)
            if (issue.simulation?.result) {
                md.appendMarkdown(`---\n\n`);
                md.appendMarkdown(`**🧪 Simulation Preview**\n`);
                const preview = issue.simulation.result.length > 80
                    ? issue.simulation.result.substring(0, 80) + '...'
                    : issue.simulation.result;
                md.appendCodeblock(preview, 'text');
            }

            // Impact one-liner (nested under simulation.impact)
            if (issue.simulation?.impact) {
                md.appendMarkdown(`\n💥 **Impact:** ${issue.simulation.impact}\n`);
            }

            markdownParts.push(md);
        }

        return new vscode.Hover(markdownParts);
    }

    private getSeverityEmoji(severity: string): string {
        switch (severity.toUpperCase()) {
            case 'CRITICAL': return '🔴';
            case 'HIGH': return '🟠';
            case 'MEDIUM': return '🟡';
            case 'LOW': return '🔵';
            default: return '⚪';
        }
    }

    private toBullets(text: string): string[] {
        const sentences = text
            .split(/(?<=\.)\s+/)
            .map(s => s.trim())
            .filter(s => s.length > 0);
        if (sentences.length <= 1) {
            return [text.trim()];
        }
        return sentences;
    }
}
