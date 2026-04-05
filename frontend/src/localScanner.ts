/**
 * localScanner.ts
 * Offline fallback vulnerability scanner — runs entirely within the extension host.
 *
 * Used when the CodeShield backend API is unreachable.
 * Results are marked confidence: "LOW" so users understand that backend AI analysis
 * is more thorough. This ensures the extension is useful to every marketplace user
 * regardless of whether they have set up the Python backend.
 *
 * Supports: JavaScript, TypeScript, Python
 * Detects:  SQL Injection, XSS, Hardcoded Secrets, Path Traversal, Command Injection
 */

import { Issue } from './apiClient';

// ─── SQL Injection ────────────────────────────────────────────────────────────

const JS_SQL_PATTERNS: RegExp[] = [
    // "SELECT ..." + variable  (string ending with SQL keyword then +)
    /(['"`])(?:.*?\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|UNION|JOIN)\b.*?)\1\s*\+/i,
    // Multi-part concat: SQL keyword ... + ... + ...  (catches: "WHERE '" + x + "'")
    /\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|UNION)\b[^;{}]*\+[^;{}]*\+/i,
    // Template literals: `SELECT ... ${var} ...`
    /`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|UNION|JOIN)\b[^`]*\$\{/i,
    // db/conn method call with dynamic string:  db.query("..." + x)  or  db.query(`...${x}`)
    /\.\s*(?:query|execute|run|all|get|prepare)\s*\(\s*(?:[^'"`)\n]*\+|`[^`]*\$\{)/i,
];

const PY_SQL_PATTERNS: RegExp[] = [
    // cursor.execute("..." + var)
    /execute\s*\(\s*['"].*?\+/i,
    // cursor.execute(f"SELECT ...")
    /execute\s*\(\s*f['"`]/i,
    // "SELECT ..." % (var,)
    /['"`](?:SELECT|INSERT|UPDATE|DELETE)\b.*?['"`]\s*%\s*[\(\w]/i,
    // "SELECT ...".format(var)
    /['"`](?:SELECT|INSERT|UPDATE|DELETE)\b.*?['"`]\s*\.\s*format\s*\(/i,
];

// ─── XSS (JS/TS only) ────────────────────────────────────────────────────────

const XSS_PATTERNS: RegExp[] = [
    // el.innerHTML = non-literal
    /\.innerHTML\s*\+?=\s*(?!['"`][^'"`]*['"`]\s*[;,])/,
    /\.outerHTML\s*\+?=\s*(?!['"`][^'"`]*['"`]\s*[;,])/,
    // document.write(non-literal)
    /document\s*\.\s*write\s*\(\s*(?!['"`])/,
    // eval(variable)
    /\beval\s*\(\s*(?!['"`])/,
    // React dangerouslySetInnerHTML
    /dangerouslySetInnerHTML\s*=\s*\{\s*\{/,
];

// ─── Hardcoded Secrets (language-agnostic) ────────────────────────────────────

const SECRET_PATTERNS: Array<{ re: RegExp; label: string }> = [
    {
        re: /(?:password|passwd|pwd)\s*[:=]\s*['"`][^'"`\s]{4,}['"`]/i,
        label: 'Hardcoded password',
    },
    {
        re: /(?:api_?key|apikey|api_secret)\s*[:=]\s*['"`][A-Za-z0-9_\-]{8,}['"`]/i,
        label: 'Hardcoded API key',
    },
    {
        re: /(?:secret_?key|client_?secret|auth_?token|access_?token)\s*[:=]\s*['"`][A-Za-z0-9_\-./+=]{8,}['"`]/i,
        label: 'Hardcoded secret/token',
    },
    { re: /AKIA[0-9A-Z]{16}/, label: 'AWS Access Key ID exposed' },
    { re: /-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----/, label: 'Private key in source code' },
    { re: /(?:ghp|ghs|github_pat)_[A-Za-z0-9]{36}/, label: 'GitHub token exposed' },
];

// ─── Path Traversal ───────────────────────────────────────────────────────────

const PATH_JS_PATTERNS: RegExp[] = [
    // readFile / createReadStream with dynamic input
    /(?:readFile|readFileSync|createReadStream)\s*\([^)\n]*(?:req\.|params\.|query\.|body\.|userInput\b|input\b)/i,
    // path.join / path.resolve with user input
    /path\s*\.\s*(?:join|resolve)\s*\([^)\n]*(?:req\.|params\.|query\.|body\.)/i,
    // fs.* with user input
    /\bfs\s*\.\s*\w+\s*\(\s*(?:req\.|params\.|query\.|body\.)/i,
];

const PATH_PY_PATTERNS: RegExp[] = [
    /\bopen\s*\(\s*(?:[^'"`)\n]*\+|.*?input\b)/i,
    /os\.path\.join\s*\([^)\n]*(?:input|request|argv|args)\b/i,
];

// ─── Command Injection ────────────────────────────────────────────────────────

const CMD_JS_PATTERNS: RegExp[] = [
    // exec("cmd " + var)  or  exec(`cmd ${var}`)
    /(?:exec|execSync)\s*\(\s*(?:[^'"`)\n]*\+|`[^`]*\$\{)/i,
    // spawn with concatenated command
    /(?:spawn|spawnSync)\s*\(\s*(?:[^'"`)\n]*\+|`[^`]*\$\{)/i,
];

const CMD_PY_PATTERNS: RegExp[] = [
    // os.system("..." + var)
    /os\s*\.\s*system\s*\([^)\n]*(?:\+|input\b|argv\b|args\b)/i,
    // subprocess with shell=True
    /subprocess\s*\.\s*\w+\s*\([^)\n]*shell\s*=\s*True/i,
    // os.popen with dynamic input
    /os\s*\.\s*popen\s*\([^)\n]*(?:\+|input\b|argv\b)/i,
];

// ─── Scanner helpers ──────────────────────────────────────────────────────────

interface RawIssue {
    type: string;
    line: number;
    severity: Issue['severity'];
    message: string;
    code_snippet: string;
}

function isCommentLine(line: string): boolean {
    const t = line.trim();
    return (
        t.startsWith('//') ||
        t.startsWith('#') ||
        t.startsWith('*') ||
        t.startsWith('/*') ||
        t.startsWith('<!--')
    );
}

function scanPatterns(
    lines: string[],
    patterns: RegExp[],
    type: string,
    severity: Issue['severity'],
    message: string,
    seen: Set<string>
): RawIssue[] {
    const results: RawIssue[] = [];
    for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        if (!raw.trim() || isCommentLine(raw)) { continue; }
        for (const re of patterns) {
            if (re.test(raw)) {
                const key = `${type}:${i + 1}`;
                if (!seen.has(key)) {
                    seen.add(key);
                    results.push({
                        type,
                        line: i + 1,
                        severity,
                        message: `${message} (offline scan — start the backend for full AI analysis)`,
                        code_snippet: raw.trim(),
                    });
                }
                break; // one issue per line per pattern group
            }
        }
    }
    return results;
}

// ─── Public API ───────────────────────────────────────────────────────────────

export interface LocalScanResult {
    score: number;
    issues: Issue[];
    isLocalScan: true;
}

const SEV_DEDUCT: Record<string, number> = { CRITICAL: 30, HIGH: 20, MEDIUM: 10, LOW: 5 };

export function localScan(code: string, language: string): LocalScanResult {
    const lang = language.toLowerCase();
    const isJs = lang === 'javascript' || lang === 'typescript';
    const isPy = lang === 'python';

    const lines = code.split(/\r?\n/);
    const raw: RawIssue[] = [];
    const seen = new Set<string>();

    if (isJs) {
        raw.push(...scanPatterns(
            lines, JS_SQL_PATTERNS, 'SQL_INJECTION', 'HIGH',
            'SQL query built with string concatenation — SQL injection risk. Use parameterized queries.', seen
        ));
        raw.push(...scanPatterns(
            lines, XSS_PATTERNS, 'XSS', 'HIGH',
            'Unsanitized user data rendered as HTML — Cross-Site Scripting (XSS) risk.', seen
        ));
        raw.push(...scanPatterns(
            lines, PATH_JS_PATTERNS, 'PATH_TRAVERSAL', 'HIGH',
            'User-controlled path used in file system operation — Path Traversal risk.', seen
        ));
        raw.push(...scanPatterns(
            lines, CMD_JS_PATTERNS, 'COMMAND_INJECTION', 'CRITICAL',
            'User input passed to shell command — Command Injection (RCE) risk.', seen
        ));
    }

    if (isPy) {
        raw.push(...scanPatterns(
            lines, PY_SQL_PATTERNS, 'SQL_INJECTION', 'HIGH',
            'SQL execute() with unsanitized data — SQL injection risk. Use parameterized queries.', seen
        ));
        raw.push(...scanPatterns(
            lines, PATH_PY_PATTERNS, 'PATH_TRAVERSAL', 'HIGH',
            'User-controlled path in file operation — Path Traversal risk.', seen
        ));
        raw.push(...scanPatterns(
            lines, CMD_PY_PATTERNS, 'COMMAND_INJECTION', 'CRITICAL',
            'User input passed to shell command — Command Injection (RCE) risk.', seen
        ));
    }

    // Hardcoded secrets are language-agnostic
    if (isJs || isPy) {
        for (const { re, label } of SECRET_PATTERNS) {
            raw.push(...scanPatterns(
                lines, [re], 'HARDCODED_SECRET', 'HIGH',
                `${label} — move to environment variables.`, seen
            ));
        }
    }

    // Compute score
    let score = 100;
    for (const issue of raw) {
        score -= SEV_DEDUCT[issue.severity] ?? 5;
    }
    score = Math.max(0, score);

    const issues: Issue[] = raw.map((issue, idx) => ({
        ...issue,
        id: `local-${idx}-${issue.line}`,
        confidence: 'LOW' as const,
    }));

    return { score, issues, isLocalScan: true };
}
