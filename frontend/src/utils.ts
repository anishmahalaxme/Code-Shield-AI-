import * as path from 'path';

export function debounce<T extends (...args: any[]) => void>(
  func: T,
  wait: number
): (...args: Parameters<T>) => void {
  let timeout: NodeJS.Timeout | null = null;
  return (...args: Parameters<T>) => {
    if (timeout) {
      clearTimeout(timeout);
    }
    timeout = setTimeout(() => {
      func(...args);
    }, wait);
  };
}

/** Map VS Code language ids to backend analyze language.
 *  Note: backend scanner.normalize_language() maps all TS dialects → 'javascript'.
 *  We do the same here so the file-extension path and the languageId fallback agree. */
const VSCODE_TO_BACKEND: Record<string, string> = {
  javascript: 'javascript',
  javascriptreact: 'javascript',
  typescript: 'javascript',       // backend normalises TS → JS for scanning
  typescriptreact: 'javascript',  // same
  python: 'python',
};

/**
 * Language id for POST /analyze. Uses file extension first; if unknown (e.g. Untitled buffers),
 * falls back to VS Code's `document.languageId` so scans still run.
 */
export function getLanguageId(filename: string, vscodeLanguageId?: string): string {
  const ext = path.extname(filename || '').replace(/^\./, '').toLowerCase();
  switch (ext) {
    case 'js':
    case 'jsx':
    case 'mjs':
    case 'cjs':
      return 'javascript';
    case 'ts':
    case 'tsx':
      return 'typescript';
    case 'py':
    case 'pyw':
    case 'pyi':
      return 'python';
    case 'java':
      return 'java';
    case 'c':
      return 'c';
    case 'cpp':
    case 'cc':
    case 'cxx':
      return 'cpp';
    case 'cs':
      return 'csharp';
    case 'go':
      return 'go';
    case 'rs':
      return 'rust';
    case 'rb':
      return 'ruby';
    case 'php':
      return 'php';
    case 'sql':
      return 'sql';
    case 'html':
      return 'html';
    default:
      break;
  }
  if (vscodeLanguageId) {
    const mapped = VSCODE_TO_BACKEND[vscodeLanguageId.toLowerCase()];
    if (mapped) {
      return mapped;
    }
  }
  return 'text';
}
