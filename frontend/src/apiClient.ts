import * as http from "http";
import * as https from "https";

let backendBaseUrl = "http://127.0.0.1:8000";

export class HttpTransportError extends Error {
  constructor(
    message: string,
    readonly statusCode?: number,
    readonly bodySnippet?: string,
    readonly code?: string
  ) {
    super(message);
    this.name = "HttpTransportError";
  }
}

/**
 * Raw Node http(s) — no axios, no follow-redirects, no env proxy hooks.
 * Loopback must work even when HTTP_PROXY is set.
 */
function httpRequest(
  method: "GET" | "POST",
  fullUrl: string,
  body: string | undefined,
  timeoutMs: number,
  extraHeaders: Record<string, string> = {}
): Promise<{ statusCode: number; body: string }> {
  return new Promise((resolve, reject) => {
    let parsed: URL;
    try {
      parsed = new URL(fullUrl);
    } catch {
      reject(new HttpTransportError("Invalid URL", undefined, undefined, "EINVAL"));
      return;
    }

    const isHttps = parsed.protocol === "https:";
    const lib = isHttps ? https : http;
    const defaultPort = isHttps ? "443" : "80";
    const port = parsed.port || defaultPort;
    const pathAndQuery = (parsed.pathname || "/") + (parsed.search || "");
    const hostHeader = parsed.port ? `${parsed.hostname}:${parsed.port}` : parsed.hostname;

    const hostname = parsed.hostname;
    const useIPv4 =
      hostname === "localhost" || hostname === "127.0.0.1";

    const opts: http.RequestOptions = {
      method,
      hostname,
      port,
      path: pathAndQuery,
      family: useIPv4 ? 4 : undefined,
      timeout: timeoutMs,
      headers: {
        Host: hostHeader,
        Accept: "application/json",
        ...extraHeaders,
        ...(body !== undefined
          ? { "Content-Length": String(Buffer.byteLength(body, "utf8")) }
          : {}),
      },
    };

    const req = lib.request(opts, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        resolve({ statusCode: res.statusCode ?? 0, body: text });
      });
    });

    req.on("error", (err: NodeJS.ErrnoException) => {
      reject(new HttpTransportError(err.message, undefined, undefined, err.code));
    });
    req.on("timeout", () => {
      req.destroy();
      reject(new HttpTransportError("Request timed out", undefined, undefined, "ETIMEDOUT"));
    });

    if (body !== undefined) {
      req.write(body, "utf8");
    }
    req.end();
  });
}

async function jsonPost<T>(url: string, payload: unknown, timeoutMs: number): Promise<T> {
  const raw = JSON.stringify(payload);
  const { statusCode, body } = await httpRequest(
    "POST",
    url,
    raw,
    timeoutMs,
    { "Content-Type": "application/json" }
  );

  if (statusCode >= 200 && statusCode < 300) {
    try {
      return JSON.parse(body) as T;
    } catch {
      throw new HttpTransportError("Invalid JSON from API", statusCode, body.slice(0, 200));
    }
  }

  throw new HttpTransportError(`HTTP ${statusCode}`, statusCode, body.slice(0, 240));
}

function mapErrorToApiMessage(error: unknown, base: string): string {
  if (error instanceof HttpTransportError) {
    if (error.code === "ECONNREFUSED" || error.code === "ECONNRESET") {
      return (
        `CodeShield: connection refused (${base}). Start ./backend/start.sh. ` +
        `Remote/WSL: run the API in that same environment or set codeshield.backendUrl to this machine's IP.`
      );
    }
    if (error.code === "ENOTFOUND") {
      return "CodeShield: host not found — check codeshield.backendUrl / DNS.";
    }
    if (error.code === "ETIMEDOUT") {
      return "CodeShield: request timed out — backend may be down or blocked.";
    }
    if (error.statusCode === 422) {
      return (
        "CodeShield: request rejected (422). Save file as UTF-8 or check for unusual characters in source."
      );
    }
    if (error.statusCode !== undefined && error.statusCode >= 500) {
      return `CodeShield: server error (${error.statusCode}). Check the backend terminal.`;
    }
  }
  return (
    `CodeShield could not reach ${base}. Start the API (backend/start.sh) ` +
    `or fix codeshield.backendUrl. Command Palette → "CodeShield: Test API Connection".`
  );
}

export function normalizeBaseUrl(url: string): string {
  let t = url.trim().replace(/\/+$/, "");
  // Clients cannot use 0.0.0.0 as a destination; map to loopback.
  t = t.replace(/^(https?:\/\/)0\.0\.0\.0(?=:|\/|$)/i, (_, proto: string) => `${proto}127.0.0.1`);
  return t || "http://127.0.0.1:8000";
}

/**
 * GET / on each candidate until one returns 200 and JSON health payload.
 */
export async function probeBackendBaseUrl(candidates: string[]): Promise<string | null> {
  const seen = new Set<string>();
  for (const raw of candidates) {
    const base = normalizeBaseUrl(raw);
    if (seen.has(base)) {
      continue;
    }
    seen.add(base);
    try {
      const { statusCode, body } = await httpRequest("GET", `${base}/`, undefined, 4000, {
        Accept: "*/*",
      });
      if (statusCode === 200 && /CodeShield/i.test(body)) {
        return base;
      }
    } catch {
      continue;
    }
  }
  return null;
}

export function configureApiClient(baseUrl: string): void {
  backendBaseUrl = normalizeBaseUrl(baseUrl);
}

export function getBackendBaseUrl(): string {
  return backendBaseUrl;
}

export interface AnalyzeRequest {
  language: string;
  filename: string;
  code: string;
}

export interface FixRequest {
  language: string;
  code_snippet: string;
  issue_type: string;
  message: string;
}

export interface SimulateRequest {
  vuln_type: string;
  payload: string;
  code_snippet: string;
  language: string;
}

export interface SimulateResponse {
  query: string;
  attack_result: string;
  attack_class: string;
  impact: string;
  is_attack: boolean;
}

export interface Issue {
  id: string;
  type: string;
  line: number;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  confidence: string;
  message: string;
  code_snippet: string;
  simulation?: {
    payload: string;
    result: string;
    impact: string;
  };
  ai?: {
    explanation: string;
    fix: string;
  };
}

export interface AnalyzeResponse {
  score: number;
  issues: Issue[];
}

export type AnalyzeResult = AnalyzeResponse & {
  apiError?: string;
};

export async function analyzeCode(request: AnalyzeRequest): Promise<AnalyzeResult> {
  const base = backendBaseUrl;

  const doPost = async (urlBase: string): Promise<AnalyzeResult> => {
    const data = await jsonPost<AnalyzeResponse>(`${urlBase}/analyze`, request, 15000);
    return { ...data };
  };

  try {
    return await doPost(base);
  } catch (error) {
    console.error("CodeShield API Error:", error);

    const rediscoveryTargets = [
      base,
      "http://127.0.0.1:8000",
      "http://localhost:8000",
      "http://[::1]:8000",
    ];
    const found = await probeBackendBaseUrl(rediscoveryTargets);
    if (found) {
      configureApiClient(found);
      try {
        return await doPost(found);
      } catch (retryErr) {
        console.error("CodeShield API retry Error:", retryErr);
        error = retryErr;
      }
    }

    return { score: 100, issues: [], apiError: mapErrorToApiMessage(error, backendBaseUrl) };
  }
}

export async function generateFix(request: FixRequest): Promise<string | null> {
  try {
    const data = await jsonPost<{ fixed_code: string }>(`${backendBaseUrl}/fix`, request, 15000);
    return data.fixed_code;
  } catch (error) {
    console.error("CodeShield API Error (Fix):", error);
    return null;
  }
}

export async function simulateExploit(request: SimulateRequest): Promise<SimulateResponse | null> {
  try {
    return await jsonPost<SimulateResponse>(`${backendBaseUrl}/simulate`, request, 20000);
  } catch (error) {
    console.error("CodeShield API Error (Simulate):", error);
    return null;
  }
}
