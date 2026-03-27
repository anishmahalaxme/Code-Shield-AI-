import axios from "axios";

const BACKEND_URL = "http://localhost:8000";

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

export async function analyzeCode(request: AnalyzeRequest): Promise<AnalyzeResponse> {
  try {
    const response = await axios.post<AnalyzeResponse>(
      `${BACKEND_URL}/analyze`,
      request,
      { headers: { "Content-Type": "application/json" }, timeout: 15000 }
    );
    return response.data;
  } catch (error) {
    console.error("CodeShield API Error:", error);
    // Return empty results on failure to prevent extension crash
    return { score: 100, issues: [] };
  }
}

export async function generateFix(request: FixRequest): Promise<string | null> {
  try {
    const response = await axios.post<{ fixed_code: string }>(
      `${BACKEND_URL}/fix`,
      request,
      { headers: { "Content-Type": "application/json" }, timeout: 15000 }
    );
    return response.data.fixed_code;
  } catch (error) {
    console.error("CodeShield API Error (Fix):", error);
    return null;
  }
}

export async function simulateExploit(request: SimulateRequest): Promise<SimulateResponse | null> {
  try {
    const response = await axios.post<SimulateResponse>(
      `${BACKEND_URL}/simulate`,
      request,
      { headers: { "Content-Type": "application/json" }, timeout: 20000 }
    );
    return response.data;
  } catch (error) {
    console.error("CodeShield API Error (Simulate):", error);
    return null;
  }
}

