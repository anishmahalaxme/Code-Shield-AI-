/**
 * analyzer.ts — HTTP client that sends code to the backend /analyze endpoint.
 */

import axios from "axios";

const BACKEND_URL = "http://localhost:8000";

export interface AnalyzeRequest {
  language: string;
  filename: string;
  code: string;
}

export interface Issue {
  type: string;
  line: number;
  severity: "critical" | "high" | "medium" | "low";
  message: string;
  simulation: string;
  ai_explanation: string;
  fix: string;
}

export interface AnalyzeResponse {
  score: number;
  issues: Issue[];
}

export async function analyzeCode(request: AnalyzeRequest): Promise<AnalyzeResponse> {
  const response = await axios.post<AnalyzeResponse>(
    `${BACKEND_URL}/analyze`,
    request,
    { headers: { "Content-Type": "application/json" }, timeout: 15000 }
  );
  return response.data;
}
