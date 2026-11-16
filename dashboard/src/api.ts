export type Verdict = "SAFE" | "SUSPICIOUS" | "SCAM";
export type Channel = "sms" | "email" | "url";

export interface ScanResult {
  scan_id: string;
  verdict: Verdict;
  risk_score: number;
  category: string;
  reasons: string[];
  iocs: { urls: string[]; phones: string[]; paybills: string[]; emails: string[] };
  detectors: { text: number | null; url: number | null; intel: number | null };
  intel_unavailable: boolean;
  model_version: string;
  latency_ms: number;
}

export interface Stats {
  days: number;
  total_scans: number;
  verdicts: { name: string; count: number }[];
  channels: { name: string; count: number }[];
  categories: { name: string; count: number }[];
  daily: { date: string; total: number; scam: number; suspicious: number; safe: number }[];
  recent_scans: {
    scan_id: string;
    created_at: string;
    channel: string;
    verdict: Verdict;
    risk_score: number;
    category: string;
  }[];
  recent_iocs: { type: string; value_masked: string; count: number; last_seen: string }[];
  feedback: { total: number; agree: number; disagree: number; unsure: number };
  avg_latency_ms: number;
}

export interface Health {
  status: string;
  version: string;
  text_model: string;
  url_model: string;
  threat_intel_enabled: boolean;
}

const BASE = import.meta.env.VITE_API_BASE ?? "";

async function request<T>(path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  // Optional: partners paste a key once; it is kept in this browser only.
  const key = localStorage.getItem("jasusi_api_key");
  if (key) headers["X-API-Key"] = key;

  const response = await fetch(`${BASE}/v1${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const data = await response.json();
      if (typeof data.detail === "string") message = data.detail;
      else if (Array.isArray(data.detail) && data.detail[0]?.msg) {
        message = String(data.detail[0].msg).replace(/^Value error, /, "");
      }
    } catch {
      /* keep the generic message */
    }
    throw new Error(message);
  }
  return response.json() as Promise<T>;
}

export const api = {
  health: () => request<Health>("/health"),
  scanSms: (text: string, sender?: string) =>
    request<ScanResult>("/scan/sms", { text, sender: sender || undefined }),
  scanEmail: (subject: string, body: string) => request<ScanResult>("/scan/email", { subject, body }),
  scanUrl: (url: string) => request<ScanResult>("/scan/url", { url }),
  feedback: (scan_id: string, user_label: "scam" | "legit" | "unsure") =>
    request<{ status: string }>("/feedback", { scan_id, user_label }),
  stats: (days: number) => request<Stats>(`/stats/summary?days=${days}`),
};
