// Shared by the service worker, popup and options page.
export const DEFAULT_API = "http://localhost:8000";

export async function getConfig() {
  const { apiBase = DEFAULT_API, apiKey = "" } = await chrome.storage.sync.get(["apiBase", "apiKey"]);
  return { apiBase: apiBase.replace(/\/+$/, ""), apiKey };
}

/** Scan a link or a piece of text. The link is sent as text; nothing here opens it. */
export async function scan(kind, value) {
  const { apiBase, apiKey } = await getConfig();
  const path = kind === "url" ? "/v1/scan/url" : "/v1/scan/sms";
  const body = kind === "url" ? { url: value } : { text: value.slice(0, 2000) };
  const headers = { "Content-Type": "application/json" };
  if (apiKey) headers["X-API-Key"] = apiKey;
  const response = await fetch(apiBase + path, { method: "POST", headers, body: JSON.stringify(body) });
  if (!response.ok) {
    let detail = `The JASUSI server answered ${response.status}`;
    try {
      const data = await response.json();
      if (typeof data.detail === "string") detail = data.detail;
    } catch { /* keep the generic message */ }
    throw new Error(detail);
  }
  return response.json();
}

export const VERDICTS = {
  SAFE: { label: "Looks safe", icon: "✓", color: "#0ca30c", badge: "OK" },
  SUSPICIOUS: { label: "Suspicious", icon: "!", color: "#fab219", badge: "?" },
  SCAM: { label: "Likely a scam", icon: "✕", color: "#d03b3b", badge: "!" },
};
