import type { Verdict } from "../api";

export const VERDICT_META: Record<
  Verdict,
  { label: string; icon: string; color: string; ink: string; advice: string }
> = {
  SAFE: {
    label: "Looks safe",
    icon: "✓",
    color: "var(--good)",
    ink: "var(--good-ink)",
    advice: "Nothing suspicious was found. Stay alert: no checker catches everything.",
  },
  SUSPICIOUS: {
    label: "Suspicious",
    icon: "!",
    color: "var(--warning)",
    ink: "var(--warning-ink)",
    advice: "Do not send money, share codes or click links until you confirm through an official channel.",
  },
  SCAM: {
    label: "Likely a scam",
    icon: "✕",
    color: "var(--critical)",
    ink: "var(--critical-ink)",
    advice: "Do not reply, pay or click. For M-Pesa fraud, forward the message to 333 (free).",
  },
};

const CATEGORY_LABELS: Record<string, string> = {
  legit: "Legitimate",
  mpesa_reversal_scam: "M-Pesa reversal scam",
  fake_bank_or_kra: "Fake bank / KRA alert",
  loan_scam: "Loan scam",
  job_scam: "Job scam",
  prize_or_promo_scam: "Prize / promo scam",
  phishing_link: "Phishing link",
  impersonation: "Impersonation",
  other_scam: "Other scam",
};

export function categoryLabel(category: string): string {
  return CATEGORY_LABELS[category] ?? category.replace(/_/g, " ");
}

/** "2026-11-16" -> "16 Nov" */
export function shortDate(iso: string): string {
  const [, month, day] = iso.slice(0, 10).split("-").map(Number);
  const names = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  return `${day} ${names[month - 1]}`;
}

/** Share of a total as a whole percentage; 0 when the total is 0. */
export function percent(part: number, total: number): number {
  return total > 0 ? Math.round((part / total) * 100) : 0;
}

/** A "nice" axis maximum (1, 2, 4 or 5 times a power of ten) at or above the value. */
export function niceMax(value: number): number {
  if (value <= 4) return 4;
  const magnitude = 10 ** Math.floor(Math.log10(value));
  for (const step of [1, 2, 4, 5, 10]) {
    if (value <= step * magnitude) return step * magnitude;
  }
  return 10 * magnitude;
}
