import { useState, type FormEvent } from "react";
import { api, type Channel, type ScanResult } from "./api";
import { categoryLabel, VERDICT_META } from "./lib/format";

const EXAMPLES: { label: string; channel: Channel; text: string }[] = [
  {
    label: "M-Pesa reversal",
    channel: "sms",
    text: "Hello, nimekutumia Ksh 3,500 kimakosa kwa MPESA. Tafadhali nirudishie kwa 0712345678 haraka.",
  },
  {
    label: "Fake KRA alert",
    channel: "sms",
    text: "KRA: Your iTax account has been suspended. Verify your PIN immediately at http://kra-itax-verify.xyz/login to avoid penalties.",
  },
  { label: "Normal chat", channel: "sms", text: "Uko wapi? Tukutane saa kumi kwa stage." },
  { label: "Suspicious link", channel: "url", text: "http://safaricom-rewards.top/claim?id=8821" },
];

const CHANNELS: { id: Channel; label: string; hint: string }[] = [
  { id: "sms", label: "SMS", hint: "Paste the message exactly as you received it" },
  { id: "email", label: "Email", hint: "Paste the email body" },
  { id: "url", label: "Link", hint: "Paste the link. It will be analysed as text and never opened." },
];

export default function ScanPage() {
  const [channel, setChannel] = useState<Channel>("sms");
  const [text, setText] = useState("");
  const [sender, setSender] = useState("");
  const [subject, setSubject] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);

  const limit = channel === "sms" ? 2000 : channel === "url" ? 2048 : 50000;

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!text.trim() || busy) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const value = text.trim();
      const scan =
        channel === "sms"
          ? await api.scanSms(value, sender.trim())
          : channel === "email"
            ? await api.scanEmail(subject.trim(), value)
            : await api.scanUrl(value);
      setResult(scan);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Something went wrong. Please try again.");
    } finally {
      setBusy(false);
    }
  }

  function pick(channelId: Channel) {
    setChannel(channelId);
    setResult(null);
    setError(null);
  }

  const inputClass = "w-full rounded-lg border bg-transparent px-3 py-2 text-[15px]";
  const inputStyle = { borderColor: "var(--axis)" };

  return (
    <main className="grid gap-5 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
      <form onSubmit={submit} className="card self-start p-5">
        <h1 className="text-lg font-semibold">Is this message a scam?</h1>
        <p className="muted mt-1 text-sm">Paste an SMS, email or link and get a verdict with the reasons.</p>

        <div className="mt-4 flex gap-1" role="tablist" aria-label="What are you checking?">
          {CHANNELS.map((c) => (
            <button
              key={c.id}
              type="button"
              role="tab"
              aria-selected={channel === c.id}
              onClick={() => pick(c.id)}
              className="rounded-lg border px-3 py-1.5 text-sm font-medium"
              style={
                channel === c.id
                  ? { background: "var(--ink)", color: "var(--surface)", borderColor: "var(--ink)" }
                  : { borderColor: "var(--line)", color: "var(--ink-2)" }
              }
            >
              {c.label}
            </button>
          ))}
        </div>

        {channel === "email" && (
          <label className="mt-4 block text-sm font-medium">
            Subject <span className="faint font-normal">(optional)</span>
            <input className={`${inputClass} mt-1`} style={inputStyle} value={subject} maxLength={300}
              onChange={(e) => setSubject(e.target.value)} />
          </label>
        )}

        <label className="mt-4 block text-sm font-medium">
          {channel === "url" ? "Link" : "Message"}
          {channel === "url" ? (
            <input className={`${inputClass} mt-1`} style={inputStyle} value={text} maxLength={limit}
              placeholder="example.com/page" onChange={(e) => setText(e.target.value)}
              autoCapitalize="off" autoCorrect="off" spellCheck={false} />
          ) : (
            <textarea className={`${inputClass} mt-1 min-h-36 resize-y`} style={inputStyle} value={text}
              maxLength={limit} onChange={(e) => setText(e.target.value)} />
          )}
        </label>
        <p className="faint mt-1 flex justify-between text-xs">
          <span>{CHANNELS.find((c) => c.id === channel)!.hint}</span>
          {channel !== "url" && <span className="tnum">{text.length}/{limit}</span>}
        </p>

        {channel === "sms" && (
          <label className="mt-3 block text-sm font-medium">
            Sender <span className="faint font-normal">(optional, e.g. MPESA or 0712…)</span>
            <input className={`${inputClass} mt-1`} style={inputStyle} value={sender} maxLength={40}
              onChange={(e) => setSender(e.target.value)} />
          </label>
        )}

        <button
          type="submit"
          disabled={busy || !text.trim()}
          className="mt-4 w-full rounded-lg px-4 py-2.5 font-semibold disabled:opacity-50"
          style={{ background: "var(--accent)", color: "#fff" }}
        >
          {busy ? "Checking…" : "Check now"}
        </button>

        <div className="mt-4 text-sm">
          <span className="muted">Try an example:</span>
          <div className="mt-2 flex flex-wrap gap-2">
            {EXAMPLES.map((ex) => (
              <button key={ex.label} type="button" className="rounded-full border px-3 py-1 text-xs"
                style={{ borderColor: "var(--line)" }}
                onClick={() => { pick(ex.channel); setText(ex.text); setSender(""); }}>
                {ex.label}
              </button>
            ))}
          </div>
        </div>
      </form>

      <section aria-live="polite" className="self-start">
        {error && (
          <div className="card p-5" role="alert">
            <p className="font-semibold" style={{ color: "var(--critical-ink)" }}>Could not check this</p>
            <p className="muted mt-1 text-sm">{error}</p>
          </div>
        )}
        {result && <ResultCard key={result.scan_id} result={result} />}
        {!result && !error && (
          <div className="card muted p-5 text-sm">
            <p className="font-medium" style={{ color: "var(--ink)" }}>Your result will appear here.</p>
            <p className="mt-2">You get a verdict, a 0–100 risk score, and the specific reasons behind it.</p>
          </div>
        )}
      </section>
    </main>
  );
}

function ResultCard({ result }: { result: ScanResult }) {
  const meta = VERDICT_META[result.verdict];
  const [sent, setSent] = useState<string | null>(null);
  const iocs = [
    ...result.iocs.urls.map((v) => ["Link", v]),
    ...result.iocs.phones.map((v) => ["Phone", v]),
    ...result.iocs.paybills.map((v) => ["Paybill / till", v]),
    ...result.iocs.emails.map((v) => ["Email", v]),
  ];

  async function feedback(label: "scam" | "legit") {
    try {
      await api.feedback(result.scan_id, label);
      setSent("Thanks, your answer was recorded.");
    } catch {
      setSent("Could not record your answer.");
    }
  }

  return (
    <div className="card overflow-hidden">
      <div className="p-5" style={{ borderTop: `4px solid ${meta.color}` }}>
        <div className="flex items-center gap-3">
          <span aria-hidden className="grid h-10 w-10 place-items-center rounded-full text-lg font-bold"
            style={{ background: meta.color, color: result.verdict === "SUSPICIOUS" ? "#0b0b0b" : "#fff" }}>
            {meta.icon}
          </span>
          <div>
            <p className="text-xl font-semibold" style={{ color: meta.ink }}>{meta.label}</p>
            {result.verdict !== "SAFE" && <p className="muted text-sm">{categoryLabel(result.category)}</p>}
          </div>
          <div className="ml-auto text-right">
            <p className="tnum text-3xl font-semibold leading-none">{result.risk_score}</p>
            <p className="faint text-xs">risk out of 100</p>
          </div>
        </div>

        <div className="mt-4 h-2 rounded-full" style={{ background: "var(--line)" }}
          role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={result.risk_score}
          aria-label="Risk score">
          <div className="h-2 rounded-full" style={{ width: `${Math.max(result.risk_score, 2)}%`, background: meta.color }} />
        </div>

        <p className="mt-4 text-sm">{meta.advice}</p>

        <h2 className="mt-5 text-sm font-semibold">Why</h2>
        <ul className="mt-2 space-y-1.5 text-sm">
          {result.reasons.map((reason) => (
            <li key={reason} className="flex gap-2">
              <span aria-hidden className="faint">•</span>
              <span>{reason}</span>
            </li>
          ))}
        </ul>

        {iocs.length > 0 && (
          <>
            <h2 className="mt-5 text-sm font-semibold">Found in the message</h2>
            <dl className="mt-2 space-y-1 text-sm">
              {iocs.map(([kind, value]) => (
                <div key={kind + value} className="flex gap-3">
                  <dt className="muted w-24 shrink-0">{kind}</dt>
                  <dd className="break-all font-mono text-[13px]">{value}</dd>
                </div>
              ))}
            </dl>
          </>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-2 border-t px-5 py-3 text-sm" style={{ borderColor: "var(--line)" }}>
        {sent ? (
          <span className="muted">{sent}</span>
        ) : (
          <>
            <span className="muted mr-1">What do you think it is?</span>
            <button type="button" className="rounded-lg border px-3 py-1" style={{ borderColor: "var(--axis)" }}
              onClick={() => feedback("scam")}>A scam</button>
            <button type="button" className="rounded-lg border px-3 py-1" style={{ borderColor: "var(--axis)" }}
              onClick={() => feedback("legit")}>Genuine</button>
          </>
        )}
        <span className="faint tnum ml-auto text-xs">{result.latency_ms} ms</span>
      </div>
    </div>
  );
}
