import { useEffect, useState } from "react";
import { api, type Health } from "./api";
import DashboardPage from "./DashboardPage";
import ScanPage from "./ScanPage";

type Page = "scan" | "dashboard";

function pageFromHash(): Page {
  return window.location.hash === "#dashboard" ? "dashboard" : "scan";
}

export default function App() {
  const [page, setPage] = useState<Page>(pageFromHash);
  const [health, setHealth] = useState<Health | null>(null);

  useEffect(() => {
    const onHash = () => setPage(pageFromHash());
    window.addEventListener("hashchange", onHash);
    api.health().then(setHealth).catch(() => setHealth(null));
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const usingRules = health && health.text_model.includes("rules");

  return (
    <div className="mx-auto max-w-5xl px-4 pb-16">
      <header className="flex flex-wrap items-center justify-between gap-3 py-5">
        <a href="#scan" className="flex items-baseline gap-2">
          <span className="text-xl font-semibold tracking-tight">JASUSI</span>
          <span className="muted text-sm">scam check for Kenya</span>
        </a>
        <nav className="flex gap-1 text-sm" aria-label="Pages">
          {(["scan", "dashboard"] as const).map((p) => (
            <a
              key={p}
              href={`#${p}`}
              aria-current={page === p ? "page" : undefined}
              className="rounded-lg px-3 py-1.5 font-medium"
              style={page === p ? { background: "var(--ink)", color: "var(--surface)" } : { color: "var(--ink-2)" }}
            >
              {p === "scan" ? "Check a message" : "Analyst dashboard"}
            </a>
          ))}
        </nav>
      </header>

      {usingRules && (
        <p className="card mb-4 px-4 py-3 text-sm" role="status">
          <strong>Basic mode.</strong> No trained model is installed, so results come from keyword rules only.
          Train the models (see the README) for full accuracy.
        </p>
      )}

      {page === "scan" ? <ScanPage /> : <DashboardPage />}

      <footer className="faint mt-10 text-xs leading-relaxed">
        JASUSI gives risk guidance, not a guarantee. When in doubt, contact your bank or Safaricom through official
        channels. Messages you check are not stored; only a fingerprint and the verdict are kept.
        {health && (
          <span className="block">
            API {health.version} · {health.text_model} · {health.url_model} · link reputation{" "}
            {health.threat_intel_enabled ? "on" : "off"}
          </span>
        )}
      </footer>
    </div>
  );
}
