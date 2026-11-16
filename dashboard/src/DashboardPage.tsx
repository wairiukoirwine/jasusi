import { useEffect, useState } from "react";
import { api, type Stats, type Verdict } from "./api";
import { categoryLabel, niceMax, percent, shortDate, VERDICT_META } from "./lib/format";

const RANGES = [7, 14, 30];
const STACK: { key: "scam" | "suspicious" | "safe"; verdict: Verdict }[] = [
  { key: "safe", verdict: "SAFE" },
  { key: "suspicious", verdict: "SUSPICIOUS" },
  { key: "scam", verdict: "SCAM" },
];

export default function DashboardPage() {
  const [days, setDays] = useState(14);
  const [stats, setStats] = useState<Stats | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    const load = () =>
      api
        .stats(days)
        .then((s) => live && (setStats(s), setError(null)))
        .catch((e: Error) => live && setError(e.message));
    load();
    const timer = window.setInterval(load, 15000);
    return () => {
      live = false;
      window.clearInterval(timer);
    };
  }, [days]);

  if (error) {
    return (
      <div className="card p-5" role="alert">
        <p className="font-semibold">Dashboard data could not be loaded</p>
        <p className="muted mt-1 text-sm">{error}</p>
      </div>
    );
  }
  if (!stats) return <p className="muted">Loading…</p>;

  const count = (name: string) => stats.verdicts.find((v) => v.name === name)?.count ?? 0;
  const flagged = count("SCAM") + count("SUSPICIOUS");
  const judged = stats.feedback.agree + stats.feedback.disagree;

  return (
    <main className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-lg font-semibold">Scan activity</h1>
        <div className="flex gap-1 text-sm" role="group" aria-label="Time range">
          {RANGES.map((d) => (
            <button key={d} type="button" aria-pressed={days === d} onClick={() => setDays(d)}
              className="rounded-lg border px-3 py-1 font-medium"
              style={days === d
                ? { background: "var(--ink)", color: "var(--surface)", borderColor: "var(--ink)" }
                : { borderColor: "var(--line)", color: "var(--ink-2)" }}>
              Last {d} days
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Tile label="Messages checked" value={stats.total_scans.toLocaleString()} />
        <Tile label="Flagged as scam or suspicious" value={`${percent(flagged, stats.total_scans)}%`}
          note={`${flagged.toLocaleString()} of ${stats.total_scans.toLocaleString()}`} />
        <Tile label="Users agreed with verdict"
          value={judged ? `${percent(stats.feedback.agree, judged)}%` : "—"}
          note={judged ? `${stats.feedback.agree} of ${judged} responses` : "No feedback yet"} />
        <Tile label="Average response time" value={`${Math.round(stats.avg_latency_ms)} ms`} />
      </div>

      {stats.total_scans === 0 ? (
        <div className="card muted p-8 text-center text-sm">
          No scans in this period yet. Check a message and it will show up here.
        </div>
      ) : (
        <>
          <section className="card p-5">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <h2 className="font-semibold">Scans per day, by verdict</h2>
              <ul className="flex gap-4 text-xs" aria-label="Legend">
                {[...STACK].reverse().map(({ verdict }) => (
                  <li key={verdict} className="flex items-center gap-1.5">
                    <span aria-hidden className="inline-block h-2.5 w-2.5 rounded-sm"
                      style={{ background: VERDICT_META[verdict].color }} />
                    <span className="muted">{VERDICT_META[verdict].icon} {VERDICT_META[verdict].label}</span>
                  </li>
                ))}
              </ul>
            </div>
            <DailyChart daily={stats.daily} />
          </section>

          <div className="grid gap-5 md:grid-cols-2">
            <section className="card p-5">
              <h2 className="font-semibold">Top scam categories</h2>
              <Bars items={stats.categories.map((c) => ({ name: categoryLabel(c.name), count: c.count }))}
                empty="Nothing flagged in this period." />
            </section>
            <section className="card p-5">
              <h2 className="font-semibold">Where checks came from</h2>
              <Bars items={stats.channels.map((c) => ({
                  name: c.name === "url" ? "Link" : c.name === "sms" ? "SMS" : "Email", count: c.count }))}
                empty="No scans yet." />
            </section>
          </div>

          <div className="grid gap-5 md:grid-cols-2">
            <section className="card p-5">
              <h2 className="font-semibold">Recent indicators from flagged messages</h2>
              <p className="faint mt-0.5 text-xs">Phone numbers are masked and links are made unclickable.</p>
              {stats.recent_iocs.length === 0 ? (
                <p className="muted mt-3 text-sm">None yet.</p>
              ) : (
                <table className="mt-3 w-full text-sm">
                  <thead>
                    <tr className="faint text-left text-xs">
                      <th className="pb-1 font-medium">Type</th>
                      <th className="pb-1 font-medium">Value</th>
                      <th className="pb-1 text-right font-medium">Seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {stats.recent_iocs.map((ioc) => (
                      <tr key={ioc.type + ioc.value_masked} className="border-t" style={{ borderColor: "var(--line)" }}>
                        <td className="muted py-1.5 pr-3 capitalize">{ioc.type}</td>
                        <td className="break-all py-1.5 pr-3 font-mono text-[13px]">{ioc.value_masked}</td>
                        <td className="tnum py-1.5 text-right">{ioc.count}×</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </section>

            <section className="card p-5">
              <h2 className="font-semibold">Latest scans</h2>
              <table className="mt-3 w-full text-sm">
                <thead>
                  <tr className="faint text-left text-xs">
                    <th className="pb-1 font-medium">Verdict</th>
                    <th className="pb-1 font-medium">Category</th>
                    <th className="pb-1 font-medium">Via</th>
                    <th className="pb-1 text-right font-medium">Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.recent_scans.map((scan) => {
                    const meta = VERDICT_META[scan.verdict];
                    return (
                      <tr key={scan.scan_id} className="border-t" style={{ borderColor: "var(--line)" }}>
                        <td className="py-1.5 pr-3 font-medium" style={{ color: meta.ink }}>
                          <span aria-hidden>{meta.icon}</span> {meta.label}
                        </td>
                        <td className="muted py-1.5 pr-3">{categoryLabel(scan.category)}</td>
                        <td className="muted py-1.5 pr-3 uppercase">{scan.channel === "url" ? "link" : scan.channel}</td>
                        <td className="tnum py-1.5 text-right">{scan.risk_score}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </section>
          </div>
        </>
      )}
    </main>
  );
}

function Tile({ label, value, note }: { label: string; value: string; note?: string }) {
  return (
    <div className="card p-4">
      <p className="muted text-xs">{label}</p>
      <p className="tnum mt-1 text-2xl font-semibold">{value}</p>
      {note && <p className="faint mt-0.5 text-xs">{note}</p>}
    </div>
  );
}

function Bars({ items, empty }: { items: { name: string; count: number }[]; empty: string }) {
  if (items.length === 0) return <p className="muted mt-3 text-sm">{empty}</p>;
  const max = Math.max(...items.map((i) => i.count));
  return (
    <ul className="mt-3 space-y-2 text-sm">
      {items.slice(0, 7).map((item) => (
        <li key={item.name} className="grid grid-cols-[minmax(0,11rem)_1fr_auto] items-center gap-3"
          title={`${item.name}: ${item.count}`}>
          <span className="truncate">{item.name}</span>
          <span className="h-3">
            <span className="block h-3 rounded-r" style={{ width: `${Math.max((item.count / max) * 100, 1.5)}%`, background: "var(--accent)" }} />
          </span>
          <span className="tnum muted w-8 text-right">{item.count}</span>
        </li>
      ))}
    </ul>
  );
}

function DailyChart({ daily }: { daily: Stats["daily"] }) {
  const [hover, setHover] = useState<number | null>(null);
  const W = 720, H = 220, left = 34, right = 8, top = 12, bottom = 26;
  const max = niceMax(Math.max(...daily.map((d) => d.total), 1));
  const plotW = W - left - right, plotH = H - top - bottom;
  const band = plotW / daily.length;
  const barW = Math.min(band - 4, 28);
  const y = (v: number) => top + plotH - (v / max) * plotH;
  const ticks = [0, max / 2, max];
  const labelEvery = Math.ceil(daily.length / 8);
  const active = hover === null ? null : daily[hover];

  return (
    <div className="relative mt-3">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img"
        aria-label={`Scans per day for the last ${daily.length} days, stacked by verdict. The table of latest scans below lists individual results.`}
        onMouseLeave={() => setHover(null)}>
        {ticks.map((t) => (
          <g key={t}>
            <line x1={left} x2={W - right} y1={y(t)} y2={y(t)} stroke={t === 0 ? "var(--axis)" : "var(--line)"} />
            <text x={left - 6} y={y(t) + 4} textAnchor="end" fontSize="11" fill="var(--ink-3)">{t}</text>
          </g>
        ))}
        {daily.map((d, i) => {
          const x = left + i * band + (band - barW) / 2;
          let base = 0;
          const present = STACK.filter((s) => d[s.key] > 0);
          return (
            <g key={d.date}>
              {present.map((s, index) => {
                const value = d[s.key];
                const y1 = y(base + value), y0 = y(base);
                base += value;
                const isTop = index === present.length - 1;
                const height = Math.max(y0 - y1 - (index > 0 ? 2 : 0), 1);
                return (
                  <path key={s.key} fill={VERDICT_META[s.verdict].color}
                    opacity={hover === null || hover === i ? 1 : 0.45}
                    d={roundedTop(x, y1, barW, height, isTop ? Math.min(4, height) : 0)} />
                );
              })}
              {i % labelEvery === 0 && (
                <text x={x + barW / 2} y={H - 8} textAnchor="middle" fontSize="11" fill="var(--ink-3)">
                  {shortDate(d.date)}
                </text>
              )}
              <rect x={left + i * band} y={top} width={band} height={plotH + bottom} fill="transparent"
                tabIndex={0} aria-label={`${shortDate(d.date)}: ${d.total} scans, ${d.scam} scam, ${d.suspicious} suspicious, ${d.safe} safe`}
                onMouseEnter={() => setHover(i)} onFocus={() => setHover(i)} onBlur={() => setHover(null)} />
            </g>
          );
        })}
      </svg>
      {active && hover !== null && (
        <div className="card pointer-events-none absolute top-0 z-10 px-3 py-2 text-xs shadow-sm"
          style={{ left: `${Math.min(Math.max(((left + (hover + 0.5) * band) / W) * 100, 12), 88)}%`, transform: "translateX(-50%)" }}>
          <p className="font-semibold">{shortDate(active.date)} · {active.total} scans</p>
          {[...STACK].reverse().map((s) => (
            <p key={s.key} className="tnum mt-0.5 flex items-center gap-1.5">
              <span aria-hidden className="inline-block h-2 w-2 rounded-sm" style={{ background: VERDICT_META[s.verdict].color }} />
              <span className="muted">{VERDICT_META[s.verdict].label}</span>
              <span className="ml-auto pl-3 font-medium">{active[s.key]}</span>
            </p>
          ))}
        </div>
      )}
    </div>
  );
}

/** Rectangle with only its top corners rounded (the bar's data end). */
function roundedTop(x: number, y: number, w: number, h: number, r: number): string {
  return `M${x},${y + h} V${y + r} Q${x},${y} ${x + r},${y} H${x + w - r} Q${x + w},${y} ${x + w},${y + r} V${y + h} Z`;
}
