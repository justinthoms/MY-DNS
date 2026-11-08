"use client";

import { useEffect, useMemo, useRef, useState } from "react";

export type Point = { t: string; total: number; blocked: number; refused: number; failed: number; forwarded: number; cached: number; local: number };

// Series in fixed categorical order (validated: see docs/ARCHITECTURE.md).
// Colours are CSS variables so light and dark mode each use their own steps.
const SERIES: { key: keyof Point; label: string; color: string }[] = [
  { key: "total", label: "Total", color: "var(--series-1)" },
  { key: "blocked", label: "Blocked", color: "var(--series-2)" },
  { key: "refused", label: "Refused", color: "var(--series-3)" },
  { key: "failed", label: "Failed", color: "var(--series-4)" },
];

const H = 260;
const PAD = { top: 12, right: 16, bottom: 28, left: 48 };

function niceMax(v: number) {
  if (v <= 4) return 4;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}

function fmtTick(d: Date, bucketSeconds: number) {
  const iso = d.toISOString();
  if (bucketSeconds >= 12 * 3600) return iso.slice(5, 10);
  if (bucketSeconds >= 2 * 3600) return `${iso.slice(5, 10)} ${iso.slice(11, 13)}h`;
  return iso.slice(11, 16);
}

const fmtNum = (n: number) => n.toLocaleString();

// QueryChart draws queries over time as a line chart with a crosshair
// tooltip and an optional table view. All times are UTC.
export default function QueryChart({ points, bucketSeconds, loading }: { points: Point[]; bucketSeconds: number; loading?: boolean }) {
  const wrap = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(640);
  const [hover, setHover] = useState<number | null>(null);
  const [table, setTable] = useState(false);

  useEffect(() => {
    if (!wrap.current) return;
    const ro = new ResizeObserver((e) => setWidth(Math.max(280, Math.floor(e[0].contentRect.width))));
    ro.observe(wrap.current);
    return () => ro.disconnect();
  }, []);

  const n = points.length;
  const innerW = width - PAD.left - PAD.right;
  const innerH = H - PAD.top - PAD.bottom;
  const yMax = useMemo(() => niceMax(Math.max(0, ...points.map((p) => p.total))), [points]);
  const x = (i: number) => PAD.left + (n <= 1 ? innerW / 2 : (i / (n - 1)) * innerW);
  const y = (v: number) => PAD.top + innerH - (v / yMax) * innerH;
  const yTicks = [0, 0.25, 0.5, 0.75, 1].map((f) => f * yMax);
  const xTickEvery = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(innerW / 90))));

  // The last bucket is still filling up: draw it separately and faded so a
  // partial count does not read as a drop in traffic.
  const seg = (key: keyof Point, from: number, to: number) =>
    points.slice(from, to + 1).map((p, j) => `${j === 0 ? "M" : "L"}${x(from + j).toFixed(1)},${y(p[key] as number).toFixed(1)}`).join("");

  const onMove = (clientX: number) => {
    const r = wrap.current?.getBoundingClientRect();
    if (!r || n === 0) return;
    const rel = clientX - r.left - PAD.left;
    setHover(Math.max(0, Math.min(n - 1, Math.round((rel / innerW) * (n - 1)))));
  };

  const hp = hover != null ? points[hover] : null;
  const tipLeft = hover != null ? Math.min(x(hover) + 12, width - 170) : 0;

  return (
    <div className="viz">
      <div className="viz-legend" aria-label="Legend">
        {SERIES.map((s) => (
          <span key={s.key}><i style={{ background: s.color }} />{s.label}</span>
        ))}
        <button type="button" className="secondary viz-toggle" onClick={() => setTable(!table)}>
          {table ? "Show chart" : "Show as table"}
        </button>
      </div>

      {table ? (
        <div className="table-wrap" style={{ maxHeight: H + 40, overflowY: "auto" }}>
          <table>
            <thead><tr><th>Time (UTC)</th>{SERIES.map((s) => <th key={s.key} style={{ textAlign: "right" }}>{s.label}</th>)}<th style={{ textAlign: "right" }}>Cached</th><th style={{ textAlign: "right" }}>Local</th></tr></thead>
            <tbody>
              {[...points].reverse().map((p) => (
                <tr key={p.t}>
                  <td>{new Date(p.t).toISOString().slice(0, 16).replace("T", " ")}</td>
                  {SERIES.map((s) => <td key={s.key} className="num" style={{ textAlign: "right" }}>{fmtNum(p[s.key] as number)}</td>)}
                  <td className="num" style={{ textAlign: "right" }}>{fmtNum(p.cached)}</td>
                  <td className="num" style={{ textAlign: "right" }}>{fmtNum(p.local)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div
          ref={wrap}
          className="viz-plot"
          style={{ opacity: loading ? 0.5 : 1 }}
          onPointerMove={(e) => onMove(e.clientX)}
          onPointerLeave={() => setHover(null)}
          tabIndex={0}
          role="img"
          aria-label={`Queries over time: ${fmtNum(points.reduce((a, p) => a + p.total, 0))} total`}
          onKeyDown={(e) => {
            if (e.key === "ArrowRight") setHover((h) => Math.min(n - 1, (h ?? -1) + 1));
            if (e.key === "ArrowLeft") setHover((h) => Math.max(0, (h ?? n) - 1));
            if (e.key === "Escape") setHover(null);
          }}
          onBlur={() => setHover(null)}
        >
          <svg width={width} height={H} role="presentation">
            {yTicks.map((v) => (
              <g key={v}>
                <line x1={PAD.left} x2={width - PAD.right} y1={y(v)} y2={y(v)} className="viz-grid" />
                <text x={PAD.left - 8} y={y(v)} className="viz-axis" textAnchor="end" dominantBaseline="middle">{fmtNum(v)}</text>
              </g>
            ))}
            {points.map((p, i) =>
              i % xTickEvery === 0 ? (
                <text key={p.t} x={x(i)} y={H - 8} className="viz-axis" textAnchor="middle">{fmtTick(new Date(p.t), bucketSeconds)}</text>
              ) : null,
            )}
            {[...SERIES].reverse().map((s) => (
              <g key={s.key}>
                <path d={seg(s.key, 0, Math.max(0, n - 2))} fill="none" stroke={s.color} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
                {n > 1 && <path d={seg(s.key, n - 2, n - 1)} fill="none" stroke={s.color} strokeWidth={2} strokeLinecap="round" opacity={0.35} />}
              </g>
            ))}
            {hp && hover != null && (
              <g>
                <line x1={x(hover)} x2={x(hover)} y1={PAD.top} y2={PAD.top + innerH} className="viz-crosshair" />
                {SERIES.map((s) => (
                  <circle key={s.key} cx={x(hover)} cy={y(hp[s.key] as number)} r={4} fill={s.color} className="viz-dot" />
                ))}
              </g>
            )}
          </svg>
          {hp && (
            <div className="viz-tip" style={{ left: tipLeft, top: PAD.top }} role="status">
              <div className="viz-tip-time">{new Date(hp.t).toISOString().slice(0, 16).replace("T", " ")} UTC{hover === n - 1 && " (in progress)"}</div>
              {SERIES.map((s) => (
                <div key={s.key} className="viz-tip-row">
                  <i style={{ background: s.color }} />
                  <strong>{fmtNum(hp[s.key] as number)}</strong>
                  <span>{s.label}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
