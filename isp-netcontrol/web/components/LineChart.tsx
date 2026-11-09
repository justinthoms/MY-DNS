"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { fmtAxis, fmtMinute, tzName } from "@/lib/api";

export type Series<P> = { key: string; label: string; color: string; value: (p: P) => number | null };

const PAD = { top: 12, right: 16, bottom: 28, left: 52 };

function niceMax(v: number) {
  if (v <= 0) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}

function fmtTick(d: Date, bucketSeconds: number) {
  if (bucketSeconds >= 12 * 3600) return fmtAxis(d, false, true);
  return fmtAxis(d, bucketSeconds >= 2 * 3600);
}

// LineChart: one y-axis, 2px lines, crosshair tooltip with every series,
// legend, and a table view. The last bucket is still filling up and is
// drawn faded. Missing values (null) leave a gap instead of a fake zero.
export default function LineChart<P extends { t: string }>({
  points, series, bucketSeconds, fmt, height = 240, area = false, label, loading,
}: {
  points: P[]; series: Series<P>[]; bucketSeconds: number; fmt: (v: number) => string;
  height?: number; area?: boolean; label: string; loading?: boolean;
}) {
  const wrap = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(600);
  const [hover, setHover] = useState<number | null>(null);
  const [table, setTable] = useState(false);
  useEffect(() => {
    if (!wrap.current) return;
    const ro = new ResizeObserver((e) => setWidth(Math.max(260, Math.floor(e[0].contentRect.width))));
    ro.observe(wrap.current);
    return () => ro.disconnect();
  }, [table]);

  const n = points.length;
  const innerW = width - PAD.left - PAD.right;
  const innerH = height - PAD.top - PAD.bottom;
  const yMax = useMemo(() => niceMax(Math.max(0, ...points.flatMap((p) => series.map((s) => s.value(p) ?? 0)))), [points, series]);
  const x = (i: number) => PAD.left + (n <= 1 ? innerW / 2 : (i / (n - 1)) * innerW);
  const y = (v: number) => PAD.top + innerH - (v / yMax) * innerH;
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => f * yMax);
  const every = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(innerW / 90))));

  // Path from index a to b, with gaps where a value is null.
  const path = (s: Series<P>, a: number, b: number) => {
    let d = "", pen = false;
    for (let i = a; i <= b && i < n; i++) {
      const v = s.value(points[i]);
      if (v == null) { pen = false; continue; }
      d += `${pen ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`;
      pen = true;
    }
    return d;
  };
  const areaPath = (s: Series<P>) => {
    const pts = points.map((p, i) => [i, s.value(p)] as const).filter(([, v]) => v != null) as [number, number][];
    if (pts.length < 2) return "";
    return `M${x(pts[0][0])},${y(0)}` + pts.map(([i, v]) => `L${x(i).toFixed(1)},${y(v).toFixed(1)}`).join("") + `L${x(pts[pts.length - 1][0])},${y(0)}Z`;
  };

  const move = (clientX: number) => {
    const r = wrap.current?.getBoundingClientRect();
    if (!r || n === 0) return;
    setHover(Math.max(0, Math.min(n - 1, Math.round(((clientX - r.left - PAD.left) / innerW) * (n - 1)))));
  };
  const hp = hover != null ? points[hover] : null;

  return (
    <div className="viz">
      <div className="viz-legend">
        {series.length > 1 && series.map((s) => <span key={s.key}><i style={{ background: s.color }} />{s.label}</span>)}
        <button type="button" className="secondary viz-toggle" onClick={() => setTable(!table)}>{table ? "Show chart" : "Show as table"}</button>
      </div>
      {table ? (
        <div className="table-wrap" style={{ maxHeight: height + 20, overflowY: "auto" }}>
          <table>
            <thead><tr><th>Time ({tzName()})</th>{series.map((s) => <th key={s.key} style={{ textAlign: "right" }}>{s.label}</th>)}</tr></thead>
            <tbody>
              {[...points].reverse().map((p) => (
                <tr key={p.t}>
                  <td>{fmtMinute(p.t)}</td>
                  {series.map((s) => { const v = s.value(p); return <td key={s.key} className="num" style={{ textAlign: "right" }}>{v == null ? "—" : fmt(v)}</td>; })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div
          ref={wrap} className="viz-plot" style={{ opacity: loading ? 0.6 : 1 }} tabIndex={0} role="img" aria-label={label}
          onPointerMove={(e) => move(e.clientX)} onPointerLeave={() => setHover(null)} onBlur={() => setHover(null)}
          onKeyDown={(e) => {
            if (e.key === "ArrowRight") setHover((h) => Math.min(n - 1, (h ?? -1) + 1));
            if (e.key === "ArrowLeft") setHover((h) => Math.max(0, (h ?? n) - 1));
            if (e.key === "Escape") setHover(null);
          }}
        >
          <svg width={width} height={height} role="presentation">
            {ticks.map((v) => (
              <g key={v}>
                <line x1={PAD.left} x2={width - PAD.right} y1={y(v)} y2={y(v)} className="viz-grid" />
                <text x={PAD.left - 8} y={y(v)} className="viz-axis" textAnchor="end" dominantBaseline="middle">{fmt(v)}</text>
              </g>
            ))}
            {points.map((p, i) => (i % every === 0 ? <text key={p.t} x={x(i)} y={height - 8} className="viz-axis" textAnchor="middle">{fmtTick(new Date(p.t), bucketSeconds)}</text> : null))}
            {area && series.length === 1 && <path d={areaPath(series[0])} fill={series[0].color} opacity={0.14} />}
            {[...series].reverse().map((s) => (
              <g key={s.key}>
                <path d={path(s, 0, Math.max(0, n - 2))} fill="none" stroke={s.color} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
                {n > 1 && <path d={path(s, n - 2, n - 1)} fill="none" stroke={s.color} strokeWidth={2} strokeLinecap="round" opacity={0.35} />}
              </g>
            ))}
            {hp && hover != null && (
              <g>
                <line x1={x(hover)} x2={x(hover)} y1={PAD.top} y2={PAD.top + innerH} className="viz-crosshair" />
                {series.map((s) => { const v = s.value(hp); return v == null ? null : <circle key={s.key} cx={x(hover)} cy={y(v)} r={4} fill={s.color} className="viz-dot" />; })}
              </g>
            )}
          </svg>
          {hp && hover != null && (
            <div className="viz-tip" style={{ left: Math.min(x(hover) + 12, width - 180), top: PAD.top }} role="status">
              <div className="viz-tip-time">{fmtMinute(hp.t)}{hover === n - 1 && " (in progress)"}</div>
              {series.map((s) => { const v = s.value(hp); return (
                <div key={s.key} className="viz-tip-row"><i style={{ background: s.color }} /><strong>{v == null ? "—" : fmt(v)}</strong><span>{s.label}</span></div>
              ); })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
