import { useEffect, useRef } from 'react';
import {
  Chart,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  LineController,
  BarController,
  DoughnutController,
  Tooltip,
  Legend,
  Filler,
  type ChartData,
  type ChartOptions,
  type ChartType,
} from 'chart.js';

Chart.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  LineController,
  BarController,
  DoughnutController,
  Tooltip,
  Legend,
  Filler,
);

// Chart.js draws to canvas, which can't read CSS custom properties directly --
// so these are resolved from tokens.css ONCE at module load (tokens.css is
// imported ahead of this module in main.tsx, so :root already has the real
// values by the time this runs). This keeps tokens.css as the single source
// of truth for the palette instead of duplicating hex values here.
function cssVar(name: string, fallback: string): string {
  if (typeof document === 'undefined') return fallback;
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return value || fallback;
}

export const SEVERITY_ORDER = ['low', 'medium', 'high', 'critical'] as const;
export const SEVERITY_COLORS: Record<(typeof SEVERITY_ORDER)[number], string> = {
  low: cssVar('--sev-low-mark', '#347eaf'),
  medium: cssVar('--sev-medium-mark', '#e6a23c'),
  high: cssVar('--sev-high-mark', '#e56b55'),
  critical: cssVar('--sev-critical-mark', '#ef39e0'),
};
export const ACCENT = cssVar('--accent-teal', '#70e1bf');
const GRID = 'rgba(157, 176, 197, 0.14)';
const TICK = '#9db0c5';

// Charts are a data-scanning surface throughout (ticks, legend, tooltip) --
// mono end to end, not just the marks.
const monoFont = { family: "'JetBrains Mono', ui-monospace, 'SF Mono', Consolas, monospace", size: 11 };

export function withAlpha(hex: string, alpha: number) {
  const n = parseInt(hex.slice(1), 16);
  const r = (n >> 16) & 255, g = (n >> 8) & 255, b = n & 255;
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

/** Creates and tears down a Chart.js instance bound to a canvas, redrawing when data/options change. */
function useChartInstance<T extends ChartType>(type: T, data: ChartData<T>, options: ChartOptions<T>) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const chartRef = useRef<Chart | null>(null);

  useEffect(() => {
    if (!canvasRef.current) return;
    chartRef.current = new Chart(canvasRef.current, { type, data, options });
    return () => chartRef.current?.destroy();
    // Re-create on every render of the wrapper component; callers already gate
    // this behind stable-ish props, and datasets here are small.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [type, JSON.stringify(data), JSON.stringify(options)]);

  return canvasRef;
}

/** A single-series trend line, e.g. a risk score across review periods. */
export function LineTrendChart({
  labels,
  values,
  label = 'Trend',
  color = ACCENT,
  height = 170,
  ariaLabel,
}: {
  labels: (string | number)[];
  values: number[];
  label?: string;
  color?: string;
  height?: number;
  ariaLabel?: string;
}) {
  const canvasRef = useChartInstance(
    'line',
    {
      labels,
      datasets: [
        {
          label,
          data: values,
          borderColor: color,
          backgroundColor: withAlpha(color, 0.16),
          pointBackgroundColor: color,
          pointBorderColor: color,
          pointRadius: 3,
          pointHoverRadius: 5,
          borderWidth: 2,
          tension: 0.35,
          fill: true,
        },
      ],
    },
    {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { display: false },
        tooltip: { intersect: false, backgroundColor: '#0e1a2a', borderColor: '#26364a', borderWidth: 1, titleColor: '#e7edf5', bodyColor: '#cdd9e6' },
      },
      scales: {
        x: { grid: { display: false }, ticks: { color: TICK, font: monoFont } },
        y: { beginAtZero: true, grid: { color: GRID }, border: { display: false }, ticks: { color: TICK, font: monoFont } },
      },
    },
  );
  return (
    <div className="chart-wrap" style={{ height }}>
      <canvas ref={canvasRef} role="img" aria-label={ariaLabel ?? `${label} line chart`} />
    </div>
  );
}

/** A categorical bar chart. Pass `colors` to color each bar (e.g. by severity); otherwise uses the accent color.
 * Pass `suggestedMax` to fix the value axis to a known domain (e.g. 100 for a 0-100 score) -- also doubles as the
 * fallback ceiling when every value is 0, where Chart.js's auto-scale otherwise picks an oddly tiny/decimal range
 * (e.g. a 0-1.0 axis for an all-zero dataset), which reads as a broken chart rather than "nothing here yet". */
export function BarChart({
  labels,
  values,
  colors,
  label = 'Count',
  height = 170,
  horizontal = false,
  ariaLabel,
  suggestedMax,
}: {
  labels: (string | number)[];
  values: number[];
  colors?: string[];
  label?: string;
  height?: number;
  horizontal?: boolean;
  ariaLabel?: string;
  suggestedMax?: number;
}) {
  const barColors = colors ?? labels.map(() => ACCENT);
  const allZero = values.length > 0 && values.every((v) => v === 0);
  const valueAxisMax = suggestedMax ?? (allZero ? 10 : undefined);
  const canvasRef = useChartInstance(
    'bar',
    {
      labels,
      datasets: [
        {
          label,
          data: values,
          backgroundColor: barColors,
          borderRadius: 4,
          maxBarThickness: 46,
        },
      ],
    },
    {
      indexAxis: horizontal ? 'y' : 'x',
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: { backgroundColor: '#0e1a2a', borderColor: '#26364a', borderWidth: 1, titleColor: '#e7edf5', bodyColor: '#cdd9e6' },
      },
      scales: {
        x: {
          grid: { display: !horizontal ? false : true, color: GRID },
          border: { display: false },
          ticks: { color: TICK, font: monoFont },
          beginAtZero: horizontal,
          ...(horizontal ? { suggestedMax: valueAxisMax } : {}),
        },
        y: {
          grid: { display: horizontal ? false : true, color: GRID },
          border: { display: false },
          ticks: { color: TICK, font: monoFont },
          beginAtZero: !horizontal,
          ...(!horizontal ? { suggestedMax: valueAxisMax } : {}),
        },
      },
    },
  );
  return (
    <div className="chart-wrap" style={{ height }}>
      <canvas ref={canvasRef} role="img" aria-label={ariaLabel ?? `${label} bar chart`} />
    </div>
  );
}

/** A tiny embedded trend line for a metric card -- e.g. a severity count's
 * daily history over the last 7 days. Deliberately a plain static SVG, not
 * another Chart.js instance: no axes/gridlines/legend/tooltip/interaction is
 * wanted here (that's the whole point vs. the full charts above), and a
 * dozen tiny canvases across the Overview cards would be needless overhead
 * for what's meant to sit quietly. No animation either -- a sparkline is
 * itself already a static snapshot of real history, not a live value
 * changing in front of you, so there's no real state change to animate.
 *
 * Caller passes exactly the real days it has -- this never fabricates
 * points. 0 values render as a genuine flat-at-zero line (that IS the real
 * history), 1 value renders as a short flat dash rather than a diagonal
 * line to nowhere, which would imply a trend across a gap that doesn't
 * exist. */
export function Sparkline({
  values,
  color,
  width = 96,
  height = 28,
}: {
  values: number[];
  color: string;
  width?: number;
  height?: number;
}) {
  if (!values || values.length === 0) return null;
  const n = values.length;
  const max = Math.max(...values);
  const min = Math.min(...values, 0);
  const range = max - min || 1;
  const pad = 3;
  const toY = (v: number) => height - pad - ((v - min) / range) * (height - pad * 2);

  if (n === 1) {
    const y = toY(values[0]);
    const half = Math.min(10, width / 4);
    return (
      <svg className="sparkline" width={width} height={height} viewBox={`0 0 ${width} ${height}`} aria-hidden="true">
        <path d={`M ${width / 2 - half} ${y} L ${width / 2 + half} ${y}`} fill="none" stroke={color} strokeWidth={1.5} strokeLinecap="round" />
        <circle cx={width / 2 + half} cy={y} r={2} fill={color} />
      </svg>
    );
  }

  const points = values.map((v, i) => [(i / (n - 1)) * width, toY(v)] as const);
  const d = points.map(([x, y], i) => `${i === 0 ? 'M' : 'L'} ${x} ${y}`).join(' ');
  const [lastX, lastY] = points[points.length - 1];
  return (
    <svg className="sparkline" width={width} height={height} viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" aria-hidden="true">
      <path d={d} fill="none" stroke={color} strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" />
      <circle cx={lastX} cy={lastY} r={2} fill={color} />
    </svg>
  );
}

/** A donut chart for part-of-whole breakdowns (e.g. severity mix, approval status). Shows a legend when there's
 * more than one category with data; a single-category state (100% one value) is a common, legitimate state here
 * (e.g. Discovery map before real app variety exists) -- rendered as a deliberate labeled ring instead of letting
 * Chart.js draw a full circle with a seam at the 0°/360° meeting point, which reads as a rendering glitch. */
export function DonutChart({
  labels,
  values,
  colors,
  height = 170,
  ariaLabel,
  centerLabel,
  showLegend = true,
}: {
  labels: string[];
  values: number[];
  colors: string[];
  height?: number;
  ariaLabel?: string;
  // Forces a center readout regardless of the single-state check below --
  // used by the Discovery map's per-category mini-donuts, which always want
  // a percentage centered (e.g. "70% Safe"), not just in the single-segment
  // edge case. Leave unset for existing full-size donuts; their 100%-state
  // labeling keeps working exactly as before.
  centerLabel?: { value: string; caption: string };
  // Mini-donuts sit in a row with ONE shared legend above them (matching
  // the smartnet-dashboard reference), not a legend per ring -- set false
  // there rather than showing five redundant copies.
  showLegend?: boolean;
}) {
  const total = values.reduce((sum, v) => sum + v, 0);
  const nonZeroCount = values.filter((v) => v > 0).length;
  const isSingleState = total > 0 && nonZeroCount <= 1;
  const singleLabel = isSingleState ? labels[values.findIndex((v) => v > 0)] : null;
  const resolvedCenterLabel = centerLabel ?? (isSingleState ? { value: '100%', caption: singleLabel! } : null);

  const canvasRef = useChartInstance(
    'doughnut',
    {
      labels,
      datasets: [
        {
          data: values,
          backgroundColor: colors,
          borderColor: '#0e1a2a',
          borderWidth: isSingleState ? 0 : 2,
          hoverOffset: isSingleState ? 0 : 4,
        },
      ],
    },
    {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '68%',
      plugins: {
        legend: {
          display: showLegend && !isSingleState && !centerLabel,
          position: 'bottom',
          labels: { color: TICK, font: monoFont, boxWidth: 10, boxHeight: 10, padding: 12, usePointStyle: true, pointStyle: 'circle' },
        },
        tooltip: { backgroundColor: '#0e1a2a', borderColor: '#26364a', borderWidth: 1, titleColor: '#e7edf5', bodyColor: '#cdd9e6' },
      },
    },
  );
  return (
    <div className="chart-wrap donut-wrap" style={{ height }}>
      <canvas ref={canvasRef} role="img" aria-label={ariaLabel ?? (resolvedCenterLabel ? `${resolvedCenterLabel.caption}: ${resolvedCenterLabel.value}` : 'Donut chart')} />
      {resolvedCenterLabel && (
        <div className="donut-center-label" aria-hidden="true">
          <b className="mono">{resolvedCenterLabel.value}</b>
          <span>{resolvedCenterLabel.caption}</span>
        </div>
      )}
    </div>
  );
}
