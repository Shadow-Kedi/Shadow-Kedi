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

function withAlpha(hex: string, alpha: number) {
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
}: {
  labels: string[];
  values: number[];
  colors: string[];
  height?: number;
  ariaLabel?: string;
}) {
  const total = values.reduce((sum, v) => sum + v, 0);
  const nonZeroCount = values.filter((v) => v > 0).length;
  const isSingleState = total > 0 && nonZeroCount <= 1;
  const singleLabel = isSingleState ? labels[values.findIndex((v) => v > 0)] : null;

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
          display: !isSingleState,
          position: 'bottom',
          labels: { color: TICK, font: monoFont, boxWidth: 10, boxHeight: 10, padding: 12, usePointStyle: true, pointStyle: 'circle' },
        },
        tooltip: { backgroundColor: '#0e1a2a', borderColor: '#26364a', borderWidth: 1, titleColor: '#e7edf5', bodyColor: '#cdd9e6' },
      },
    },
  );
  return (
    <div className="chart-wrap donut-wrap" style={{ height }}>
      <canvas ref={canvasRef} role="img" aria-label={ariaLabel ?? (isSingleState ? `${singleLabel}: 100%` : 'Donut chart')} />
      {isSingleState && (
        <div className="donut-center-label" aria-hidden="true">
          <b className="mono">100%</b>
          <span>{singleLabel}</span>
        </div>
      )}
    </div>
  );
}
