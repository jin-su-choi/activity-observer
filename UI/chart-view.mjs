import { BarController, BarElement, CategoryScale, Chart, Filler, Legend, LinearScale,
  LineController, LineElement, PointElement, Tooltip } from 'chart.js';
import { i18n, t } from './widget-i18n.mjs';

Chart.register(BarController, BarElement, CategoryScale, Filler, Legend, LinearScale,
  LineController, LineElement, PointElement, Tooltip);

export function mountChart(container, initial, onSelect) {
  const frame = document.createElement('div');
  const canvas = document.createElement('canvas');
  frame.style.position = 'relative';
  canvas.style.color = 'var(--oi-muted)';
  canvas.style.borderColor = 'var(--oi-line)';
  const selectionSwatch = document.createElement('span');
  selectionSwatch.hidden = true;
  selectionSwatch.style.color = 'var(--oi-chart-selection)';
  selectionSwatch.setAttribute('aria-hidden','true');
  frame.append(selectionSwatch,canvas);
  container.replaceChildren(frame);
  canvas.setAttribute('role', 'img');
  let chart, selection, start;
  const brush = { id: 'activitySelection', beforeDatasetsDraw({ ctx, chartArea, scales }) {
    if (!selection || !scales.x || !chartArea) return;
    const { top, bottom, left, right } = chartArea;
    const first = scales.x.getPixelForValue(selection.first), last = scales.x.getPixelForValue(selection.last);
    const step = Math.abs(scales.x.getPixelForValue(1) - scales.x.getPixelForValue(0)) / 2 || 10;
    const x = Math.max(left, first - step);
    ctx.save();
    // Resolve theme-dependent CSS to an actual color before passing it to Canvas.
    ctx.fillStyle = getComputedStyle(selectionSwatch).color;
    ctx.fillRect(x, top, Math.min(right, last + step) - x, bottom - top);
    ctx.restore();
  } };
  if (onSelect) {
    canvas.tabIndex = 0;
    canvas.style.cursor = 'crosshair';
    const indexAt = event => {
      if (!chart?.chartArea) return;
      const rect = canvas.getBoundingClientRect(), x = event.clientX - rect.left, y = event.clientY - rect.top;
      const { left, right, top, bottom } = chart.chartArea;
      if (y < top || y > bottom) return;
      return chart.scales.x.getValueForPixel(Math.min(right, Math.max(left, x)));
    };
    const pick = (a, b, point) => {
      const max = chart.data.labels.length - 1;
      if (max < 0) return;
      const limit = index => Math.max(0, Math.min(max, index));
      selection = { first: limit(Math.min(a, b)), last: limit(Math.max(a, b)) };
      chart.draw();
      onSelect(selection.first, selection.last, point);
    };
    canvas.addEventListener('pointerdown', event => {
      if (!event.isPrimary || event.button !== 0) return;
      start = indexAt(event);
      if (start !== undefined) canvas.setPointerCapture(event.pointerId);
    });
    canvas.addEventListener('pointerup', event => {
      const end = indexAt(event);
      if (start !== undefined && end !== undefined) pick(start, end, {
        clientX: event.clientX, clientY: event.clientY, focusMenu: true
      });
      start = undefined;
    });
    canvas.addEventListener('pointercancel', () => { start = undefined; });
    canvas.addEventListener('keydown', event => {
      if (!chart?.chartArea || !['ArrowLeft', 'ArrowRight', 'Enter', ' '].includes(event.key)) return;
      event.preventDefault();
      const active = selection?.last ?? 0;
      const next = active + (event.key === 'ArrowLeft' ? -1 : event.key === 'ArrowRight' ? 1 : 0);
      const { left, bottom } = canvas.getBoundingClientRect();
      const from = event.shiftKey || event.key === 'Enter' || event.key === ' ' ? selection?.first ?? active : next;
      pick(from, next, { clientX: left + chart.scales.x.getPixelForValue(next),
        clientY: bottom - 20, focusMenu: event.key === 'Enter' || event.key === ' ', keyboard: true });
    });
  }
  const view = {
    destroy() { chart?.destroy(); frame.remove(); },
    clearSelection() { selection = undefined; chart?.draw(); },
    refreshTheme() {
      if(!chart)return;
      const {color,borderTopColor:grid}=getComputedStyle(canvas);
      chart.options.color=color;chart.options.plugins.legend.labels.color=color;
      for(const axis of ['x','y']){chart.options.scales[axis].ticks.color=color;chart.options.scales[axis].title.color=color;}
      chart.options.scales.y.grid.color=grid;
      chart.update('none');
    },
    set config({ title, summary, height, spec, columns, rows }) {
      const type = /area$/i.test(spec.type) ? 'line' : 'bar';
      const stacked = Array.isArray(spec.y);
      const { color, borderTopColor: grid } = getComputedStyle(canvas);
      const labels = rows.map(row => row[0]);
      const number = new Intl.NumberFormat(i18n.tag, spec.valueFormat);
      const datasets = columns.slice(1).map((label, i) => {
        const fill = spec.colors[label] || '#998bd5';
        return {
          label, data: rows.map(row => row[i + 1]), backgroundColor: type === 'bar' ? fill : fill + '80',
          borderColor: fill, borderWidth: type === 'line' ? 1.5 : 0, borderRadius: 4,
          fill: type === 'line' && (i ? '-1' : 'origin'), pointRadius: 0, pointHoverRadius: 3, tension: 0.25
        };
      });
      frame.style.height = (height + (stacked ? 44 : 24)) + 'px';
      canvas.setAttribute('aria-label', title + '. ' + summary + (onSelect ? t('chart.selectHint') : ''));
      selection = undefined;
      const options = {
        animation: false, maintainAspectRatio: false, color,
        interaction: { mode: 'index', intersect: false },
        plugins: {
          legend: { display: spec.showLegend, position: 'bottom', labels: { color, usePointStyle: true, boxWidth: 8, boxHeight: 5 } },
          tooltip: { callbacks: { label: ({ dataset, parsed }) => dataset.label + ' · ' + number.format(parsed.y) + ' ' + spec.yLabel } }
        },
        scales: {
          x: { stacked, grid: { display: false }, ticks: { color, maxTicksLimit: type === 'line' ? 6 : 24 },
            title: { display: true, text: spec.xLabel, color } },
          y: { stacked, beginAtZero: true, grid: { color: grid }, ticks: { color, maxTicksLimit: 6 },
            title: { display: true, text: spec.yLabel, color } }
        }
      };
      if (chart && chart.config.type !== type) {
        chart.destroy();
        chart = undefined;
      }
      if (!chart) chart = new Chart(canvas, { type, data: { labels, datasets }, options, plugins: onSelect ? [brush] : [] });
      else {
        chart.data = { labels, datasets };
        chart.options = options;
        chart.update('none');
      }
    }
  };
  view.config = initial;
  return view;
}
