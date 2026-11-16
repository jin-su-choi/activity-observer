// i18n is the display language object from i18n.mjs.
export function activityChart(app, tab, compact, i18n) {
  const { t } = i18n;
  const colors = { files: '#998bd5', launch: '#69a99b', inputs: '#c49a66', network: '#6e9bc7', other: '#91929b' };
  const traffic = tab === 'network', all = tab === 'all';
  const groups = all ? Object.keys(colors).filter(g => g !== 'other' || app.groupRecords.other > 0) : [tab];
  const received = t('chart.series.received'), sent = t('chart.series.sent');
  const series = traffic ? [received, sent] : groups.map(g => t('group.' + g));
  const bins = app.days ? Object.values(app.days).sort((a, b) => a.h.localeCompare(b.h)) : app.hours;
  const peak = bins.reduce((max, h) => Math.max(max, h.rx + h.tx), 0);
  const factor = peak >= 1000000 ? 1000000 : peak >= 1000 ? 1000 : 1;
  const unit = factor === 1000000 ? 'MB' : factor === 1000 ? 'KB' : 'B';
  const stacked = series.length > 1;
  const time = t('chart.axis.time');
  return {
    id: 'observer-hourly',
    title: t('chart.title', { name: app.name, daily: Boolean(app.days), subject: traffic ? t('chart.subject.traffic') : all ? t('chart.subject.all') : t('group.' + tab) }),
    showHeader: false,
    summary: t(traffic ? 'chart.summary.traffic' : all ? 'chart.summary.all' : 'chart.summary.group'),
    height: 212,
    spec: {
      type: compact ? stacked ? 'stackedArea' : 'area' : stacked ? 'stackedBar' : 'bar',
      x: time, y: stacked ? series : series[0], xLabel: t(app.days ? 'chart.axis.day' : 'chart.axis.hour'), yLabel: traffic ? unit : t('chart.axis.records'), showLegend: stacked,
      ...(!compact ? { sortOrder: 'original' } : {}),
      colors: { ...Object.fromEntries(Object.entries(colors).map(([group, color]) => [t('group.' + group), color])), [received]: '#a9bddf', [sent]: '#7f82c9' },
      valueFormat: { style: 'decimal', maximumFractionDigits: 1 }
    },
    columns: [time, ...series],
    rows: traffic && !app.byteSamples ? [] : bins.map(h => [app.days ? h.h.slice(5) : compact ? h.h : String(h.h).padStart(2, '0'),
      ...(traffic ? [h.rx / factor, h.tx / factor] : groups.map(g => h.groups[g]))])
  };
}
