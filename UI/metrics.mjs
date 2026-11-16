// Metric definitions use the complete non-network summary set. Exporters retain
// these facts before trimming the detail list, so headline values stay complete.
// The short names are written into published facts, so they stay as they are.
// Labels and explanations come from the display language.
const metricFeatures = [
  { id: 'input', short: '입력 장치', pattern: /^(keyboard_observer_|hid_access_)/ },
  { id: 'screen', short: '화면 접근', pattern: /^(screen_|capture_stream_)/ },
  { id: 'audio', short: '오디오', pattern: /^(microphone_|audio_input_|system_audio_)/ },
  { id: 'camera', short: '카메라', pattern: /^camera_/ }
];
const metricKeyboardOnly = '키보드 등록';
const metricLatest = rows => rows.reduce((latest, r) => latest == null || r.last > latest ? r.last : latest, null);
const metricPaths = rows => new Set(rows.flatMap(r => r.locations.map(p => p.path))).size;
const metricFeatureStarts = (app, id) => {
  const alternatives = {
    input: [['keyboard_observer_active', 'hid_access_active']],
    screen: [['screen_started'], ['screen_capture_client_connected'], ['capture_stream_started']],
    audio: [['microphone_started'], ['audio_input_started'], ['system_audio_started']],
    camera: [['camera_started']]
  }[id];
  const kinds = alternatives.find(group => group.some(kind => app.kinds[kind] > 0)) || [];
  return { count: kinds.reduce((n, kind) => n + (app.kinds[kind] || 0), 0),
    last: metricLatest(app.activity.filter(r => kinds.includes(r.kind))) };
};

export function computeMetricFacts(app) {
  const rows = app.activity;
  if (rows.reduce((n, r) => n + r.records, 0) !== app.records - app.groupRecords.network) throw Error('Complete activity summaries are required to calculate headline metrics');
  const added = rows.filter(r => r.kind === 'program_installed');
  const modified = rows.filter(r => ['program_updated', 'program_files_changed'].includes(r.kind));
  const removed = rows.filter(r => r.kind === 'program_removed');
  const updates = rows.filter(r => r.kind === 'program_updated').map(r => {
    if (Number.isSafeInteger(r.versionChangeCount) && r.versionChangeCount >= 0) return { count: r.versionChangeCount, pair: r.lastVersionChange };
    if (r.records > 1) throw Error('Raw version-change facts are required for merged program changes');
    const changed = r.version && r.previousVersion && r.version !== r.previousVersion;
    return { count: changed ? r.count : 0, pair: changed ? { before: r.previousVersion, after: r.version, last: r.last } : null };
  });
  const lastUpdate = updates.map(r => r.pair).filter(Boolean).sort((a,b) => b.last - a.last)[0];
  return {
    schema: 1,
    files: { added: metricPaths(added), modified: metricPaths(modified), removed: metricPaths(removed),
      changed: metricPaths([...added, ...modified, ...removed]), firstSeen: metricPaths(rows.filter(r => r.kind === 'program_first_seen')),
      versionChanges: updates.reduce((n,r) => n + r.count, 0), lastVersion: lastUpdate ? { before: lastUpdate.before, after: lastUpdate.after } : null },
    features: metricFeatures.map(feature => {
      const matching = rows.filter(r => feature.pattern.test(r.kind));
      const present = matching.length > 0;
      const registrationOnly = feature.id === 'input' && matching.every(r => r.kind.startsWith('keyboard_observer_'));
      return { id: feature.id, present, last: metricLatest(matching), starts: metricFeatureStarts(app, feature.id),
        short: registrationOnly ? metricKeyboardOnly : feature.short };
    }),
    launch: { count: app.kinds.application_launched || 0, last: metricLatest(rows.filter(r => r.kind === 'application_launched')) },
    termination: { count: app.kinds.application_terminated || 0, last: metricLatest(rows.filter(r => r.kind === 'application_terminated')) }
  };
}

// i18n is the display language object from i18n.mjs.
export function programMetrics(app, tab, i18n) {
  const { t } = i18n;
  const facts = app.metricFacts?.schema === 1 ? app.metricFacts : computeMetricFacts(app);
  const count = (id, value, note = null) => ({ id, label: t('metric.' + id + '.label'), value, unit: t('metric.' + id + '.unit'),
    help: t('metric.' + id + '.help'), note, format: 'count' });
  const bytesMetric = (id, value, note = null) => ({ id, label: t('metric.' + id + '.label'), value: app.byteSamples ? value : null,
    format: 'bytes', note, help: t('metric.bytes.help') });
  const time = (id, value) => ({ id, label: t('metric.' + id + '.label'), value, format: 'time', help: t('metric.' + id + '.help') });
  const targets = count('targets', app.endpointCount);
  const connections = count('connections', app.opens);
  if (tab === 'network') return {
    metrics: [connections, targets, bytesMetric('received', app.rx), bytesMetric('sent', app.tx)],
    caption: t('caption.network')
  };
  if (tab === 'files') return {
    metrics: [
      count('version_changes', facts.files.versionChanges, facts.files.lastVersion ? { type: 'version', ...facts.files.lastVersion } : null),
      count('added', facts.files.added),
      count('modified', facts.files.modified),
      count('removed', facts.files.removed)
    ],
    caption: t('caption.files')
  };
  if (tab === 'launch') return {
    metrics: [
      count('launches', facts.launch.count),
      time('last_launch', facts.launch.last),
      count('exits', facts.termination.count),
      time('last_exit', facts.termination.last)
    ],
    caption: t('caption.launch')
  };
  if (tab === 'inputs') return {
    metrics: metricFeatures.map(feature => {
      const fact = facts.features.find(f => f.id === feature.id);
      const starts = fact.starts || metricFeatureStarts(app, feature.id);
      return count(feature.id, starts.count, starts.last ? { type: 'last', value: starts.last } : null);
    }),
    caption: t('caption.inputs')
  };
  const present = facts.features.filter(f => f.present);
  const screen = metricFeatures.find(feature => feature.id === 'screen').short;
  return {
    metrics: [
      count('file_changes', facts.files.changed),
      count('features', present.length || null, { type: 'text', value: present.map(f => i18n.token('feature', f.id === 'screen' ? screen : f.short)).join(' · ') }),
      { ...targets, note: app.opens ? { type: 'connections', value: app.opens } : null },
      bytesMetric('traffic', app.rx + app.tx, app.byteSamples ? { type: 'traffic', rx: app.rx, tx: app.tx } : null)
    ],
    caption: t('caption.all')
  };
}

export function tabDescription(app, tab, i18n) {
  const scope = tab === 'network' ? i18n.t('scope.network', { total: app.endpointCount, shown: Math.min(app.endpoints.length, 20) })
    : i18n.has('scope.' + tab) ? i18n.t('scope.' + tab) : '';
  return [programMetrics(app, tab, i18n).caption, scope].filter(Boolean).join(' ');
}
