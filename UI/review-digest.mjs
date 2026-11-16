import { createHash } from 'node:crypto';
import { describeProgram, openReviewInterval, programIdentity, readReviewStatistics } from './build-widget.mjs';
import { autostartPath, externalAddress, incidentKey, ownAutostart, temporaryPath } from './incident-rules.mjs';
import { incidentDir, readIncidentState } from './incident-store.mjs';
import { guardObserved } from './untrusted.mjs';
import { zoneClock } from './zone.mjs';

// The digest is what a reviewing agent reads first. It is computed from every
// verified row of the interval, so the agent does not page through the log to
// find out what happened. Details stay available through the MCP tools.
const accessKinds = {
  keyboard_observer_active: 'keyboard', keyboard_observer_changed: 'keyboard', hid_access_active: 'hid',
  screen_started: 'screen', screen_capture_client_connected: 'screen_client', camera_started: 'camera',
  microphone_started: 'microphone', audio_input_started: 'audio_input', system_audio_started: 'system_audio'
};
const changeKinds = new Set(['program_installed', 'program_first_seen', 'program_updated', 'program_version_observed', 'program_files_changed', 'program_removed']);
const programLimit = 40;
const parse = text => { try { return JSON.parse(text) ?? {}; } catch { return {}; } };
const push = (list, item, limit) => { if (list.length < limit) list.push(item); return list.length <= limit; };

export function buildReviewDigest(start) {
  const interval = openReviewInterval(start);
  const { anchor, status } = interval;
  const clock = zoneClock();
  const stamp = seconds => new Date(seconds * 1000).toLocaleString('sv-SE', { timeZone: clock.timeZone });
  const programs = new Map(), days = {};
  const gaps = [], sensitiveFiles = [], autostart = [];
  let rejections = 0, sensorRestarts = 0, reconciled = 0;
  // Rows arrive in ID order, so the first one marks when the interval began.
  let began = null;
  let history = null;
  try { history = readIncidentState(incidentDir, true); } catch { /* The digest does not depend on the detector. */ }

  const rows = interval.rows(row => {
    began ??= row.first;
    days[row.day] = (days[row.day] ?? 0) + 1;
    const detail = parse(row.detail);
    if (row.kind === 'collection_gap' || row.kind === 'sensor_transport_gap') push(gaps, { at: stamp(row.last), source: row.source, reason: String(detail.reason ?? row.kind).slice(0, 160) }, 12);
    else if (row.kind === 'filesystem_inventory_reconciled') { if (detail.status === 'completed') reconciled++; }
    else if (row.kind === 'guard_connection_rejected') rejections += row.count;
    else if (row.kind === 'sensor_connected') sensorRestarts += row.count;
    if (row.kind === 'sensitive_file_changed') {
      push(sensitiveFiles, { at: stamp(row.last), path: row.path, category: detail.category, scope: detail.current?.scope, exists: detail.current?.exists }, 20);
    }
    const id = programIdentity(row);
    let program = programs.get(id);
    if (!program) {
      const [name, , type] = describeProgram(id, row);
      program = { id, name, type, records: 0, first: row.first, last: row.last, apps: new Set(), paths: new Map(), changes: [], changeCount: 0,
        access: {}, permissions: new Map(), launches: 0, flags: new Set(),
        network: { opens: 0, sent: 0, received: 0, destinations: new Map(), chains: new Map() } };
      programs.set(id, program);
    }
    program.records++; program.first = Math.min(program.first, row.first); program.last = Math.max(program.last, row.last);
    if (typeof row.app === 'string') program.apps.add(row.app);
    if (row.path) {
      program.paths.set(row.path, (program.paths.get(row.path) ?? 0) + 1);
      if (temporaryPath(row.path)) program.flags.add('runs_from_temporary_or_download_path');
    }
    if (changeKinds.has(row.kind)) {
      program.changeCount++;
      const before = detail.previous ?? {}, current = detail.current ?? {};
      const signerChanged = Boolean(before.team_id && before.team_id !== current.team_id);
      if (signerChanged) program.flags.add('signer_changed');
      if (row.kind !== 'program_removed' && !current.team_id && !current.signing_identifier && row.kind !== 'program_files_changed') program.flags.add('unsigned_program_change');
      if (autostartPath(row.path) && !ownAutostart(row.path) && row.kind !== 'program_removed') {
        program.flags.add('autostart_item_changed');
        push(autostart, { at: stamp(row.last), kind: row.kind, path: row.path }, 20);
      }
      // Repeated changes to one path are listed once with their number.
      const repeated = program.changes.find(item => item.kind === row.kind && item.path === row.path && item.version === current.version);
      if (repeated) { repeated.times = (repeated.times ?? 1) + 1; repeated.last = stamp(row.last); }
      else push(program.changes, { at: stamp(row.last), kind: row.kind, path: row.path, ...(current.version && { version: current.version }),
        ...(before.version && before.version !== current.version && { previousVersion: before.version }),
        ...(signerChanged && { previousTeam: before.team_id, team: current.team_id ?? '' }) }, 6);
    }
    const access = accessKinds[row.kind];
    if (access) {
      const entry = program.access[access] ??= { count: 0, first: stamp(row.first) };
      entry.count += row.count;
    }
    if (row.kind === 'permission_decision') {
      const key = detail.service + ' ' + detail.decision;
      program.permissions.set(key, (program.permissions.get(key) ?? 0) + row.count);
    }
    if (row.kind === 'application_launched') program.launches += row.count;
    if (row.kind === 'network_open' || row.kind === 'network_bytes') {
      const ip = externalAddress(detail.remote);
      if (!ip) return;
      const network = program.network;
      let destination = network.destinations.get(detail.remote);
      if (!destination) {
        if (network.destinations.size >= 2000) return;
        destination = { remote: detail.remote, protocol: detail.protocol, sent: 0, received: 0, opens: 0 };
        const known = history?.destinations?.[incidentKey(row.app, row.path, detail.protocol, ip)];
        // The detector's baseline tells whether this program contacted the address before.
        if (history && (!known || known.first >= began)) destination.firstContact = true;
        network.destinations.set(detail.remote, destination);
      }
      if (row.kind === 'network_open') {
        destination.opens += row.count; network.opens += row.count;
        if (Array.isArray(detail.ancestors) && detail.ancestors.length) {
          const chain = detail.ancestors.slice(0, 4).map(path => String(path).split('/').pop()).join(' < ');
          if (network.chains.size < 200 || network.chains.has(chain)) network.chains.set(chain, (network.chains.get(chain) ?? 0) + row.count);
        }
      } else {
        const sent = (detail.tx_delta || 0) * row.count, received = (detail.rx_delta || 0) * row.count;
        destination.sent += sent; destination.received += received; network.sent += sent; network.received += received;
      }
    }
  });

  // Programs with no recorded activity in the two weeks before this interval.
  let statistics = null;
  try { statistics = readReviewStatistics(interval.after); } catch { /* Novelty flags are omitted. */ }
  const earlier = statistics && new Set((statistics.previous_14_days ?? []).map(entry => entry.app));
  const top = (map, limit) => [...map].sort((a, b) => b[1] - a[1]).slice(0, limit);
  const summaries = [...programs.values()].map(program => {
    if (earlier && program.id !== 'unresolved' && ![...program.apps].some(app => earlier.has(app))) program.flags.add('no_activity_in_previous_14_days');
    const destinations = [...program.network.destinations.values()];
    const firstContacts = destinations.filter(item => item.firstContact && item.sent >= 256 * 1024);
    if (firstContacts.length) program.flags.add('large_send_to_first_contacted_address');
    const notable = program.flags.size || program.changeCount || Object.keys(program.access).length || program.permissions.size;
    return { notable: Boolean(notable), summary: {
      id: program.id, programKey: createHash('sha256').update(program.id).digest('hex'), name: program.name, type: program.type, records: program.records,
      first: stamp(program.first), last: stamp(program.last),
      ...(program.flags.size && { flags: [...program.flags] }),
      paths: top(program.paths, 3).map(([path, records]) => ({ path, records })), pathCount: program.paths.size,
      ...(program.changeCount && { changes: program.changes, changeCount: program.changeCount }),
      ...(Object.keys(program.access).length && { access: program.access }),
      ...(program.permissions.size && { permissions: top(program.permissions, 8).map(([decision, count]) => ({ decision, count })) }),
      ...(program.launches && { launches: program.launches }),
      ...(destinations.length && { network: {
        opens: program.network.opens, externalDestinations: destinations.length, sent: program.network.sent, received: program.network.received,
        topBySent: destinations.sort((a, b) => b.sent - a.sent).slice(0, 5).map(({ remote, protocol, sent, received, opens }) => ({ remote, protocol, sent, received, opens })),
        ...(firstContacts.length && { firstContacts: firstContacts.sort((a, b) => b.sent - a.sent).slice(0, 5).map(({ remote, sent }) => ({ remote, sent })) }),
        ...(program.network.chains.size && { launchedBy: top(program.network.chains, 3).map(([chain, opens]) => ({ chain, opens })) })
      } })
    } };
  }).sort((a, b) => Number(b.notable) - Number(a.notable) || b.summary.records - a.summary.records);
  const shown = summaries.slice(0, programLimit).map(item => item.summary), rest = summaries.slice(programLimit);

  const incidents = Object.values(history?.incidents ?? {}).filter(item => item.updatedAt >= (began ?? 0))
    .sort((a, b) => a.createdAt - b.createdAt).slice(-20)
    .map(({ id, revision, severity, reasons, createdAt, delivery }) => ({ id, revision, severity, reasons, createdAt: stamp(createdAt), delivery: delivery?.status ?? 'pending' }));
  const sensors = Object.entries(status.sensors ?? {}).filter(([name, value]) => value?.status && value.status !== 'active' && name !== 'endpoint_security')
    .map(([name, value]) => ({ name, status: value.status, detail: String(value.detail ?? '').slice(0, 200) }));
  const { value: observed, flagged } = guardObserved({ programs: shown,
    ...(rest.length && { otherPrograms: { count: rest.length, records: rest.reduce((sum, item) => sum + item.summary.records, 0) } }),
    sensitiveFiles, autostart });
  const day = clock.day(anchor.payload.created_at);
  return {
    schema: 1, timeZone: clock.timeZone, anchor,
    start: { after: interval.after, previousHash: interval.previousHash, ...(interval.uncovered && { uncovered: interval.uncovered }) },
    through: anchor.payload.head_id, rows, days, suggestedDay: days[day] ? day : Object.keys(days).sort().at(-1) ?? day,
    integrity: { verifiedRows: rows, chainMatchesSignedAnchor: true, keyFingerprint: anchor.key_fingerprint },
    collection: { version: status.version, collectorRunning: Boolean(status.collector_running), heartbeatAgeSeconds: Math.round(status.heartbeat_age_seconds ?? 0),
      sensorsNotActive: sensors, droppedEvents: status.dropped_events, sensorDropped: status.sensors?.guard_sensor_metrics?.dropped,
      prunedRows: status.pruned_rows, prunedStatisticsRows: status.pruned_statistics_rows, boundaryId: status.boundary_id,
      dataBytes: status.data_bytes, maxDataBytes: status.max_data_bytes,
      gaps, gapCount: gaps.length, reconciledRescans: reconciled, rejectedConnections: rejections, sensorConnections: sensorRestarts },
    detector: history ? { lastScan: history.lastScan ? stamp(history.lastScan) : null, deliveryIssue: history.deliveryIssue ?? null, incidents } : null,
    observed, ...(flagged.length && { flagged })
  };
}
