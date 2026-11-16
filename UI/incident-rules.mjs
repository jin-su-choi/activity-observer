import { createHash } from 'node:crypto';
import { isIP } from 'node:net';

const minute = 60;
const windowSeconds = 5 * minute;
const day = 24 * 60 * minute;
const incidentLifetime = 60 * minute;
// A destination counts as new for an hour after a program first contacts it.
const newDestinationAge = 60 * minute;
const newDestinationBytes = 256 * 1024;
const unusualBytes = 8 * 1024 * 1024;
// Rules that compare against a baseline stay silent for the first day of
// observation. Their findings are still in the log for the daily review.
const learningPeriod = day;
// From the third send to a new destination within a week, a program is a
// habitual sender, such as a browser or a sync client, and that rule alone no
// longer raises an incident for it.
const habitWindow = 7 * day;
const habitualSends = 2;
// A first-seen executable and its first external connection belong together
// when they are this close. Discovery can trail the connection slightly.
const introductionWindow = 10 * minute;
// A file-watch gap that the collector repairs by rechecking known paths is
// left to the daily review. Without a completed recheck it becomes an incident.
const gapGrace = 10 * minute;

// Incidents store these codes. Their text is in i18n.mjs under incident.reason.
export const incidentReasonCodes = new Set(['changed_program_access', 'sensitive_external_send', 'signer_changed_access',
  'signer_changed', 'new_destination_send', 'new_program_network', 'autostart_changed', 'sensitive_file_changed',
  'settings_changed', 'protected_installation', 'log_integrity', 'retention_gap', 'collection_gap', 'collection_loss',
  'sensor_unhealthy', 'collection_unavailable', 'monitor_storage']);
const severeReasons = new Set(['signer_changed_access', 'signer_changed', 'protected_installation', 'log_integrity', 'retention_gap']);

const sensitiveKinds = {
  keyboard_observer_active: 'keyboard', keyboard_observer_changed: 'keyboard',
  hid_access_active: 'hid', screen_started: 'screen',
  screen_capture_client_connected: 'captureClient',
  microphone_started: 'audio', audio_input_started: 'audio',
  system_audio_started: 'audio', camera_started: 'camera'
};

// Paths whose contents start programs at login or boot.
const autostartRoots = ['/Library/LaunchAgents/', '/Library/LaunchDaemons/', '/Library/PrivilegedHelperTools/'];
export const autostartPath = path => autostartRoots.some(root => path.startsWith(root)) || /^\/Users\/[^/]+\/Library\/LaunchAgents\//.test(path);
// The collector's own items change only through an administrator-authorized
// installation, which the protected-installation check covers.
export const ownAutostart = path => /^\/Library\/(?:LaunchDaemons\/local\.activity-observer\.(?:guard|capture)\.plist|LaunchAgents\/local\.activity-observer\.sensor\.plist|PrivilegedHelperTools\/local\.activity-observer)$/.test(path) ||
  /^\/Users\/[^/]+\/Library\/LaunchAgents\/local\.activity-observer\.(?:mcp|incidents)\.plist$/.test(path);
// Sealed system locations cannot gain a new executable without an OS update.
const platformPath = path => /^\/(?:System|usr\/(?:bin|sbin|libexec|lib)|bin|sbin)\//.test(path);
export const temporaryPath = path => /^\/(?:private\/)?(?:tmp|var\/tmp|var\/folders)\//.test(path) || /^\/Users\/(?:Shared\/|[^/]+\/Downloads\/)/.test(path);

const key = (...parts) => createHash('sha256').update(JSON.stringify(parts)).digest('hex');
export const incidentKey = key;
const bundlePath = path => path.match(/^.*?\.app(?=\/|$)/)?.[0] ?? path;
const sameTime = (a, b, span = windowSeconds) => Math.abs(a - b) <= span;

export function externalAddress(remote) {
  if (typeof remote !== 'string') return null;
  const separator = remote.lastIndexOf(':');
  if (separator < 1) return null;
  const port = Number(remote.slice(separator + 1));
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  const ip = remote.slice(0, separator).replace(/^\[|\]$/g, '').toLowerCase();
  if (isIP(ip) === 6) return /^[23]/.test(ip) && !ip.startsWith('2001:db8:') ? ip : null;
  if (isIP(ip) !== 4) return null;
  const [a, b, c] = ip.split('.').map(Number);
  if (a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 192 && b === 0 && c <= 2) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
      (a === 203 && b === 0 && c === 113)) return null;
  return ip;
}

function changedProgram(row, detail, ref) {
  const before = detail.previous, current = detail.current;
  if (!current) return null;
  const bytesChanged=['code_directory_fingerprint','sha256'].some(name=>
    current[name] && before?.[name] && current[name]!==before[name]);
  const signerChanged = Boolean(before?.team_id && (current.team_id || current.code_directory_fingerprint || current.sha256) && before.team_id !== current.team_id);
  const changed = row.kind === 'program_installed' || row.kind === 'program_version_observed' ||
    (row.kind === 'program_files_changed' && detail.changed_paths?.length > 0) || signerChanged ||
    bytesChanged ||
    (current.version && before?.version && current.version !== before.version) ||
    (current.build && before?.build && current.build !== before.build);
  return changed ? { at: row.last, ref, signerChanged } : null;
}

const snapshot = incident => ({
  revision: incident.revision, severity: incident.severity, reasons: incident.reasons, evidence: incident.evidence,
  ...(incident.coverageGap && { coverageGap: incident.coverageGap })
});

export function incidentAlertRevision(incident) {
  return incident.alertRevision ?? incident.revision;
}

function report(state, actor, reason, at, evidence, urgent = false) {
  let incident = state.incidents[state.active[actor]];
  if (!incident || at - incident.updatedAt > incidentLifetime) {
    const id = key(actor, evidence[0]?.id ?? at).slice(0, 24);
    incident = state.incidents[id] ?? { id, reasons: [], severity: 0, revision: 0, evidence: [], createdAt: at };
    state.incidents[id] = incident;
    state.active[actor] = id;
  }
  const reasons = incident.reasons.includes(reason) ? incident.reasons : [...incident.reasons, reason];
  const severity = reasons.length > 1 || urgent || severeReasons.has(reason) ? 3 : 2;
  const escalated = severity > incident.severity;
  const refs = [...incident.evidence];
  for (const ref of evidence) {
    if (!refs.some(item => item.id === ref.id) && refs.length < 12) refs.push(ref);
  }
  if (escalated || reasons !== incident.reasons || refs.length !== incident.evidence.length) {
    const alertRevision = incidentAlertRevision(incident);
    if (incident.revision) {
      incident.revisions ??= {};
      if (incident.previous) {
        incident.revisions[incident.previous.revision] ??= incident.previous;
        delete incident.previous;
      }
      incident.revisions[incident.revision] = snapshot(incident);
    }
    incident.revision++;
    incident.alertRevision = escalated ? incident.revision : alertRevision;
    incident.reasons = reasons;
    incident.severity = Math.max(severity, incident.severity);
    incident.evidence = refs;
  }
  incident.updatedAt = Math.max(incident.updatedAt ?? 0, at);
  return incident;
}

export function recordRetentionGap(state, after, boundary, now) {
  const incident = report(state, key('retention', after, boundary.id, boundary.hash), 'retention_gap', now, []);
  incident.coverageGap ??= { after, through: boundary.id };
}

function checkChangedAccess(state, actor, program, change, access, emit) {
  if (access.kind === 'captureClient' || access.at < change.at || access.at - change.at > day) return;
  if (change.signerChanged) {
    if (change.signerSeen) return;
    change.signerSeen = true;
    if (emit) report(state, actor, 'signer_changed_access', access.at, [change.ref, access.ref]);
    return;
  }
  change.reported ??= [];
  if (program.seen[access.kind] < change.at || change.known?.includes(access.kind) || change.reported.includes(access.kind)) return;
  // An earlier access can be in a later ID page. Do not commit a verdict
  // until the complete signed scan interval has updated the earliest access.
  if (!access.expected) {
    state.pendingChangeAccess ??= {};
    const candidateKey=key(actor,change.ref.id,access.kind);
    state.pendingChangeAccess[candidateKey]={actor,change,access};
    if(Object.keys(state.pendingChangeAccess).length>2048)throw Error('Incident candidate capacity exceeded');
  }
}

// Baseline rules report only after the first day of observation. A state
// saved by an earlier version has no start time and has already learned.
const learned = (state, at) => state.observedSince === undefined ||
  (state.observedSince !== null && at - state.observedSince >= learningPeriod);

function reportIntroduction(state, actor, program, emit) {
  const { introduced, external } = program;
  if (!introduced || !external || introduced.reported || external.at < introduced.at - 2 * minute ||
      external.at - introduced.at > introductionWindow) return;
  introduced.reported = true;
  if (emit && learned(state, external.at)) {
    report(state, actor, 'new_program_network', external.at, [introduced.ref, external.ref], introduced.unsigned || introduced.temporary);
  }
}

// Returns true when the stored settings digest changed.
export function recordSettingsChange(state, digest, now) {
  const known = state.settingsDigest;
  if (known === digest) return false;
  state.settingsDigest = digest;
  // The first scan after an upgrade records the current settings silently.
  if (known !== undefined) report(state, key('settings', now), 'settings_changed', now, []);
  return true;
}

// Returns true when a waiting file-watch gap was resolved into an incident.
export function settlePendingGaps(state, now, emit = true) {
  const waiting=[];
  let reported=false;
  for(const gap of state.pendingGaps ?? []) {
    if(now-gap.at<gapGrace) waiting.push(gap);
    else if(emit) { report(state,key('collection-gap',gap.source),'collection_gap',gap.at,[gap.ref]); reported=true; }
  }
  if(waiting.length) state.pendingGaps=waiting; else delete state.pendingGaps;
  return reported;
}

export function finalizeIncidentObservations(state, emit=true, now=Infinity) {
  settlePendingGaps(state, now, emit);
  const candidates=Object.values(state.pendingChangeAccess ?? {});
  delete state.pendingChangeAccess;
  for(const {actor,change,access} of candidates) {
    const program=state.programs[actor];
    if(!program || program.seen[access.kind]<change.at || change.known?.includes(access.kind) || change.reported?.includes(access.kind))continue;
    (change.reported ??= []).push(access.kind);
    if(emit)report(state,actor,'changed_program_access',access.at,[change.ref,access.ref]);
  }
}

export function recordIncidentFault(state, reason, now, immediate = false) {
  if (!reason) { delete state.fault; return; }
  if (state.fault?.reason !== reason) {
    const availability=['sensor_unhealthy','collection_unavailable'];
    const continuing=availability.includes(reason)&&availability.includes(state.fault?.reason);
    state.fault=continuing ? {...state.fault,reason} : {reason,since:now};
  }
  if (!state.fault.raised && (immediate || now - state.fault.since >= 60)) {
    report(state, key('health', reason, state.fault.since), reason, now, []);
    state.fault.raised = true;
  }
}

export function collectionLossCount(row, sensorPid) {
  if(!Number.isSafeInteger(sensorPid)||sensorPid<=0||row.pid!==sensorPid)return 0;
  const detail=JSON.parse(row.detail);
  const n=row.kind==='sensor_transport_gap' ? Number(detail.received_sequence)-Number(detail.expected_sequence) :
    Number(detail.queue_dropped ?? detail.ingress_dropped ?? detail.paths ?? 0);
  const count=n*Number(row.count ?? 1);
  return Number.isSafeInteger(count)&&count>0?count:0;
}

export function recordCollectionHealth(state, { healthy, dropDelta, gapCount, sensorPid }, now) {
  recordIncidentFault(state, healthy ? null : 'sensor_unhealthy', now);
  // Events and sensor metrics arrive separately. Match quantified loss across
  // scans in either order, without hiding an unrelated increase in the counter.
  const old=state.lossAccounting;
  const recent=old?.pid===sensorPid && now-old.at<=5*minute;
  let credit=recent?old.credit:0,debt=recent?old.debt:0;
  const delayed=Math.min(debt,gapCount);debt-=delayed;credit+=gapCount-delayed;
  const covered=Math.min(credit,dropDelta);credit-=covered;
  const unmatched=dropDelta-covered;debt+=unmatched;
  if(credit||debt)state.lossAccounting={pid:sensorPid,credit,debt,at:dropDelta||gapCount?now:old.at,
    ...(recent&&old.incidentId&&{incidentId:old.incidentId})};
  else delete state.lossAccounting;
  if(unmatched>0)state.lossAccounting.incidentId=report(state,key('collection-loss'),'collection_loss',now,[]).id;
}

export function newIncidentState() {
  return { schema: 1, networkAttribution: 2, observedSince: null, programs: {}, destinations: {}, active: {}, incidents: {} };
}

export function upgradeNetworkAttribution(state) {
  if(state.networkAttribution===2)return;
  // Preserve verified connections and all past incidents. Old app-wide byte
  // peaks cannot be used as an executable-specific baseline after the upgrade.
  for(const flow of Object.values(state.destinations)){
    flow.bytes=flow.peak=0;flow.from=flow.last;delete flow.unusual;
  }
  for(const program of Object.values(state.programs)){delete program.send;delete program.sendByPath;}
  state.networkAttribution=2;
}

// options.expectedAccess lists the owner's allowances from settings.json.
export function observeIncidentRow(state, row, segment, emit = true, options = {}) {
  if (state.observedSince === null && Number.isFinite(row.last)) state.observedSince = row.last;
  if (['collection_gap', 'sensor_transport_gap'].includes(row.kind) && Number.isFinite(row.last)) {
    if (emit) {
      const loss=state.lossAccounting;
      const count=loss?collectionLossCount(row,loss.pid):0;
      const available=loss?Math.max(0,loss.debt-(loss.claimed??0)):0;
      const eligible=available>0 && Math.abs(row.last-loss.at)<=5*minute && state.incidents[loss.incidentId] && count>0;
      const delayed=eligible && count<=available;
      if(eligible)loss.claimed=(loss.claimed??0)+Math.min(available,count);
      const ref={id:row.id,hash:row.chain_hash,segment:{anchor:segment.anchor,after:row.id-1,previousHash:row.chain_prev}};
      if(!delayed && row.kind==='collection_gap' && row.source==='fsevents') {
        // Wait for the collector's recheck of known paths before alerting.
        state.pendingGaps ??= [];
        if(state.pendingGaps.length<32)state.pendingGaps.push({at:row.last,source:row.source,ref});
      } else report(state,delayed?key('collection-loss'):key('collection-gap',row.source),
        delayed?'collection_loss':'collection_gap',row.last,[ref]);
    }
    return;
  }
  if (row.kind === 'filesystem_inventory_reconciled' && Number.isFinite(row.last) && state.pendingGaps) {
    let detail = {};
    try { detail = JSON.parse(row.detail) ?? {}; } catch { /* An unreadable recheck repairs nothing. */ }
    if (detail.status === 'completed') {
      state.pendingGaps = state.pendingGaps.filter(gap => gap.at > row.last);
      if (!state.pendingGaps.length) delete state.pendingGaps;
    }
    return;
  }
  if (row.kind === 'sensitive_file_changed' && typeof row.path === 'string' && Number.isFinite(row.last)) {
    if (emit) report(state, key('sensitive-file', row.path), 'sensitive_file_changed', row.last,
      [{ id: row.id, hash: row.chain_hash, segment: { anchor: segment.anchor, after: row.id - 1, previousHash: row.chain_prev } }]);
    return;
  }
  if (typeof row.app !== 'string' || typeof row.path !== 'string' || !row.path.startsWith('/') ||
      !Number.isFinite(row.last)) return;
  const sensitivity = sensitiveKinds[row.kind];
  const programChange = ['program_installed', 'program_updated', 'program_version_observed', 'program_files_changed'].includes(row.kind);
  // The collector writes no event for files that were present at its baseline,
  // so a first observation here is a file that appeared or first ran later.
  const introduction = row.kind === 'program_first_seen' || row.kind === 'program_installed';
  const network = ['network_open', 'network_actor_resolved', 'network_bytes'].includes(row.kind);
  if (!sensitivity && !programChange && !introduction && !network) return;

  const path = bundlePath(row.path);
  const actor = key(row.app, path);
  const program = state.programs[actor] ??= { seen: {} };
  const ref = { id: row.id, hash: row.chain_hash,
    segment: { anchor: segment.anchor, after: row.id - 1, previousHash: row.chain_prev } };
  const at = row.last;
  program.last = Math.max(program.last ?? 0, at);
  if (programChange || introduction) {
    const detail = JSON.parse(row.detail);
    if (emit && autostartPath(row.path) && !ownAutostart(row.path) &&
        (row.kind !== 'program_files_changed' || detail.changed_paths?.length > 0)) {
      report(state, key('autostart', row.path), 'autostart_changed', at, [ref]);
    }
    if (introduction && !platformPath(row.path)) {
      const current = detail.current ?? {};
      program.introduced = { at, ref, unsigned: !current.team_id && !current.signing_identifier, temporary: temporaryPath(row.path) };
      reportIntroduction(state, actor, program, emit);
    }
    if (!programChange) return;
    const change = changedProgram(row, detail, ref);
    if (!change) return;
    if (change.signerChanged && emit) report(state, actor, 'signer_changed', at, [ref]);
    const changes = program.changes ??= program.change ? [program.change] : [];
    delete program.change;
    changes.push(change);
    changes.sort((a, b) => b.at - a.at || b.ref.id - a.ref.id);
    if (changes.length > 8) changes.length = 8;
    for (const access of Object.values(program.accessByKind ?? {})) {
      if (changes.find(item => item.at <= access.at) === change) checkChangedAccess(state, actor, program, change, access, emit);
    }
    return;
  }
  if (sensitivity) {
    const change = program.changes?.find(item => item.at <= at) ?? program.change;
    // An allowance applies only to the change-plus-access rule. An unusual send
    // or a changed signing identity still raises an incident for the same app.
    const expected = (options.expectedAccess ?? []).some(entry => row.app === entry.app && path === entry.path && entry.access.includes(sensitivity));
    program.seen[sensitivity] = Math.min(program.seen[sensitivity] ?? at, row.first ?? at);
    const access = { at, ref, kind: sensitivity, expected, path: row.path };
    program.accessByKind ??= {};
    if (!program.accessByKind[sensitivity] || at >= program.accessByKind[sensitivity].at) program.accessByKind[sensitivity] = access;
    program.accessByPath ??= {};
    const pathAccess=program.accessByPath[row.path] ??= {};
    if(!pathAccess[sensitivity] || at>=pathAccess[sensitivity].at)pathAccess[sensitivity]=access;
    if (change) checkChangedAccess(state, actor, program, change, access, emit);
    if (!program.access || at >= program.access.at) program.access = access;
    const send = program.sendByPath?.[row.path] ?? program.send;
    if (emit && send && send.path === row.path && sameTime(at, send.at)) {
      report(state, actor, 'sensitive_external_send', Math.max(at, send.at), [ref, send.open, send.ref]);
    }
    return;
  }

  const detail = JSON.parse(row.detail);
  // Legacy app-wide totals cannot establish which executable sent the bytes.
  if(row.kind==='network_bytes' && detail.aggregated_by_application && !detail.aggregated_by_executable)return;
  const ip = externalAddress(detail.remote);
  if (!ip || !['tcp', 'udp'].includes(detail.protocol)) return;
  const destination = key(row.app, row.path, detail.protocol, ip);
  const flow = state.destinations[destination] ??= { first: at, last: at, from: at, bytes: 0, peak: 0 };
  flow.last = Math.max(flow.last, at);
  if (row.kind !== 'network_bytes') {
    if (!flow.open || at >= flow.open.at) flow.open = { at, ref };
    // The connection can be recorded just before the executable's discovery.
    if (!program.external || at >= program.external.at) program.external = { at, ref };
    reportIntroduction(state, actor, program, emit);
    if (flow.unusual && sameTime(flow.unusual.at, at, 15 * minute)) {
      correlateSend(state, actor, program, row.path, flow.unusual, flow.open, emit);
    }
    return;
  }
  const bytes = Number(detail.tx_delta) * row.count;
  if (!Number.isSafeInteger(bytes) || bytes <= 0 || at < flow.from) return;
  if (at - flow.from >= windowSeconds) {
    flow.peak = Math.max(flow.peak, flow.bytes);
    flow.from = at;
    flow.bytes = 0;
  }
  flow.bytes += bytes;
  const fresh = at - flow.first <= newDestinationAge && flow.bytes >= newDestinationBytes;
  const unusual = fresh || (flow.peak > 0 && flow.bytes >= Math.max(unusualBytes, flow.peak * 4));
  // Executable-level totals require a matching flow, without attributing them
  // to one PID. Legacy app-wide totals are excluded above.
  if (!unusual) return;
  flow.unusual = { at, ref };
  if (fresh && !flow.newSend) {
    flow.newSend = at;
    const recent = (program.newSends ?? []).filter(time => at - time <= habitWindow);
    program.newSends = [...recent, at].slice(-8);
    if (emit && recent.length < habitualSends && learned(state, at)) {
      report(state, actor, 'new_destination_send', at, [flow.open?.ref, ref].filter(Boolean));
    }
  }
  if (flow.open && sameTime(at, flow.open.at, 15 * minute)) correlateSend(state, actor, program, row.path, flow.unusual, flow.open, emit);
}

function correlateSend(state, actor, program, path, send, open, emit) {
  const { at, ref } = send;
  program.send = { at, ref, path, open: open.ref };
  (program.sendByPath ??= {})[path]=program.send;
  const access = Object.values(program.accessByPath?.[path] ?? {}).find(item=>sameTime(at,item.at)) ??
    Object.values(program.accessByKind ?? {}).find(item => item.path === path && sameTime(at, item.at)) ?? program.access;
  if (emit && access?.path === path && sameTime(at, access.at)) {
    report(state, actor, 'sensitive_external_send', Math.max(at, access.at), [access.ref, open.ref, ref]);
  }
}

export function trimIncidentState(state, now) {
  function keepRecent(table, oldest, limit) {
    const recent = Object.entries(table).filter(([, v]) => v.last >= oldest);
    recent.sort((a, b) => b[1].last - a[1].last);
    return Object.fromEntries(recent.slice(0, limit));
  }
  state.programs = keepRecent(state.programs, now - 7 * day, 1024);
  state.destinations = keepRecent(state.destinations, now - 7 * day, 8192);
  for(const program of Object.values(state.programs)){
    for(const [path,accesses] of Object.entries(program.accessByPath ?? {})){
      for(const [kind,access] of Object.entries(accesses))if(access.at<now-15*minute)delete accesses[kind];
      if(!Object.keys(accesses).length)delete program.accessByPath[path];
    }
    for(const [path,send] of Object.entries(program.sendByPath ?? {}))if(send.at<now-15*minute)delete program.sendByPath[path];
  }
  for (const [actor, id] of Object.entries(state.active)) {
    if (now - state.incidents[id]?.updatedAt > incidentLifetime) delete state.active[actor];
  }
  for (const [id, incident] of Object.entries(state.incidents)) {
    if (incident.delivery?.revision === incidentAlertRevision(incident) && now - incident.updatedAt > 30 * day) delete state.incidents[id];
  }
}
