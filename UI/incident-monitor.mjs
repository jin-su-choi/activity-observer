import { execFileSync, spawn } from 'node:child_process';
import { lstatSync, mkdirSync, readFileSync, realpathSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, isAbsolute, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { serverI18n } from './i18n-server.mjs';
import { fileURLToPath } from 'node:url';
import { checkMcpIsolation, readCurrentRetentionBoundary, readIncidentContext, readLogStart, readRetentionBoundary } from './build-widget.mjs';
import { incidentIdPattern, incidentDir, readIncidentState, readIncidentView, readIncidentScanStatus,
  saveIncidentState, saveIncidentScanStatus, verifiedRows } from './incident-store.mjs';
import { finalizeIncidentObservations, incidentAlertRevision, incidentReasonCodes, newIncidentState, observeIncidentRow, recordIncidentFault, recordCollectionHealth, collectionLossCount, recordRetentionGap, recordSettingsChange, settlePendingGaps, trimIncidentState, upgradeNetworkAttribution } from './incident-rules.mjs';
import { readSettings } from './settings.mjs';

const script = fileURLToPath(import.meta.url);
const localPolicy = resolve(dirname(script), 'incident.sb');
const configPath = resolve(incidentDir, 'target.json');
const codexSocket = resolve(homedir(), '.codex/app-server-control/app-server-control.sock');
const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const now = () => Math.floor(Date.now() / 1000);
// macOS returns decomposed names for paths that a user typed composed.
const samePath = (a, b) => a.normalize('NFC') === b.normalize('NFC');
const requiredSensors = ['guard_sensor_liveness', 'guard_capture_feed', 'guard_network_isolation', 'sensor_network_isolation',
  'network', 'install_update', 'input_taps', 'hid', 'capture', 'audio'];

function head(anchor) {
  return { after: anchor.payload.head_id, previousHash: anchor.payload.head_hash };
}

function consume(state, anchor, start, emit, pageReader, sensorPid, live = false) {
  upgradeNetworkAttribution(state);
  const range = { ...start, anchor };
  const options = { expectedAccess: readSettings().expectedAccess };
  let gapCount=0;
  verifiedRows(range, row => {
    if(['collection_gap','sensor_transport_gap'].includes(row.kind))gapCount+=collectionLossCount(row,sensorPid);
    observeIncidentRow(state, row, range, emit, options);
  }, pageReader);
  // A replay judges every gap. A live scan lets recent ones wait for a recheck.
  finalizeIncidentObservations(state,emit,live?anchor.payload.created_at:Infinity);
  state.cursor = anchor;
  trimIncidentState(state, anchor.payload.created_at);
  return gapCount;
}

function faultCode(error) {
  if (/Unapproved observer artifact|Operational key mismatch|ENOENT.*(PrivilegedHelperTools|ActivityObserver)/.test(error.message)) {
    return 'protected_installation';
  }
  if (/hash|signature|anchor|proof|evidence/i.test(error.message) && !/^Read failed:/.test(error.message)) return 'log_integrity';
  return 'collection_unavailable';
}

function scan() {
  const saved = readIncidentState(incidentDir, false);
  let state = saved ?? newIncidentState();
  const previous = state.cursor?.payload;
  const oldFault = JSON.stringify(state.fault);
  const oldCollection = state.collection;
  let collection, changed = false;
  try {
    const source = readIncidentContext();
    const { status } = source;
    const dropDelta = Math.max(0,status.dropped_events-(oldCollection?.dropped ?? status.dropped_events));
    const sensorPid=status.sensors?.guard_sensor_metrics?.pid;
    const healthy = status.collector_running && status.sensors?.storage?.status !== 'degraded' &&
      requiredSensors.every(name => status.sensors?.[name]?.status === 'active');
    // Counter changes can precede the cached anchor. Flush a fresh signed
    // upper bound so a pending gap event is read before deciding on a fallback.
    let anchor = source.anchor(dropDelta>0);
    let gapCount=0;
    const boundary = status.boundary_id !== undefined ? readRetentionBoundary(status) : null;
    if (boundary?.id > anchor.payload.head_id) anchor = source.anchor(true);
    if (previous?.head_id !== anchor.payload.head_id || previous?.head_hash !== anchor.payload.head_hash) {
      if (!previous) throw Error('Missing verified incident cursor; seed from the last completed review');
      if (previous.head_id > anchor.payload.head_id || (previous.head_id === anchor.payload.head_id && previous.head_hash !== anchor.payload.head_hash)) {
        throw Error('Current anchor regressed or differs from the verified incident cursor');
      }
      state = readIncidentState() ?? state;
      if (state.cursor.key_fingerprint !== anchor.key_fingerprint) throw Error('Incident cursor key does not match the current anchor');
      source.verifyAnchor(state.cursor);
      const start = head(state.cursor);
      let retained = boundary?.id > start.after ? boundary : null;
      if (!retained) {
        try {
          gapCount=consume(state, anchor, start, true, source.page,sensorPid,true);
        } catch (error) {
          if (!/hash|incomplete|missing/i.test(error.message) || (!boundary && !status.pruned_rows)) throw error;
          retained = boundary ? readCurrentRetentionBoundary() : readRetentionBoundary(status);
          if (retained.id <= start.after) throw error;
          state = readIncidentState();
        }
      }
      if (retained) {
        if (retained.id > anchor.payload.head_id) anchor = source.anchor(true);
        if (retained.id > anchor.payload.head_id) throw Error('Signed retention boundary exceeds the current anchor');
        recordRetentionGap(state, start.after, retained, now());
        // Correlations across missing records cannot establish first access or
        // a destination baseline. Keep the incidents and rebuild rule history.
        state.programs = {};
        state.destinations = {};
        state.active = {};
        state.observedSince = null;
        gapCount=consume(state, anchor, { after: retained.id, previousHash: retained.hash }, true, source.page,sensorPid,true);
      }
    }
    if (settlePendingGaps(state, now())) changed = true;
    if (recordSettingsChange(state, readSettings().digest, now())) changed = true;
    recordCollectionHealth(state,{healthy,dropDelta,gapCount,sensorPid},now());
    collection = { healthy: Boolean(healthy), heartbeat: status.heartbeat, dropped: status.dropped_events,
      sensorDropped: status.sensors?.guard_sensor_metrics?.dropped, pruned: status.pruned_rows };
  } catch (error) {
    // A partial scan never commits a new position or a rule result.
    state = readIncidentState(incidentDir, false) ?? newIncidentState();
    const reason = faultCode(error);
    recordIncidentFault(state, reason, now(), reason !== 'collection_unavailable');
    // An unavailable read is not a new counter baseline. Preserve the last
    // successful values so delayed metrics cannot leave stale loss credit.
    collection = { ...oldCollection, healthy: reason === 'collection_unavailable' ? null : false };
  }
  const lastScan = now();
  if (!saved || changed || state.cursor?.payload.head_hash !== previous?.head_hash ||
      JSON.stringify(state.fault) !== oldFault ||
      ['healthy', 'dropped', 'sensorDropped', 'pruned'].some(key => collection[key] !== oldCollection?.[key])) {
    state.lastScan = lastScan;
    state.collection = collection;
    saveIncidentState(state);
  }
  saveIncidentScanStatus({ lastScan, collection });
  const needsDelivery = Object.values(state.incidents).some(item =>
    (item.notified ?? 0) < incidentAlertRevision(item) ||
    (item.delivery?.revision ?? 0) < incidentAlertRevision(item) && lastScan >= (item.nextAttempt ?? 0) &&
      lastScan - (state.lastDispatch ?? 0) >= 60);
  console.log(needsDelivery ? 'deliver' : 'idle');
}

function checkedTarget(target) {
  if (!['codex', 'claude'].includes(target?.agent) || !uuid.test(target.sessionId) ||
      !isAbsolute(target.command) || !isAbsolute(target.project)) throw Error('Invalid incident target');
  if (!lstatSync(target.project).isDirectory() || !samePath(realpathSync(target.project), target.project) ||
      !lstatSync(realpathSync(target.command)).isFile()) throw Error('Incident target paths are unavailable');
  if (target.agent === 'claude' && (!isAbsolute(target.transcript) || basename(target.transcript) !== target.sessionId + '.jsonl')) {
    throw Error('A Claude transcript path matching the session UUID is required');
  }
  return target;
}

async function codexProject(target) {
  const child = spawn(target.command, ['app-server', '--listen', 'stdio://'], {
    cwd: target.project, stdio: ['pipe', 'pipe', 'ignore']
  });
  const lines = createInterface({ input: child.stdout });
  try {
    return await new Promise((resolve, reject) => {
      const send = message => child.stdin.write(JSON.stringify(message) + '\n');
      const timeout = setTimeout(() => reject(Error('Codex thread lookup timed out')), 8000);
      const fail = error => { clearTimeout(timeout); reject(error); };
      child.once('error', fail);
      child.stdin.on('error', fail);
      child.once('exit', () => fail(Error('Codex thread lookup exited')));
      lines.on('line', line => {
        let response;
        try { response = JSON.parse(line); } catch { return; }
        if (response.id === 1 && response.result) {
          send({ method: 'initialized' });
          send({ id: 2, method: 'thread/read', params: { threadId: target.sessionId, includeTurns: false } });
        } else if (response.id === 1 && response.error) {
          fail(Error('Codex thread lookup could not initialize'));
        } else if (response.id === 2) {
          clearTimeout(timeout);
          const thread = response.result?.thread;
          if (thread?.id !== target.sessionId || !thread.cwd) return reject(Error('Codex thread was not found'));
          resolve(thread.cwd);
        }
      });
      send({ id: 1, method: 'initialize', params: { clientInfo: { name: 'activity-observer-incidents', version: '1.0' } } });
    });
  } finally {
    lines.close();
    child.kill();
  }
}

async function claudeProject(target) {
  const { createReadStream } = await import('node:fs');
  const lines = createInterface({ input: createReadStream(target.transcript) });
  let project;
  for await (const line of lines) {
    try {
      const record = JSON.parse(line);
      if (record.sessionId === target.sessionId && typeof record.cwd === 'string') project = record.cwd;
    } catch { /* Ignore incomplete transcript records. */ }
  }
  return project;
}

async function verifyTarget(target) {
  checkedTarget(target);
  const workspace = await (target.agent === 'codex' ? codexProject(target) : claudeProject(target));
  if (!workspace || !samePath(realpathSync(workspace), target.project)) throw Error('Session workspace does not match the configured project');
}

function canResumeCodex() {
  try {
    const path = realpathSync(codexSocket);
    const socket = lstatSync(path), directory = lstatSync(dirname(path));
    return socket.isSocket() && socket.uid === process.getuid() &&
      directory.uid === process.getuid() && !(directory.mode & 0o077);
  } catch { return false; }
}

function send(target, incident) {
  if (!incidentIdPattern.test(incident.id) || !Number.isSafeInteger(incident.revision) || incident.revision < 1) {
    throw Error('Invalid incident reference');
  }
  if (target.agent === 'codex' && !canResumeCodex()) {
    try {
      execFileSync(target.command, ['app-server', 'daemon', 'start'], { timeout: 30000, stdio: 'ignore' });
    } catch { /* The native queue can persist the alert until Codex resumes. */ }
  }
  // The alert is written in the macOS language at the time it is sent.
  const message = serverI18n().s('alert.prompt', { id: incident.id, revision: incident.revision });
  const resume = target.agent === 'codex' && canResumeCodex();
  const args = target.agent === 'codex'
    ? ['queue', '--thread', target.sessionId, '--message', message, ...(resume ? ['--resume'] : [])]
    : ['--bg', '--resume', target.transcript, message];
  execFileSync(target.command, args, {
    cwd: target.project, timeout: 90000, stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 1024 * 1024
  });
  return target.agent === 'codex' ? (resume ? 'queued_resume_requested' : 'queued') : 'dispatched';
}

function notify(incident) {
  const code = incident.reasons.at(-1);
  const reason = serverI18n().reason(incidentReasonCodes.has(code) ? code : 'monitor_storage');
  try {
    execFileSync('/usr/bin/osascript', ['-e', 'on run argv', '-e',
      'display notification (item 1 of argv) with title "Activity Observer"', '-e', 'end run',
      '--', `${reason} · ${incident.id.slice(0, 8)}`], { timeout: 5000, stdio: 'ignore' });
  } catch { /* The durable incident remains available without notification permissions. */ }
}

function runScanner(args, timeout) {
  return execFileSync('/usr/bin/sandbox-exec', ['-f', localPolicy, process.execPath, script, ...args], {
    timeout, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe']
  });
}

async function deliver() {
  const state = readIncidentState(incidentDir, false);
  if (!state) return;
  const incidents = Object.values(state.incidents).sort((a, b) => b.severity - a.severity || a.createdAt - b.createdAt);
  const notices = incidents.filter(item => (item.notified ?? 0) < incidentAlertRevision(item)).slice(0, 3);
  if (notices.length) {
    for (const item of notices) item.notified = incidentAlertRevision(item);
    saveIncidentState(state);
    for (const item of notices) notify(item);
  }
  if (now() - (state.lastDispatch ?? 0) < 60) return;
  const incident = incidents.find(item => (item.delivery?.revision ?? 0) < incidentAlertRevision(item) && now() >= (item.nextAttempt ?? 0));
  if (!incident) return;
  const revision = incidentAlertRevision(incident);
  const alert = revision === incident.revision ? incident : { ...incident, ...incident.revisions[revision] };
  let target;
  try {
    const info = lstatSync(configPath);
    if (!info.isFile() || info.uid !== process.getuid() || (info.mode & 0o077)) throw Error('Invalid target file');
    target = JSON.parse(readFileSync(configPath, 'utf8'));
    await verifyTarget(target);
  } catch (error) {
    if (error.code !== 'ENOENT') {
      incident.nextAttempt = now() + 120;
      state.deliveryIssue = 'target_unavailable';
      saveIncidentState(state);
    }
    return;
  }
  if (alert.evidence.length) {
    try { runScanner(['check-incident', incident.id, String(revision)], 120000); }
    catch {
      incident.nextAttempt = now() + 120;
      state.deliveryIssue = 'evidence_unavailable';
      saveIncidentState(state);
      return;
    }
  }
  state.lastDispatch = now();
  incident.delivery = { revision, status: 'uncertain', at: now() };
  saveIncidentState(state);
  try {
    incident.delivery.status = send(target, alert);
    delete state.deliveryIssue;
  } catch (error) {
    // A killed or timed-out provider may already have accepted the message.
    // Preserve that ambiguity instead of duplicating an automatic agent turn.
    if (error.code === 'ENOENT' || error.code === 'EACCES' ||
        /no conversation found|not sent|could not find.*session/i.test(String(error.stderr ?? ''))) {
      delete incident.delivery;
      incident.nextAttempt = now() + 120;
      state.deliveryIssue = 'agent_unavailable';
    } else {
      state.deliveryIssue = 'delivery_uncertain';
    }
  }
  saveIncidentState(state);
}

async function run() {
  let outcome;
  try {
    outcome = runScanner(['scan'], 150000).trim();
  } catch {
    notify({ id: 'storage', reasons: ['monitor_storage'] });
    throw Error('Incident scan could not save its state');
  }
  if (outcome === 'deliver') await deliver();
}

const [command, ...args] = process.argv.slice(2);
try {
  if (command === 'scan' && !args.length) scan();
  else if (command === 'run' && !args.length) await run();
  else if (command === 'deliver' && !args.length) await deliver();
  else if (command === 'scan-failed' && !args.length) {
    notify({ id: 'storage', reasons: ['monitor_storage'] });
    throw Error('Incident scan could not save its state');
  }
  else if (command === 'check-incident' && args.length === 2) {
    if (!readIncidentView(args[0], Number(args[1])).verified) throw Error('Incident evidence is unavailable');
  }
  else if (command === 'isolation-check' && !args.length) {
    checkMcpIsolation();
    console.log('Collector reachable under the local incident policy.');
  } else if ((command === 'seed' || command === 'replay') && args.length <= 3) {
    if (command === 'seed' && readIncidentState()) throw Error('Incident state already exists');
    // Without a position, start where the retained log begins.
    if (args.length < 2) { const start = readLogStart(); args.splice(0, args.length, String(start.after), start.previousHash); }
    const [startId, previousHash, anchorFile] = args;
    const source = readIncidentContext();
    const anchor = anchorFile ? JSON.parse(readFileSync(anchorFile, 'utf8')) : source.anchor();
    if (anchorFile) source.verifyAnchor(anchor);
    const state = newIncidentState();
    consume(state, anchor, { after: Number(startId), previousHash }, command === 'replay', source.page);
    if (command === 'seed') { state.settingsDigest = readSettings().digest; saveIncidentState(state); }
    console.log(JSON.stringify({ through: anchor.payload.head_id, events: anchor.payload.head_id - Number(startId),
      incidents: Object.values(state.incidents).map(({ id, severity, reasons }) => ({ id, severity, reasons })) }));
  } else if (['configure', 'retarget'].includes(command) && [4, 5].includes(args.length)) {
    // configure sets the first alert target. retarget replaces it.
    const [agent, executable, project, sessionId, transcript] = args;
    const target = { agent, command: realpathSync(executable), project: realpathSync(project), sessionId, transcript };
    await verifyTarget(target);
    mkdirSync(incidentDir, { recursive: true, mode: 0o700 });
    if (command === 'configure') writeFileSync(configPath, JSON.stringify(target) + '\n', { flag: 'wx', mode: 0o600 });
    else {
      const temporary = configPath + '.' + process.pid + '.tmp';
      writeFileSync(temporary, JSON.stringify(target) + '\n', { flag: 'wx', mode: 0o600 });
      renameSync(temporary, configPath);
    }
    console.log(JSON.stringify({ agent, sessionId, project: target.project }));
  } else if (command === 'target' && !args.length) {
    let target = null;
    try { target = JSON.parse(readFileSync(configPath, 'utf8')); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    console.log(JSON.stringify(target && { agent: target.agent, sessionId: target.sessionId, project: target.project }));
  } else if (command === 'status' && !args.length) {
    const state = readIncidentState(incidentDir, false);
    const scan = readIncidentScanStatus();
    const current = scan && scan.lastScan >= (state?.lastScan ?? 0) ? scan : state;
    console.log(JSON.stringify(state && { lastScan: current?.lastScan, through: state.cursor?.payload.head_id, collection: current?.collection,
      deliveryIssue: state.deliveryIssue, incidents: Object.values(state.incidents).map(({ id, severity, revision, reasons, delivery }) =>
        ({ id, severity, revision, reasons, delivery })) }));
  } else throw Error('Use run, status, target, seed [AFTER HASH [ANCHOR]], replay [AFTER HASH [ANCHOR]], or configure|retarget AGENT CLI PROJECT SESSION [TRANSCRIPT]');
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
