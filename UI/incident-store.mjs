import { readFileSync, writeFileSync, renameSync, unlinkSync, mkdirSync, lstatSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { gunzipSync, gzipSync } from 'node:zlib';
import { installedUiDir } from './paths.mjs';
import { readActivityPage } from './build-widget.mjs';
import { incidentReasonCodes } from './incident-rules.mjs';
import { serverI18n } from './i18n-server.mjs';

export const incidentDir = resolve(installedUiDir, 'incidents');
export const incidentIdPattern = /^[a-f0-9]{24}$/;
const hashPattern = /^[a-f0-9]{64}$/;
const storageLimit = 16 * 1024 * 1024;

function readPrivateJson(directory, name, limit) {
  const path = resolve(directory, name);
  try {
    const info = lstatSync(path);
    if (!info.isFile() || info.uid !== process.getuid() || (info.mode & 0o077) || info.size > limit) {
      throw Error('Unexpected incident file: ' + name);
    }
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

export function readIncidentState(directory = incidentDir, includeHistory = true) {
  const state = readPrivateJson(directory, 'state.json', storageLimit);
  if (!state) return null;
  if (state.schema !== 1 || !state.programs || !state.destinations || !state.incidents || !state.active) {
    throw Error('Invalid incident state');
  }
  if (includeHistory && state.ruleHistoryGzip !== undefined) {
    const json = gunzipSync(Buffer.from(state.ruleHistoryGzip, 'base64'), { maxOutputLength: storageLimit });
    const { programs, destinations } = JSON.parse(json);
    if (!programs || !destinations) throw Error('Invalid incident rule history');
    Object.assign(state, { programs, destinations });
    delete state.ruleHistoryGzip;
  }
  return state;
}

function savePrivateJson(directory, name, text) {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const info = lstatSync(directory);
  if (!info.isDirectory() || info.uid !== process.getuid() || (info.mode & 0o077)) throw Error('Unexpected incident directory');
  const path = resolve(directory, name);
  const temp = path + '.' + randomBytes(8).toString('hex') + '.tmp';
  try {
    writeFileSync(temp, text, { flag: 'wx', mode: 0o600, flush: true });
    renameSync(temp, path);
  } finally {
    try { unlinkSync(temp); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
}

export function saveIncidentState(state, directory = incidentDir) {
  const { programs, destinations, ruleHistoryGzip, ...header } = state;
  // Older MCP workers still read incident revisions and the cursor directly.
  // Only the rule history is compressed, and the history and cursor share one commit.
  let packed = ruleHistoryGzip;
  if (packed === undefined) {
    const history = JSON.stringify({ programs, destinations });
    if (Buffer.byteLength(history) + Buffer.byteLength(JSON.stringify(header)) > storageLimit) {
      throw Error('Incident storage limit reached');
    }
    packed = gzipSync(history, { level: 1 }).toString('base64');
  }
  const text = JSON.stringify({ ...header, programs: {}, destinations: {}, ruleHistoryGzip: packed });
  if (Buffer.byteLength(text) > storageLimit) throw Error('Incident storage limit reached');
  savePrivateJson(directory, 'state.json', text);
}

export function readIncidentScanStatus(directory = incidentDir) {
  return readPrivateJson(directory, 'scan-status.json', 4096);
}

export function saveIncidentScanStatus(status, directory = incidentDir) {
  savePrivateJson(directory, 'scan-status.json', JSON.stringify(status));
}

export function verifiedRows({ after, previousHash, anchor }, consume, pageReader = readActivityPage) {
  const { head_id: through, head_hash: headHash } = anchor.payload;
  if (!Number.isSafeInteger(after) || after < 0 || after > through ||
      !hashPattern.test(previousHash) || !hashPattern.test(headHash)) throw Error('Invalid incident evidence range');
  let cursor = after, hash = previousHash;
  while (cursor < through) {
    const page = pageReader({ after: cursor, previousHash: hash, anchor });
    if (!page.events?.length) throw Error('Missing incident evidence page');
    for (const row of page.events) {
      if (!Number.isSafeInteger(row.id) || row.id <= cursor || row.id > through) throw Error('Unexpected incident evidence ID');
      cursor = row.id;
    }
    if (cursor !== page.next_after) throw Error('Incomplete incident evidence page');
    for (const row of [...page.events].sort((a, b) => a.last - b.last || a.id - b.id)) consume(row);
    hash = page.next_hash;
  }
  if (hash !== headHash) throw Error('Incident evidence does not match the signed anchor');
}

function smallText(value, limit = 400) {
  return typeof value === 'string' ? value.slice(0, limit) : '';
}

function summarizeEvidence(row) {
  const detail = JSON.parse(row.detail);
  return {
    id: row.id, timestamp: row.last, kind: row.kind, app: smallText(row.app, 160), path: smallText(row.path),
    ...(row.pid > 0 && { pid: row.pid }),
    ...(detail.remote && { remote: smallText(detail.remote, 120), protocol: smallText(detail.protocol, 12) }),
    ...(row.kind === 'network_bytes' && { sent: Number(detail.tx_delta) * row.count,
      appAggregate: !detail.aggregated_by_executable, executableAggregate: Boolean(detail.aggregated_by_executable) }),
    ...(detail.current && {
      previousVersion: smallText(detail.previous?.version, 64), version: smallText(detail.current.version, 64),
      previousTeam: smallText(detail.previous?.team_id, 64), team: smallText(detail.current.team_id, 64),
      changedPaths: Array.isArray(detail.changed_paths) ? detail.changed_paths.slice(0, 5).map(path => smallText(path)) : []
    })
  };
}

export function readIncidentView(id, revision, directory = incidentDir, pageReader = readActivityPage) {
  if (!incidentIdPattern.test(id)) throw Error('Invalid incident ID');
  const current = readIncidentState(directory, false)?.incidents?.[id];
  const historical = current?.revisions?.[revision] ??
    (current?.previous?.revision === revision ? current.previous : undefined);
  const incident = historical ? { ...current, ...historical } : current;
  if (!incident || incident.id !== id || !Number.isSafeInteger(incident.revision) ||
      (revision !== undefined && revision !== incident.revision) || !Array.isArray(incident.evidence) ||
      incident.evidence.length > 12 || !Array.isArray(incident.reasons) ||
      !incident.reasons.length || incident.reasons.some(reason => !incidentReasonCodes.has(reason))) {
    throw Error('Incident revision is unavailable');
  }
  const segments = new Map();
  for (const ref of incident.evidence) {
    const segment = ref.segment;
    if (!Number.isSafeInteger(ref.id) || !hashPattern.test(ref.hash) || segment.after >= ref.id ||
        ref.id > segment.anchor.payload.head_id) throw Error('Invalid incident event reference');
    const token = segment.anchor.payload.head_hash;
    const range = segments.get(token) ?? { segment, rows: new Map() };
    if (segment.after < range.segment.after) range.segment = segment;
    range.rows.set(ref.id, ref.hash);
    segments.set(token, range);
  }
  const evidence = [];
  let verified = incident.evidence.length > 0;
  try {
    for (const { segment, rows } of segments.values()) {
      verifiedRows(segment, row => {
        if (!rows.has(row.id)) return;
        if (rows.get(row.id) !== row.chain_hash) throw Error('Incident event hash mismatch');
        evidence.push(summarizeEvidence(row));
        rows.delete(row.id);
      }, pageReader);
      if (rows.size) throw Error('Incident evidence has expired');
    }
  } catch {
    verified = false;
    evidence.length = 0;
  }
  return {
    id, revision: incident.revision, severity: incident.severity, createdAt: incident.createdAt,
    // The text is for the model. Widgets translate the codes themselves.
    reasons: incident.reasons.map(code => serverI18n().reason(code)), reasonCodes: incident.reasons, verified,
    ...(incident.coverageGap && { coverageGap: incident.coverageGap }),
    evidence: evidence.sort((a, b) => a.timestamp - b.timestamp || a.id - b.id)
  };
}

export function listIncidentViews() {
  return Object.values(readIncidentState(incidentDir, false)?.incidents ?? {})
    .filter(item => incidentIdPattern.test(item.id) && Array.isArray(item.reasons))
    .sort((a, b) => b.updatedAt - a.updatedAt).slice(0, 20)
    .map(({ id, revision, severity, createdAt, reasons, delivery }) => ({
      id, revision, severity, createdAt,
      reasons: reasons.filter(reason => incidentReasonCodes.has(reason)).map(reason => serverI18n().reason(reason)),
      delivery: delivery?.status ?? 'pending'
    }));
}
