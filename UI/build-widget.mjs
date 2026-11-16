import { readFileSync, writeFileSync, mkdirSync, lstatSync, statSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync, execFile } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify, isDeepStrictEqual } from 'node:util';
import { reviewBadge } from './review-findings.mjs';
import { computeMetricFacts } from './metrics.mjs';
import { readApprovedTrust } from './trust.mjs';
import { fail } from './i18n-server.mjs';
import { createPrograms } from './programs.mjs';
import { readSettings } from './settings.mjs';
import { systemZone, zoneClock } from './zone.mjs';
const sourceTrust=typeof AO_APPROVED_KEY==='undefined'?readApprovedTrust() ?? {}:{};

const CLI = '/Library/PrivilegedHelperTools/local.activity-observer';
const APPROVED = typeof AO_APPROVED_BINARY !== 'undefined' ? AO_APPROVED_BINARY : sourceTrust.binary;
const KEY = typeof AO_APPROVED_KEY !== 'undefined' ? AO_APPROVED_KEY : sourceTrust.key;
const PUBLIC = '/Library/Application Support/ActivityObserver/public-key.der';
const GENESIS = typeof AO_APPROVED_GENESIS !== 'undefined' ? AO_APPROVED_GENESIS : sourceTrust.genesis;
const policy = '/Library/Application Support/ActivityObserver/policies/mcp.sb';
const approvedPolicy = typeof AO_APPROVED_POLICY !== 'undefined' ? AO_APPROVED_POLICY : sourceTrust.policy;
const verifier = '/Library/Application Support/ActivityObserver/bin/page-verify';
const approvedVerifier = typeof AO_APPROVED_VERIFIER !== 'undefined' ? AO_APPROVED_VERIFIER : sourceTrust.verifier;
const sensorPolicies = [
  ['/Library/Application Support/ActivityObserver/policies/guard.sb', typeof AO_APPROVED_GUARD_POLICY !== 'undefined' ? AO_APPROVED_GUARD_POLICY : sourceTrust.guard],
  ['/Library/Application Support/ActivityObserver/policies/sensor.sb', typeof AO_APPROVED_SENSOR_POLICY !== 'undefined' ? AO_APPROVED_SENSOR_POLICY : sourceTrust.sensor]
// Pins written before these two policies were recorded leave them unchecked
// when the sources run uninstalled. An installed build always carries them.
].filter(([, pin]) => pin !== undefined || typeof AO_MCP_INSTALLED !== 'undefined');
export const installedMcpBuild = typeof AO_MCP_INSTALLED !== 'undefined' && AO_MCP_INSTALLED;
const sourceDir = dirname(fileURLToPath(import.meta.url));
// Reports published before their time zone was recorded use the zone named in
// the settings, so their hourly totals can still be reproduced after a move.
const clockFor = source => zoneClock(source?.timeZone ?? readSettings().legacyTimeZone ?? systemZone());
let programSet;
function programs() {
  const settings = readSettings();
  if (programSet?.digest !== settings.digest) programSet = { digest: settings.digest, ...createPrograms(settings.programGroups) };
  return programSet;
}
const identity = row => programs().identity(row);
const shiftDay = (day, days) => new Date(Date.parse(day + 'T00:00:00Z') + days * 86400000).toISOString().slice(0, 10);
const hash = x => createHash('sha256').update(x).digest('hex');
const execute = promisify(execFile);
function protectedInvocation(command, args) {
  return installedMcpBuild ? [command, args] : ['/usr/bin/sandbox-exec', ['-D', 'AO_NODE=' + CLI, '-f', policy, command, ...args]];
}
function protectedCommand(command, args, options) {
  const [executable, arguments_] = protectedInvocation(command, args);
  return spawnSync(executable, arguments_, options);
}
function verifyNative(request) {
  const p = protectedCommand(verifier, [], { input: JSON.stringify({...request,expectedKey:KEY}), encoding: 'utf8', timeout: 15000, maxBuffer: 2 * 1024 * 1024 });
  if (p.error) throw p.error;
  if (p.signal || !p.stdout) throw Error(`Native verifier stopped${p.signal ? ` (${p.signal})` : ` (exit ${p.status})`}`);
  const result = JSON.parse(p.stdout);
  if (p.status !== 0 || !result.valid) throw Error(result.error || 'Native verification failed');
  return result;
}
function cli(...parts) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const p = protectedCommand(CLI, parts, { encoding: 'utf8', timeout: 65000, maxBuffer: 16 * 1024 * 1024 });
    let data; try { data = JSON.parse(p.stdout); } catch { data = null; }
    if (p.status === 0 && data && !data.error) return data;
    if (p.status === 2 && parts[0] === 'status' && data?.status_signature_valid === true) return data;
    if (attempt === 2) throw Error(`Read failed: ${parts[0]} ${data?.error || p.error?.message || p.stderr || p.stdout}`);
  }
}
function checkObserver(extra = []) {
  let installedHash;
  for (const [path, approved] of [[CLI, [APPROVED]], [policy, [approvedPolicy]], [verifier, [approvedVerifier]], ...extra.map(([path, value]) => [path, [value]])]) {
    const st = lstatSync(path);
    const current = st.isFile() && st.uid === 0 && !(st.mode & 0o022) && hash(readFileSync(path));
    if (!approved.includes(current)) throw Error('Unapproved observer artifact: ' + path);
    if (path === CLI) installedHash = current;
  }
  if (hash(readFileSync(PUBLIC)) !== KEY) throw Error('Operational key mismatch');
  return installedHash;
}
export function readIncidentContext() {
  checkObserver(sensorPolicies);
  const context = cli('monitor-context', '--expected-key', KEY);
  const status = validateStatus(context.status);
  return {
    status,
    anchor: fresh => !fresh ? context.anchor : readCheckedAnchor(fresh),
    verifyAnchor: checkAnchor,
    page: range => readAnchoredPage(range, 500)
  };
}
function readCheckedAnchor(fresh = false) {
  // The protected CLI verifies the signature against the pinned public key.
  return cli('anchor', '--expected-key', KEY, ...(fresh ? ['--fresh'] : []));
}
function retentionBoundary(payload) {
  const id = payload?.boundary_id, hash = payload?.boundary_hash;
  if (!Number.isSafeInteger(id) || id < 0 || typeof hash !== 'string' || !/^[0-9a-f]{64}$/.test(hash)) {
    throw Error('Invalid signed retention boundary');
  }
  return { id, hash };
}
export function readRetentionBoundary(status) {
  if (status.boundary_id !== undefined) return retentionBoundary(status.integrity_signature?.payload);
  // The earlier approved collector exposes its signed boundary with full verify.
  const p = protectedCommand(CLI, ['verify', '--expected-key', KEY], { encoding: 'utf8', timeout: 150000, maxBuffer: 2 * 1024 * 1024 });
  if (p.error || p.status !== 0) throw Error('Signed retention boundary could not be verified');
  const data = JSON.parse(p.stdout);
  if (data.valid !== true) throw Error('Invalid signed retention boundary');
  checkAnchor(data.checkpoint);
  return retentionBoundary(data.checkpoint.payload);
}
export function readCurrentRetentionBoundary() {
  const checkpoint = cli('integrity-checkpoint', '--expected-key', KEY);
  return retentionBoundary(checkpoint.payload);
}
export function checkMcpIsolation() {
  if (!installedMcpBuild) return;
  checkObserver();
  const result = cli('check-network-isolation');
  if (!result.internet_sockets_blocked) throw Error('Activity Observer MCP requires the installed network isolation policy');
}
function checkAnchor(anchor) {
  if (anchor?.key_fingerprint !== KEY) throw Error('Operational key mismatch');
  verifyNative({ op: 'anchor', anchor });
}
function checkedStatus() {
  return validateStatus(cli('status', '--expected-key', KEY));
}
function validateStatus(status) {
  if (!status.status_signature_valid || status.integrity_signature?.key_fingerprint !== KEY || status.protection_mode !== 'privileged_writer') throw Error('Status signature invalid');
  if (status.max_data_bytes !== 1_000_000_000 || status.retention_policy !== 'capacity') throw Error('Protected retention settings differ from the approved configuration');
  return status;
}
function eventPage(after, through, limit) {
  return cli('events', '--after', String(after), '--through', String(through), '--limit', String(limit));
}
function checkPrevious(after, previousHash, allowPruned) {
  if (!after) {
    if (previousHash !== GENESIS) throw Error('Starting genesis commitment does not match');
    return true;
  }
  const [prior] = eventPage(after - 1, after, 1).events;
  if (prior ? prior.id !== after || prior.chain_hash !== previousHash : !allowPruned) throw Error('Starting anchor missing or changed');
  return Boolean(prior);
}
export function beginActivityReview(after, previousHash) {
  checkObserver();
  const anchor = readCheckedAnchor(true);
  const status = checkedStatus();
  if (after > anchor.payload.head_id) throw Error('The previous review is ahead of the current anchor');
  if (status.boundary_id > after) throw Error('The signed retention boundary exceeds the previous completed review');
  const previousRetained = checkPrevious(after, previousHash, status.pruned_rows > 0);
  // The collector's full report is large. The model gets the largest totals,
  // and the review command-line tool produces the verified digest.
  const report = cli('report', '--after', String(after));
  const totals = [...(report.all_app_activity_totals ?? [])].sort((a, b) => b.count - a.count).slice(0, 80)
    .map(({ app, kind, count }) => ({ app, kind, count }));
  return { anchor, status, previousRetained, summary: { rows: report.row_count, through: report.through_id, timeZone: report.timezone, totals } };
}
// Opens the interval for a new review: a fresh signed upper bound, the signed
// collector status and a reader that verifies every row up to that bound. When
// the previous position was pruned, the review starts at the signed boundary
// and the skipped range is returned as uncovered.
export function openReviewInterval(start) {
  checkObserver(sensorPolicies);
  const anchor = readCheckedAnchor(true);
  const status = checkedStatus();
  const boundary = readRetentionBoundary(status);
  let { after, previousHash } = start ?? { after: boundary.id, previousHash: boundary.id ? boundary.hash : GENESIS };
  let uncovered = null;
  if (after > anchor.payload.head_id) throw Error('The previous review is ahead of the current anchor');
  if (boundary.id > after) {
    uncovered = { after, through: boundary.id };
    after = boundary.id; previousHash = boundary.hash;
  } else if (after !== boundary.id) checkPrevious(after, previousHash, false);
  else if (previousHash !== (boundary.id ? boundary.hash : GENESIS)) throw Error('Starting anchor missing or changed');
  const interval = { after, previousHash, anchor };
  return { anchor, status, after, previousHash, uncovered,
    rows(consume) {
      let cursor = after, hash = previousHash, count = 0;
      while (cursor < anchor.payload.head_id) {
        const page = readAnchoredPage({ ...interval, after: cursor, previousHash: hash }, 500);
        for (const row of page.events) { consume(row); count++; }
        cursor = page.next_after; hash = page.next_hash;
      }
      if (hash !== anchor.payload.head_hash) throw Error('Review head mismatch');
      return count;
    } };
}
// Where the retained log begins: the signed pruning boundary, or the genesis
// commitment when nothing has been pruned.
export function readLogStart() {
  checkObserver();
  const boundary = readRetentionBoundary(checkedStatus());
  return { after: boundary.id, previousHash: boundary.id ? boundary.hash : GENESIS };
}
export const programIdentity = row => identity(row);
// Per-program totals that the collector keeps beyond the detailed log.
export const readReviewStatistics = after => cli('report', '--after', String(after));
export const describeProgram = (id, row) => programs().describe(id, row);
export function readActivityPage({ after, previousHash, anchor }) {
  checkObserver();
  checkAnchor(anchor);
  return readAnchoredPage({ after, previousHash, anchor });
}
function readAnchoredPage({ after, previousHash, anchor }, limit = 100) {
  const through = anchor.payload.head_id;
  if (after >= through) throw Error('Page cursor is outside the review interval');
  const page = eventPage(after, through, limit);
  if (!page.events?.length || page.next_after <= after || page.next_after !== page.events.at(-1).id || page.next_after > through) throw Error('Incomplete selected interval');
  const proof = verifyNative({ op: 'page', previous: previousHash, rows: page.events });
  if (page.next_after === through && proof.last_hash !== anchor.payload.head_hash) throw Error('Review head mismatch');
  return { ...page, next_hash: proof.last_hash };
}

export function activityPeriod(start, end) {
  const valid = day => /^\d{4}-\d{2}-\d{2}$/.test(day) && Number.isFinite(Date.parse(day + 'T00:00:00Z')) && shiftDay(day, 0) === day;
  if (!valid(start) || !valid(end) || start > end) throw fail('period_invalid');
  if (end > zoneClock().day(Date.now() / 1000)) throw fail('period_future');
  return { start, end };
}

export function openActivityPeriod(start, end) {
  const period = activityPeriod(start, end);
  checkObserver(sensorPolicies);
  const anchor = cli('anchor', '--expected-key', KEY, '--fresh');
  checkAnchor(anchor);
  const status = checkedStatus();
  const head = anchor.payload.head_id;
  const first = eventPage(0, head, 1).events[0];
  if (head && !first) throw fail('anchor_not_retained');
  return { period, anchor, status, first };
}

export function activityPeriodBounds({ period, anchor, first }) {
  if (!first) return [];
  const head = anchor.payload.head_id, boundary = first.id - 1;
  if (shiftDay(period.start, 6) < period.end) return [{ after: boundary, through: head }];
  // ID order is only a search hint. Confirm both ends against the day index
  // before omitting any pages, since late observations can arrive out of order.
  function beforeDay(day) {
    let low = boundary, high = head + 1;
    while (high - low > 1) {
      const mid = Math.floor((low + high) / 2);
      const row = eventPage(mid - 1, head, 1).events[0];
      if (row?.day < day) low = mid;
      else high = mid;
    }
    return low;
  }
  const before = beforeDay(period.start), afterEnd = beforeDay(shiftDay(period.end, 1));
  // Reports see the live writer. Remove additions beyond this view's signed
  // head so count comparisons stay valid while a new observation is written.
  let tail = head;
  const newRows = new Map();
  const count = (day, id) => {
    const report = cli('report', '--after', String(id), '--day', day);
    while (tail < report.through_id) {
      const page = eventPage(tail, report.through_id, 500);
      if (page.next_after <= tail) throw fail('retention_changed');
      for (const row of page.events) {
        if (!newRows.has(row.day)) newRows.set(row.day, []);
        newRows.get(row.day).push(row.id);
      }
      tail = page.next_after;
    }
    const later = newRows.get(day)?.filter(id => id <= report.through_id).length || 0;
    if (later > report.row_count) throw fail('totals_changed');
    return report.row_count - later;
  };
  const edgePages = (day, lower, upper) => {
    const spans = [];
    let remaining = count(day, lower), outside = count(day, upper);
    while (remaining > outside && lower < upper) {
      let lo = lower, hi = upper;
      while (hi - lo > 1) {
        const mid = Math.floor((lo + hi) / 2);
        if (count(day, mid) === remaining) lo = mid;
        else hi = mid;
      }
      const through = Math.min(hi + 499, upper);
      spans.push({ after: lo, through });
      remaining = count(day, through);
      lower = through;
      if (spans.length === 12 && remaining > outside) { spans.push({ after: lower, through: upper }); break; }
    }
    return spans;
  };
  const spans = [{ after: before, through: afterEnd }];
  for (let day = period.start; day <= period.end; day = shiftDay(day, 1)) {
    if (before > boundary) spans.push(...edgePages(day, boundary, before));
    if (afterEnd < head) spans.push(...edgePages(day, afterEnd, head));
  }
  const merged = [];
  for (const span of spans.sort((a, b) => a.after - b.after)) {
    if (span.after >= span.through) continue;
    const last = merged.at(-1);
    if (last && last.through >= span.after) last.through = Math.max(last.through, span.through);
    else merged.push(span);
  }
  return merged;
}

export function readActivityPeriodPage({ anchor, after, through, previous }) {
  const page = eventPage(after, through, 500);
  if (!page.events.length || page.next_after <= after || page.next_after !== page.events.at(-1).id || page.next_after > through) throw fail('retention_changed');
  const proof = verifyNative({ op: 'page', previous: previous ?? page.events[0].chain_prev, rows: page.events });
  if (page.next_after === anchor.payload.head_id && proof.last_hash !== anchor.payload.head_hash) throw fail('anchor_hash_mismatch');
  return { ...page, next_hash: proof.last_hash };
}

export function activityPeriodRetained({ first, anchor }) {
  const row = eventPage(0, anchor.payload.head_id, 1).events[0];
  return row?.id === first?.id && row?.chain_hash === first?.chain_hash;
}
const labels = {
  network_open: '네트워크 연결', network_close: '네트워크 연결 종료', network_bytes: '송수신량 증분',
  screen_started: '화면 사용 시작', screen_stopped: '화면 사용 종료', screen_capture_client_connected: '화면 접근',
  capture_stream_started: '캡처 스트림 시작', capture_stream_stopped: '캡처 스트림 종료',
  keyboard_observer_active: '키보드 관측기 등록', keyboard_observer_inactive: '키보드 관측기 해제',
  hid_access_active: 'HID 장치 연결', hid_access_inactive: 'HID 장치 연결 해제',
  microphone_started: '마이크 사용 시작', microphone_stopped: '마이크 사용 종료',
  audio_input_started: '오디오 입력 시작', audio_input_stopped: '오디오 입력 종료',
  program_first_seen: '구성요소 첫 관측', program_installed: '신규 생성 관측', program_updated: '프로그램 변경',
  program_version_observed: '다른 버전 관측', program_files_changed: '프로그램 파일 변경', program_removed: '프로그램 제거',
  application_launched: '앱 실행', application_terminated: '앱 종료', collector_started: '수집 시작',
  guard_started: '보호 서비스 시작', guard_stopped: '보호 서비스 종료', sensor_connected: '센서 연결', sensor_connection_closed: '센서 연결 종료',
  guard_connection_rejected: '보호 서비스 접속 거절', collection_gap: '수집 공백', filesystem_inventory_reconciled: '파일 상태 재검색',
  sensitive_file_changed: '민감 파일 변경', permission_decision: '권한 확인'
};
function category(kind) {
  if (/screen|capture|camera/.test(kind)) return '화면';
  if (/keyboard|hid_/.test(kind)) return '입력';
  if (/microphone|audio_input|system_audio/.test(kind)) return '오디오';
  if (kind.startsWith('program_')) return '프로그램 변경';
  if (kind.startsWith('network_')) return '네트워크';
  return '기타';
}
function activityGroup(kind) {
  if (kind.startsWith('network_')) return 'network';
  if (kind.startsWith('program_') || kind === 'sensitive_file_changed') return 'files';
  if (/^application_(launched|terminated)$/.test(kind)) return 'launch';
  if (/screen|capture|camera|keyboard|hid_|microphone|audio_input|system_audio/.test(kind) || kind === 'permission_decision') return 'inputs';
  return 'other';
}
const emptyGroups = () => ({ files: 0, launch: 0, inputs: 0, network: 0, other: 0 });
const networkSummaryKinds = ['network_open', 'network_bytes', 'network_actor_resolved'];
const endpointKey = detail => `${detail.protocol || ''}|${detail.remote || ''}`;
function activityNote(row, detail) {
  if (row.kind === 'guard_connection_rejected') {
    return detail.reason === 'connection_limit' ? '동시 접속 한도 초과' : detail.reason === 'peer_authentication_failed' ? '접속 프로세스 인증 실패' : '사유 미기록';
  }
  if (row.kind === 'filesystem_inventory_reconciled') return detail.status === 'partial' ? '일부 경로 확인 실패' : '재검색 완료';
  // Service names and outcomes are system identifiers and stay as recorded.
  if (row.kind === 'permission_decision') return [detail.service, detail.decision].filter(value => typeof value === 'string').join(' · ').slice(0, 120);
  if (row.kind === 'sensitive_file_changed') return typeof detail.category === 'string' ? detail.category.slice(0, 40) : '';
  return '';
}
const activityKey = (row, detail, note) => `${row.kind}|${row.kind === 'program_first_seen' ? '' : row.path}|${detail.current?.version || ''}|${note}`;
function addLocation(record, r) {
  record.records++;
  if (!r.path) { record.unlocatedRecords++; return; }
  const location = record.locations.get(r.path) || { path: r.path, records: 0, observations: 0, first: r.first, last: r.last, pids: new Set() };
  location.records++; location.observations += r.count;
  location.first = Math.min(location.first, r.first); location.last = Math.max(location.last, r.last);
  if (r.pid && location.pids.size < 5) location.pids.add(r.pid);
  record.locations.set(r.path, location);
}
function withLocations(record) {
  const { parents, ...rest } = record;
  return { ...rest, locations: [...record.locations.values()].map(p => ({ ...p, pids: [...p.pids] })).sort((a, b) => b.records - a.records || a.path.localeCompare(b.path)),
    ...(parents && { parents: [...parents.values()].map(p => ({ path: p.path, pids: [...p.pids] })) }) };
}
// Programs whose name is still the recorded identifier. A later row with an
// app bundle path replaces it. Kept outside the summary so stored digests,
// which cover every summary field, do not change.
const unnamed = new WeakSet();
function createApp(id, r) {
  const [name, icon, type, named] = programs().describe(id, r);
  const app = createSummary(id, name, icon, type, r);
  if (!named) unnamed.add(app);
  return app;
}
function createSummary(id, name, icon, type, r) {
  return { id, name, icon, type, records: 0, observations: 0, kinds: {}, ids: new Set(), paths: new Map(),
    first: r.first, last: r.last, opens: 0, rx: 0, tx: 0, byteSamples: 0, categories: {},
    groupRecords: emptyGroups(), rowKinds: {},
    hours: Array.from({ length: 24 }, (_, h) => ({ h, records: 0, rx: 0, tx: 0, sensitive: 0, groups: emptyGroups() })),
    endpoints: new Map(), activity: new Map(), versions: new Set(), components: new Set() };
}
function aggregate(apps, r, multiDay = false, keepReference = false, clock = zoneClock()) {
  const id = identity(r), a = apps.get(id) || createApp(id, r); apps.set(id, a);
  if (unnamed.has(a) && r.path) {
    const [name, , , named] = programs().describe(id, r);
    if (named) { a.name = name; unnamed.delete(a); }
  }
  const d = JSON.parse(r.detail) || {}, c = category(r.kind), hour = clock.hour(r.last);
  const n = r.count, group = activityGroup(r.kind);
  let h = a.hours[hour];
  if (multiDay) {
    a.days ??= new Map();
    h = a.days.get(r.day) || { h: r.day, records: 0, rx: 0, tx: 0, sensitive: 0, groups: emptyGroups() };
    a.days.set(r.day, h);
  }
  a.records++; a.observations += n; h.records++; a.kinds[r.kind] = (a.kinds[r.kind] || 0) + n;
  if (keepReference) {
    h.eventBounds ??= {};
    for (const key of ['all', group]) {
      const bound = h.eventBounds[key] ??= { firstEventId: r.id, lastEventId: r.id };
      bound.lastEventId = r.id;
    }
  }
  a.groupRecords[group]++; h.groups[group]++; a.rowKinds[r.kind] = (a.rowKinds[r.kind] || 0) + 1;
  a.first = Math.min(a.first, r.first); a.last = Math.max(a.last, r.last); a.ids.add(r.app);
  a.categories[c] = (a.categories[c] || 0) + 1;
  if (['화면', '입력', '오디오'].includes(c)) h.sensitive++;
  if (r.path) { const p = a.paths.get(r.path) || { path: r.path, records: 0, pids: new Set(), groups: emptyGroups() }; p.records++; p.groups[group]++; if (r.pid) p.pids.add(r.pid); a.paths.set(r.path, p); }
  if (r.kind === 'network_open') a.opens += n;
  if (r.kind === 'network_bytes') { const rx = (d.rx_delta || 0) * n, tx = (d.tx_delta || 0) * n; a.rx += rx; a.tx += tx; h.rx += rx; h.tx += tx; a.byteSamples += n; }
  if (networkSummaryKinds.includes(r.kind)) {
    const key = endpointKey(d), e = a.endpoints.get(key) || { remote: d.remote || '식별되지 않음', protocol: d.protocol || '', connections: 0, rx: 0, tx: 0, byteObserved: false, first: r.first, last: r.last, records: 0, unlocatedRecords: 0, locations: new Map() };
    if (r.kind === 'network_open') e.connections += n;
    if (r.kind === 'network_actor_resolved') e.resolvedActors = (e.resolvedActors || 0) + n;
    if (r.kind === 'network_bytes') { e.rx += (d.rx_delta || 0) * n; e.tx += (d.tx_delta || 0) * n; e.byteObserved = true; }
    const pid = d.parent?.pid;
    if (Number.isSafeInteger(pid) && pid > 0) {
      const path = typeof d.parent.path === 'string' && d.parent.path.startsWith('/') ? d.parent.path : '';
      e.parents ??= new Map();
      const key = path || String(pid);
      if (!e.parents.has(key) && e.parents.size < 8) e.parents.set(key, { path, pids: new Set() });
      const parent = e.parents.get(key);
      if (parent && parent.pids.size < 5) parent.pids.add(pid);
    } else if (typeof d.parent?.path === 'string' && d.parent.path.startsWith('/')) {
      // A merged connection summary names the launching program without a PID.
      e.parents ??= new Map();
      if (!e.parents.has(d.parent.path) && e.parents.size < 8) e.parents.set(d.parent.path, { path: d.parent.path, pids: new Set() });
    }
    if (keepReference && r.last >= e.last) e.sample = { eventId: r.id, eventHash: r.chain_hash };
    e.first = Math.min(e.first, r.first); e.last = Math.max(e.last, r.last); addLocation(e, r);
    a.endpoints.set(key, e);
  }
  if (!r.kind.startsWith('network_')) {
    const note = activityNote(r, d), key = activityKey(r, d, note);
    const t = a.activity.get(key) || { kind: r.kind, group, category: c, label: labels[r.kind] || r.kind, first: r.first, last: r.last, count: 0, records: 0, unlocatedRecords: 0, locations: new Map(), versionChangeCount: 0, lastVersionChange: null,
      path: r.path, source: r.source, note, version: d.current?.version || '', previousVersion: d.previous?.version || '', device: d.devices?.map(x => x.name).join(', ') || '' };
    if (r.kind === 'program_updated' && d.current?.version && d.previous?.version && d.current.version !== d.previous.version) {
      t.versionChangeCount += n;
      if (!t.lastVersionChange || r.last >= t.lastVersionChange.last) t.lastVersionChange = { before: d.previous.version, after: d.current.version, last: r.last };
    }
    if (keepReference && r.last >= t.last) t.sample = { eventId: r.id, eventHash: r.chain_hash };
    t.count += n; t.first = Math.min(t.first, r.first); t.last = Math.max(t.last, r.last); addLocation(t, r); a.activity.set(key, t);
  }
  if (d.current?.version) a.versions.add(d.current.version);
  if (r.kind === 'program_first_seen') a.components.add(r.path);
}
function summarizeApp(a) {
  const activity = [...a.activity.values()];
  const { days, ...base } = a;
  return { ...base, ...(days && { days: Object.fromEntries(days) }),
    metricFacts: computeMetricFacts({ ...a, activity: activity.map(withLocations) }), ids: [...a.ids], versions: [...a.versions], components: a.components.size,
    paths: [...a.paths.values()].map(p => ({ ...p, pids: [...p.pids] })).sort((a, b) => b.records - a.records),
    endpoints: [...a.endpoints.values()].sort((a, b) => (b.rx + b.tx) - (a.rx + a.tx) || b.connections - a.connections).slice(0, 80).map(withLocations),
    endpointCount: a.endpoints.size, activity: activity.sort((a, b) => b.last - a.last).slice(0, 100).map(withLocations) };
}

async function reviewedEventPage(after, through, signal, limit = 500) {
  const [command, args] = protectedInvocation(CLI, ['events', '--after', String(after), '--through', String(through), '--limit', String(limit)]);
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const { stdout } = await execute(command, args, { encoding: 'utf8', timeout: 15000, maxBuffer: 16 * 1024 * 1024, signal });
      const page = JSON.parse(stdout);
      if (!page.error && Array.isArray(page.events)) return page;
    } catch (error) {
      if (signal?.aborted) throw error;
      if (error.stdout?.includes('response_limit_exceeded') && limit > 100) return reviewedEventPage(after, through, signal, 100);
    }
    await new Promise(resolve => setTimeout(resolve, 40 * (attempt + 1)));
  }
  throw fail('log_unreachable');
}

async function verifyPublishedPage(previous, rows, signal) {
  const [command, args] = protectedInvocation(verifier, []);
  return new Promise((resolve, reject) => {
    const child = execFile(command, args, { encoding: 'utf8', timeout: 15000, maxBuffer: 2 * 1024 * 1024, signal }, (error, stdout) => {
      if (signal?.aborted) { reject(signal.reason); return; }
      try {
        if (!stdout) throw error || Error('Native verifier returned no result');
        const proof = JSON.parse(stdout);
        if (error || !proof.valid) throw Error(proof.error || 'Native verification failed');
        resolve(proof);
      } catch (error) { reject(error); }
    });
    child.stdin.on('error', reject);
    child.stdin.end(JSON.stringify({ op: 'page', previous, rows }));
  });
}

export async function assertPublishedRetained({ source, previousHash }, signal) {
  const { events: [first] } = await reviewedEventPage(0, source.through, signal, 1);
  if (first && (first.id <= source.after || first.chain_prev === previousHash)) return;
  const status = checkedStatus();
  if (status.pruned_rows > 0 && (status.boundary_id === undefined || status.boundary_id > source.after)) throw fail('report_pruned');
  throw fail('report_start_unverified');
}

async function queryActivity(query, signal) {
  const [command, args] = protectedInvocation(CLI, ['activity-query', '--expected-key', KEY]);
  return new Promise((resolve, reject) => {
    const child = execFile(command, args, {encoding:'utf8', timeout:30000, maxBuffer:16*1024*1024, signal}, (error, stdout) => {
      try {
        const result = JSON.parse(stdout || '{}');
        if (result.error === 'query_range_pruned') throw fail('range_pruned');
        if (error || result.error) throw fail(['query_catalog_limit','invalid_query_actors'].includes(result.error) ? 'query_too_large' : result.error === 'invalid_query_range' ? 'query_range_invalid' : 'query_failed');
        const data = result.payload;
        if (result.key_fingerprint !== KEY || data?.schema !== 1 || !isDeepStrictEqual(data.query, query) || !Array.isArray(data.rows)) throw fail('query_scope_mismatch');
        resolve(data);
      } catch (failure) { reject(signal?.aborted ? signal.reason : failure); }
    });
    child.stdin.on('error', reject);
    child.stdin.end(JSON.stringify(query));
  });
}
function activityQueryScope(source) {
  return {start:source.start ?? source.day, end:source.end ?? source.day,
    after:source.after ?? (source.first?.id ? source.first.id-1 : 0), through:source.through ?? source.anchor.payload.head_id};
}
export async function readActivityCatalog(source, signal) {
  checkObserver(); checkAnchor(source.anchor);
  const scope = activityQueryScope(source);
  const result = await queryActivity({mode:'catalog', ...scope, cursor:scope.after}, signal);
  const catalog = new Map(), dayRows = {}, catalogNamed = new Set();
  for (const row of result.rows) {
    if (!Number.isSafeInteger(row.records) || row.records < 1) throw fail('catalog_count_invalid');
    const id = identity({...row, kind:row.kind === 'network' ? 'network_open' : 'catalog'});
    const [name, icon, type, named] = programs().describe(id, row);
    const entry = catalog.get(id) ?? {id,name,icon,type,records:0,first:row.first,last:row.last,actors:new Map()};
    if (named && entry.name !== name && !catalogNamed.has(id)) entry.name = name;
    if (named) catalogNamed.add(id);
    entry.records += row.records; entry.first = Math.min(entry.first,row.first); entry.last = Math.max(entry.last,row.last);
    const actor = {app:row.app,path:row.path,kind:row.kind};
    entry.actors.set(JSON.stringify(actor),actor); catalog.set(id,entry);
    dayRows[row.day] = (dayRows[row.day] ?? 0)+row.records;
  }
  return {scope, dayRows, apps:[...catalog.values()].map(app=>({...app,actors:[...app.actors.values()]}))};
}
export async function readCatalogProgram(source, catalog, programId, signal, reference = false) {
  const selected = catalog.apps.find(app=>app.id === programId);
  if (!selected) throw fail('program_not_in_range');
  const scope = activityQueryScope(source), apps = new Map(), clock = clockFor(source);
  let cursor = scope.after, count = 0;
  for (;;) {
    signal?.throwIfAborted();
    const page = await queryActivity({mode:'program',...scope,cursor,actors:selected.actors},signal);
    for (const row of page.rows) {
      if (!Number.isSafeInteger(row.id) || row.id<=cursor || row.id>scope.through || identity(row)!==programId || row.day<scope.start || row.day>scope.end) throw fail('foreign_rows');
      aggregate(apps,row,scope.start!==scope.end,reference,clock); cursor=row.id; count++;
    }
    if(page.next_after!==cursor) throw fail('cursor_mismatch');
    if(!page.has_more) break;
    if(!page.rows.length) throw fail('query_stalled');
  }
  if(count!==selected.records) throw fail('program_count_changed');
  const {paths,...app}=summarizeApp(apps.get(programId));
  if(reference && app.days) app.days=Object.fromEntries(Object.keys(catalog.dayRows).map(day=>[day,app.days[day] ?? {h:day,records:0,rx:0,tx:0,sensitive:0,groups:emptyGroups()}]));
  return {...app,pathCount:paths.length,iconData:null,...(reference && {programKey:hash(programId)})};
}
export async function readPublishedPrograms(publication, signal, programId, cachedCatalog) {
  const {source,applications}=publication;
  checkObserver();checkAnchor(source.anchor);await assertPublishedRetained(publication,signal);
  const selected=applications.find(app=>app.id===programId) ?? (programId===undefined ? applications[0] : null);
  if(!selected) return [];
  // Early publications have only a whole-range commitment. Keep their original
  // chain verification; current reports use the app-specific published digest.
  if(!selected.detailHash) {
    const apps=new Map(),clock=clockFor(source);let cursor=source.after,previous=publication.previousHash,rows=0;
    while(cursor<source.through) {
      const page=await reviewedEventPage(cursor,source.through,signal);
      if(!page.events.length || page.next_after<=cursor || page.next_after!==page.events.at(-1).id || page.next_after>source.through)throw fail('legacy_range_incomplete');
      const proof=await verifyPublishedPage(previous,page.events,signal);
      for(const row of page.events)if(row.day===source.day&&identity(row)===selected.id)aggregate(apps,row,false,true,clock);
      rows+=page.events.length;cursor=page.next_after;previous=proof.last_hash;
    }
    if(previous!==source.anchor.payload.head_hash||rows!==(source.reviewedRows??source.rowsRead))throw fail('legacy_anchor_mismatch');
    const {paths,...app}=summarizeApp(apps.get(selected.id));
    if(app.records!==selected.records)throw fail('published_count_mismatch');
    return [{...app,pathCount:paths.length,iconData:null,name:selected.name,icon:selected.icon,review:selected.review,programKey:hash(selected.id)}];
  }
  const catalog=cachedCatalog ?? await readActivityCatalog(source,signal);
  const app=await readCatalogProgram(source,catalog,selected.id,signal,true);
  if(app.records!==selected.records) throw fail('published_program_count_mismatch');
  return [{...app,name:selected.name,icon:selected.icon,review:selected.review}];
}

export function createActivityPeriodSummary({ period, anchor, status, first }, icons) {
  const apps = new Map(), clock = zoneClock();
  let rowsRead = 0;
  const dayRows = {};
  return {
    add(rows) {
      for (const row of rows) {
        if (row.day < period.start || row.day > period.end) continue;
        aggregate(apps, row, period.start !== period.end, true, clock);
        rowsRead++;
        dayRows[row.day] = (dayRows[row.day] || 0) + 1;
      }
    },
    view() {
      return { schema: 3, source: { day: period.start, ...period, firstDay: first?.day ?? null, through: anchor.payload.head_id,
        rowsRead, dayRows, anchor, storageAsOf: status.heartbeat, storageBytes: status.data_bytes, storageLimit: status.max_data_bytes,
        pruned: status.pruned_rows, collecting: status.collector_running },
        apps: [...apps.values()].map(a => {
          const { paths, ...app } = summarizeApp(a);
          const days = app.days && Object.fromEntries(Object.keys(dayRows).map(day => [day,
            app.days[day] ?? { h: day, records: 0, rx: 0, tx: 0, sensitive: 0, groups: emptyGroups() }]));
          return { ...app, ...(days && { days }), programKey: hash(a.id), pathCount: paths.length, iconData: icons.get(a.id) ?? null };
        }) };
    }
  };
}

function matchesPeriodScope(row, scope) {
  if (row.day < scope.start || row.day > scope.end || (scope.category !== 'all' && activityGroup(row.kind) !== scope.category)) return false;
  const hour = scope.clock.hour(row.last);
  return (scope.startHour === undefined || hour >= scope.startHour && hour <= scope.endHour) && hash(identity(row)) === scope.programKey;
}

export function readActivitySelection(selection) {
  // A selection made in a published report uses that report's time zone.
  const scope = { ...selection, clock: selection.reviewAfter === undefined ? zoneClock() : clockFor(selection) };
  const { start, end, throughId, expectedHeadHash, eventId, eventHash, after } = scope;
  const lower=scope.reviewAfter ?? 0;
  const source = openActivityPeriod(start, end);
  const head = source.anchor.payload.head_id;
  if (throughId > head || !throughId) throw fail('selection_anchor_not_retained');
  const selected = throughId === head ? source.anchor.payload.head_hash : eventPage(throughId - 1, throughId, 1).events[0]?.chain_hash;
  if (selected !== expectedHeadHash) throw fail('selection_anchor_hash_mismatch');
  if (eventId !== undefined) {
    if (eventId <= lower || eventId > throughId) throw fail('selection_out_of_range');
    const [sample] = readActivityPeriodPage({ anchor: source.anchor, after: eventId - 1, through: eventId }).events;
    if (sample.chain_hash !== eventHash || !matchesPeriodScope(sample, scope)) throw fail('selection_record_mismatch');
    const record = evidenceRow(sample, JSON.parse(sample.detail) || {});
    return { records: [record], nextAfter: null };
  }
  const spans = scope.firstEventId === undefined ? activityPeriodBounds(source) : [{ after: scope.firstEventId - 1, through: scope.lastEventId }];
  let cursor = Math.max(after ?? 0,lower), pageCount = 0;
  const records = [];
  scan: for (const { after, through: endId } of spans) {
    const through = Math.min(throughId, endId);
    cursor = Math.max(cursor, after);
    let previous;
    while (cursor < through) {
      if (pageCount++ >= 5) break scan;
      const { events, next_after, next_hash } = readActivityPeriodPage({ anchor: source.anchor, after: cursor, through, previous });
      for (const row of events) {
        if (!matchesPeriodScope(row, scope)) continue;
        const detail = JSON.parse(row.detail) || {};
        records.push(evidenceRow(row, detail));
        if (records.length === 30) { cursor = row.id; break scan; }
      }
      cursor = next_after; previous = next_hash;
    }
  }
  if (!activityPeriodRetained(source)) throw fail('retention_changed');
  return { records, nextAfter: cursor < Math.min(throughId, spans.at(-1)?.through ?? 0) ? cursor : null };
}

function evidenceRow(row, detail) {
  return { id: row.id, day: row.day, first: row.first, last: row.last, kind: row.kind, count: row.count,
    app: row.app, path: row.path, ...(detail.remote && { remote: detail.remote, protocol: detail.protocol }),
    ...(row.kind === 'network_bytes' && { received: (detail.rx_delta || 0) * row.count, sent: (detail.tx_delta || 0) * row.count }),
    ...(detail.current?.version && { version: detail.current.version, previousVersion: detail.previous?.version }) };
}
function appIcons(apps) {
  // An installed release carries the icon reader built with it.
  const source = resolve(sourceDir, 'app-icons.m'), binary = resolve(sourceDir, installedMcpBuild ? 'widget-icons' : '../build/widget-icons');
  if (!installedMcpBuild && (!existsSync(binary) || statSync(binary).mtimeMs < statSync(source).mtimeMs)) {
    mkdirSync(dirname(binary), { recursive: true });
    const build = spawnSync('/usr/bin/xcrun', ['clang', '-O2', '-fobjc-arc', source, '-framework', 'AppKit', '-o', binary], { encoding: 'utf8' });
    if (build.status !== 0) throw Error(build.stderr || 'Could not build icon reader');
  }
  const request = apps.map(a => ({ id: a.id, paths: [...new Set(a.paths.flatMap(p => {
    const end = p.path.indexOf('.app/'); return end < 0 ? [] : [p.path.slice(0, end + 4)];
  }))] }));
  const p = spawnSync(binary, [], { input: JSON.stringify(request), encoding: 'utf8', timeout: 20000, maxBuffer: 1024 * 1024 });
  if (p.status !== 0) throw Error(p.stderr || 'Could not read application icons');
  return JSON.parse(p.stdout);
}
export function prepareViewData(data, findings) {
  if (data.schema !== 3 || data.apps.some(a => [...a.activity, ...a.endpoints].some(r => !Array.isArray(r.locations)))) throw Error('Recollect the snapshot for record-specific file locations');
  const icons = appIcons(data.apps);
  return { ...data, apps: data.apps.map(({ paths, ...a }) => ({ ...a, metricFacts: a.metricFacts?.schema === 1 ? a.metricFacts : computeMetricFacts(a), pathCount: paths.length, iconData: icons[a.id] || null, review: reviewBadge(data.source, a.id, findings) })) };
}
export function renderAppFragment(runtime) {
  const template = readFileSync(resolve(sourceDir, 'activity-review.template.html'), 'utf8');
  const chartCode = readFileSync(resolve(sourceDir, 'chart-config.mjs'), 'utf8').replace(/^export /gm, '');
  const timelineCode = readFileSync(resolve(sourceDir, 'timeline.mjs'), 'utf8').replace(/^export /gm, '');
  const viewportCode = readFileSync(resolve(sourceDir, 'viewport.mjs'), 'utf8').replace(/^export /gm, '');
  const metricsCode = readFileSync(resolve(sourceDir, 'metrics.mjs'), 'utf8').replace(/^export /gm, '');
  const orderCode = readFileSync(resolve(sourceDir, 'program-order.mjs'), 'utf8').replace(/^export /gm, '');
  return template.replace('__CHART_CONFIG_CODE__', () => chartCode).replace('__TIMELINE_CODE__', () => timelineCode).replace('__VIEWPORT_CODE__', () => viewportCode).replace('__METRICS_CODE__', () => metricsCode).replace('__PROGRAM_ORDER_CODE__', () => orderCode)
    .replace('__MCP_RUNTIME_CODE__', () => runtime.replaceAll('</script', '<\\/script'));
}
export function renderAppHtml(runtime) {
  return '<!doctype html><html lang="ko" data-activity-observer-canvas="flush"><head><meta charset="utf-8"><meta name="color-scheme" content="light dark"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Activity Observer</title></head><body>'+renderAppFragment(runtime)+'</body></html>';
}
function render(data, out) {
  const runtime = readFileSync(resolve(sourceDir, 'dist/runtime.js'), 'utf8');
  const html = renderAppHtml(runtime);
  if (Buffer.byteLength(html) > 1_000_000) throw Error('Widget exceeds size budget');
  mkdirSync(dirname(out), { recursive: true }); writeFileSync(out, html, { mode: 0o600 });
  writeFileSync(out.replace(/\.html$/, '.view.json'), JSON.stringify(prepareViewData(data)), { mode: 0o600 });
  console.log(JSON.stringify({ html: out, bytes: Buffer.byteLength(html), apps: data.apps.length, rows: data.source.rowsRead }));
}
export function collectReviewSnapshot({ anchor, after, previousHash, day, reviewedOnly = false }) {
  const codeHash = checkObserver();
  if (!Number.isSafeInteger(after) || after < 0 || !/^[0-9a-f]{64}$/.test(previousHash || '')) throw Error('A reviewed starting anchor is required');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(day || '')) throw Error('A display day in YYYY-MM-DD form is required');
  const head = anchor?.payload?.head_id;
  if (!Number.isSafeInteger(head) || head <= after) throw Error('A nonempty completed review interval is required');
  checkAnchor(anchor);
  const status = checkedStatus();
  if (!status.collector_running) throw Error('Collector heartbeat is stale');
  // Republishing a completed review verifies exactly the externally committed
  // interval. The independent full audit remains available to the old exporter.
  if (!reviewedOnly && status.pruned_rows !== 0) throw Error('A signed retention boundary is required for a full audit');
  const auditAnchor = reviewedOnly ? anchor : cli('anchor', '--expected-key', KEY);
  if (!reviewedOnly) checkAnchor(auditAnchor);
  if (auditAnchor.payload.head_id < head) throw Error('The signed audit head precedes the completed review');
  checkPrevious(after, previousHash, reviewedOnly && status.pruned_rows > 0);
  let cursor = reviewedOnly ? after : 0, previous = reviewedOnly ? previousHash : GENESIS;
  let rowsRead = 0, reviewedRows = 0, auditedRows = 0, selectedHeadVerified = false;
  const apps = new Map(), dayRows = new Map(), clock = zoneClock();
  while (cursor < auditAnchor.payload.head_id) {
    const page = eventPage(cursor, auditAnchor.payload.head_id, reviewedOnly ? 100 : 500);
    if (!page.events?.length || page.next_after !== page.events.at(-1).id || page.next_after > auditAnchor.payload.head_id) throw Error('Incomplete selected interval');
    const proof = verifyNative({ op: 'page', previous, rows: page.events, checkpoints: [after, head] });
    if (proof.checkpoints[String(after)] && proof.checkpoints[String(after)] !== previousHash) throw Error('Previous review commitment mismatch');
    if (proof.checkpoints[String(head)]) {
      if (proof.checkpoints[String(head)] !== anchor.payload.head_hash) throw Error('Historical anchor mismatch'); selectedHeadVerified = true;
    }
    for (const r of page.events) {
      if (!Number.isSafeInteger(r.id) || r.id <= cursor) throw Error('Event cursor did not advance');
      cursor = r.id;
      auditedRows++;
      if (r.id > after && r.id <= head) {
        reviewedRows++;
        dayRows.set(r.day, (dayRows.get(r.day) || 0) + 1);
        if (r.day !== day) {
          if (!reviewedOnly) throw Error('Requested interval crosses the selected day');
          continue;
        }
        aggregate(apps, r, false, false, clock); rowsRead++;
      }
    }
    previous = proof.last_hash;
  }
  if (!selectedHeadVerified || cursor !== auditAnchor.payload.head_id || previous !== auditAnchor.payload.head_hash) throw Error('Audit does not match signed anchors');
  if (!rowsRead) throw Error('The completed review has no records for the selected display day');
  const data = { schema: 3, source: { day, timeZone: clock.timeZone, after, through: head, rowsRead, reviewedRows, outsideDayRows: reviewedRows - rowsRead, dayRows: Object.fromEntries(dayRows), anchor, verifiedAt: Date.now() / 1000,
    first: Math.min(...[...apps.values()].map(a => a.first)), last: Math.max(...[...apps.values()].map(a => a.last)),
    integrity: 'verified', auditScope: reviewedOnly ? 'completed_review_interval' : 'retained_chain', auditedRows, auditAnchor, storageAsOf: status.heartbeat, codeHash, keyFingerprint: KEY, storageBytes: status.data_bytes, storageLimit: status.max_data_bytes,
    dropped: status.dropped_events, sensorDropped: status.sensors?.guard_sensor_metrics?.dropped, pruned: status.pruned_rows,
    heartbeatAge: status.heartbeat_age_seconds, collecting: Boolean(status.collector_running), sensorState: status.sensors?.guard_sensor_liveness?.status },
    apps: [...apps.values()].map(summarizeApp) };
  if (data.apps.reduce((n, a) => n + a.records, 0) !== rowsRead || data.apps.some(a =>
    a.hours.reduce((n, h) => n + h.records, 0) !== a.records ||
    Object.values(a.groupRecords).reduce((n, v) => n + v, 0) !== a.records ||
    a.paths.some(p => Object.values(p.groups).reduce((n, v) => n + v, 0) !== p.records) ||
    [...a.activity, ...a.endpoints].some(r => r.locations.reduce((n, p) => n + p.records, r.unlocatedRecords) !== r.records) ||
    a.hours.some(h => Object.values(h.groups).reduce((n, v) => n + v, 0) !== h.records) ||
    Object.keys(a.groupRecords).some(g => a.hours.reduce((n, h) => n + h.groups[g], 0) !== a.groupRecords[g])
  )) throw Error('Aggregate validation failed');
  return data;
}
async function main() {
  const args = new Map();
  for (let i = 2; i < process.argv.length; i += 2) {
    if (!['--anchor', '--after', '--previous-hash', '--day', '--out', '--render'].includes(process.argv[i]) || !process.argv[i + 1]) throw Error('Invalid arguments');
    args.set(process.argv[i], process.argv[i + 1]);
  }
  if (!args.has('--out') || !args.get('--out').endsWith('.html')) throw Error('An explicit .html output path is required');
  const out = resolve(args.get('--out'));
  if (args.has('--render')) { render(JSON.parse(readFileSync(args.get('--render'), 'utf8')), out); return; }
  const data = collectReviewSnapshot({ anchor: JSON.parse(readFileSync(args.get('--anchor'), 'utf8')), after: Number(args.get('--after')), previousHash: args.get('--previous-hash'), day: args.get('--day') });
  const jsonPath = out.replace(/\.html$/, '.data.json'); mkdirSync(dirname(out), { recursive: true }); writeFileSync(jsonPath, JSON.stringify(data), { mode: 0o600 });
  render(data, out);
}
if (!installedMcpBuild && process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
