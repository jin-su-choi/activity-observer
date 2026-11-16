// Serves the pages behind the README images. They show the real widgets from
// UI/dist, fed with the synthetic day in demo-data.mjs. Nothing here is installed.
//
//   (cd UI && node build-mcp-app.mjs)
//   HOME=$(mktemp -d) TZ=America/Los_Angeles node docs/demo/demo-server.mjs
//
// The empty home directory keeps your own settings out of the pictures. Open
// dashboard.html, daily-review.html or alert.html on http://127.0.0.1:47891 in
// a browser set to the same time zone. The pictures were taken with Luma
// Launcher and its Network tab open, and in the dashboard with the 13:00 hour
// of the chart selected and a note typed. The window around the widgets is
// drawn by scene.css and demo-chrome.mjs to look like the Codex desktop app.
import { createServer } from 'node:http';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import esbuild from '../../UI/node_modules/esbuild/lib/main.js';
import { createActivityPeriodSummary } from '../../UI/build-widget.mjs';
import { createPrograms } from '../../UI/programs.mjs';
import { reviewApplication, reviewCardSummary } from '../../UI/review-history.mjs';
import { serverI18n } from '../../UI/i18n-server.mjs';
import { demoRows, launcher, timeOn, timeZone } from './demo-data.mjs';

const dir = dirname(fileURLToPath(import.meta.url));
const ui = resolve(dir, '../../UI');
const port = Number(process.env.PORT ?? 47891);
const host = (await esbuild.build({ entryPoints: [resolve(dir, 'demo-host.mjs')], bundle: true, format: 'esm', write: false,
  platform: 'browser', target: 'es2022', nodePaths: [resolve(ui, 'node_modules')] })).outputFiles[0].text;
const widget = readFileSync(resolve(ui, 'dist/activity-review.html'), 'utf8');
const widgets = {
  review: widget,
  dashboard: widget.replace('<html lang="ko"', '<html lang="ko" data-activity-observer-mode="dashboard"'),
  incident: readFileSync(resolve(ui, 'dist/incident.html'), 'utf8')
};
const text = serverI18n('en');
const zero = '0'.repeat(64);
const today = () => new Intl.DateTimeFormat('sv-SE', { timeZone, dateStyle: 'short' }).format(new Date());

// Icons of the apps that are installed on this Mac are read when the server
// starts. They are not stored in the repository.
function readIcons() {
  const { identity } = createPrograms();
  const bundles = new Map();
  for (const row of demoRows(today())) {
    const bundle = /^(.*?\.app)(?:\/|$)/.exec(row.path)?.[1];
    if (bundle) bundles.set(identity(row), bundle);
  }
  const reader = resolve(dir, '../../build/widget-icons');
  if (!existsSync(reader)) {
    mkdirSync(dirname(reader), { recursive: true });
    spawnSync('/usr/bin/xcrun', ['clang', '-O2', '-fobjc-arc', resolve(ui, 'app-icons.m'), '-framework', 'AppKit', '-o', reader]);
  }
  const read = spawnSync(reader, [], { input: JSON.stringify([...bundles].map(([id, path]) => ({ id, paths: [path] }))), encoding: 'utf8', maxBuffer: 4 << 20 });
  return { ...(read.status === 0 ? JSON.parse(read.stdout) : {}), [launcher.id]: launcher.icon };
}
const icons = readIcons();

// One synthetic day, aggregated by the same code that serves real records.
// The dashboard and the alert show the day as it stood right after the upload.
// The daily review covers all of it.
const clock = scene => scene === 'daily' ? [23, 55] : [13, 46];
const days = new Map();
function dayView(day, scene) {
  const key = day + '/' + clock(scene);
  if (days.has(key)) return days.get(key);
  const now = timeOn(day)(...clock(scene)), rows = demoRows(day).filter(row => row.last <= now);
  const anchor = { algorithm: 'ECDSA-P256-SHA256', key_fingerprint: 'a'.repeat(64), signature: 'ZGVtbw==',
    payload: { schema: 1, created_at: now, head_id: rows.length, head_hash: rows.at(-1).chain_hash, daily_statistics_hash: zero, inventory_hash: zero } };
  const status = { heartbeat: now, data_bytes: 148_300_000, max_data_bytes: 1_000_000_000, pruned_rows: 0, collector_running: true };
  const summary = createActivityPeriodSummary({ period: { start: day, end: day }, anchor, status, first: { day, id: 1 } }, new Map());
  summary.add(rows);
  const view = summary.view();
  Object.assign(view.source, { timeZone, after: 0 });
  for (const app of view.apps) app.iconData = icons[app.id] ?? null;
  view.apps.sort((a, b) => b.records - a.records);
  const entry = { view, rows, catalog: view.apps.map(({ id, name, icon, type, records, first, last, iconData }) => ({ id, name, icon, type, records, first, last, iconData })) };
  days.set(key, entry);
  return entry;
}

const chunked = (data, offset, size, extra = {}) => {
  const bytes = Buffer.from(JSON.stringify(data)), end = Math.min(offset + size, bytes.length);
  return { content: [], structuredContent: { ...extra, chunk: bytes.subarray(offset, end).toString('base64'), nextOffset: end < bytes.length ? end : null } };
};
const megabytes = bytes => Math.round(bytes / 1e6);
const uploaded = megabytes(launcher.uploads.reduce((sum, upload) => sum + upload[3], 0));
const reviewed = id => id === launcher.id
  ? { status: 'attention', label: 'Needs review', reason: 'Sent ' + uploaded + ' MB to an address it first contacted at 13:41. Its files and signer did not change.' }
  : { status: 'normal', label: 'Normal', reason: 'Activity matches earlier days.' };

function review(day) {
  const { view } = dayView(day, 'daily');
  const source = { ...view.source, integrity: 'verified', reviewedRows: view.source.rowsRead, outsideDayRows: 0 };
  const applications = view.apps.map(app => reviewApplication({ ...app, review: reviewed(app.id) }));
  const report = {
    conclusion: 'One program needs your attention: Luma Launcher sent ' + uploaded + ' MB to an address it had never contacted.',
    activity: 'Visual Studio Code updated from 1.96.0 to 1.96.1 with the same signer. Zoom used the camera, microphone and screen from 10:31 to 11:22. Magnet holds its usual keyboard tap.',
    collection: 'All sensors were active. No gaps. 148 MB of the 1 GB limit is in use.',
    integrity: 'Every record since the last review matches the signed chain.'
  };
  const summary = { ...reviewCardSummary(source, applications), publicationHash: 'b'.repeat(64) };
  return { source, applications, report, summary };
}

function incident(day) {
  const at = timeOn(day), { rows } = dayView(day, 'alert');
  const evidence = rows.filter(row => row.app === launcher.app && JSON.parse(row.detail).remote === launcher.remote).map(row => {
    const detail = JSON.parse(row.detail);
    return { id: row.id, timestamp: row.first, kind: row.kind, app: row.app, path: row.path, pid: row.pid, remote: detail.remote, protocol: detail.protocol,
      ...(row.kind === 'network_bytes' && { sent: detail.tx_delta, appAggregate: false, executableAggregate: true }) };
  });
  return { id: '7c1e09d2b4a8f36e5d0c9a17', revision: 1, severity: 2, createdAt: at(13, 44, 40), verified: true,
    reasons: [text.reason('new_destination_send')], reasonCodes: ['new_destination_send'], evidence };
}

const resources = { open_activity_dashboard: 'dashboard', show_activity_incident: 'incident', show_activity_review: 'review' };
const toolInfo = name => ({ name, inputSchema: { type: 'object' }, _meta: { ui: { resourceUri: 'ui://activity-observer/' + resources[name] + '.html' } } });
function initialResult(tool) {
  const day = today();
  if (tool === 'open_activity_dashboard') return { tool: toolInfo(tool), arguments: {}, result: { content: [], structuredContent: { opened: true } } };
  if (tool === 'show_activity_incident') {
    const view = incident(day);
    return { tool: toolInfo(tool), arguments: { incidentId: view.id, revision: 1 }, result: { content: [{ type: 'text', text: 'Incident ' + view.id }], structuredContent: view } };
  }
  const { summary, report } = review(day);
  const reference = text.referenceLabel + ' ' + summary.through + '/' + summary.headHash + '/' + summary.publicationHash;
  return { tool: toolInfo(tool), arguments: { throughId: summary.through, expectedHeadHash: summary.headHash },
    result: { content: [{ type: 'text', text: reference }], structuredContent: { ...summary, report } } };
}

function call(name, args, scene) {
  if (name === 'read_activity_period_view') {
    const { view, catalog } = dayView(args.start, scene);
    const source = { ...view.source, day: args.start, start: args.start, end: args.end };
    const index = catalog.findIndex(app => app.id === args.programId);
    const data = args.programId === undefined
      ? { schema: 3, source, apps: [], catalog, applicationCount: catalog.length }
      : { schema: 3, source, apps: [view.apps[index]], catalog, applicationIndex: index, applicationCount: catalog.length };
    return chunked(data, args.offset, 32 * 1024, { periodId: args.periodId ?? randomUUID() });
  }
  const day = today();
  if (name === 'read_activity_review_cards') return { content: [], structuredContent: review(day).summary };
  if (name === 'read_activity_review_icons') return { content: [], structuredContent: { icons: Object.fromEntries(args.programIds.filter(id => icons[id]).map(id => [id, icons[id]])) } };
  if (name === 'read_activity_review_view') {
    const { source, applications, report } = review(day), { view } = dayView(day, 'daily');
    const programId = args.programId ?? applications[0].id, index = view.apps.findIndex(app => app.id === programId);
    const app = { ...view.apps[index], review: reviewed(programId) };
    return chunked({ schema: 3, source, report, apps: [app], publicationHash: 'b'.repeat(64), applicationIndex: index, applicationCount: applications.length,
      catalog: applications.map(({ id, name, records, icon, review }) => ({ id, name, records, icon, review, iconData: icons[id] ?? null })) }, args.offset, 8 * 1024);
  }
  if (name === 'read_activity_incident_view') return { content: [], structuredContent: incident(day) };
  return { isError: true, content: [{ type: 'text', text: 'Not available in the demo' }] };
}

const types = { '.css': 'text/css', '.png': 'image/png', '.html': 'text/html; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8' };
createServer(async (request, response) => {
  const url = new URL(request.url, 'http://127.0.0.1');
  const send = (type, body) => { response.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-store' }); response.end(body); };
  try {
    if (url.pathname === '/host.js') return send('text/javascript; charset=utf-8', host);
    if (url.pathname.startsWith('/widget/')) return send(types['.html'], widgets[url.pathname.slice(8, -5)] ?? '');
    if (url.pathname === '/result') return send('application/json', JSON.stringify(initialResult(url.searchParams.get('tool'))));
    if (url.pathname === '/call' && request.method === 'POST') {
      let body = '';
      for await (const chunk of request) body += chunk;
      const { name, arguments: args, scene } = JSON.parse(body);
      return send('application/json', JSON.stringify(call(name, args ?? {}, scene)));
    }
    const file = resolve(dir, '.' + url.pathname), type = types[/\.[a-z]+$/.exec(file)?.[0]];
    if (!file.startsWith(dir + '/') || !type || !existsSync(file)) { response.writeHead(404).end(); return; }
    send(type, readFileSync(file));
  } catch (error) { response.writeHead(500).end(String(error.message)); }
}).listen(port, '127.0.0.1', () => console.log('http://127.0.0.1:' + port));
