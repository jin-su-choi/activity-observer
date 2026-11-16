import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { collectReviewSnapshot, prepareViewData } from './build-widget.mjs';
import { installedReviewDir, installedUiDir, reviewReportSchema } from './published-review.mjs';
import { readReviewPublication, reviewPublication, reviewPublicationHash, saveReviewPublication } from './review-history.mjs';
import { buildReviewDigest } from './review-digest.mjs';
import { readSettings, settingsPath } from './settings.mjs';
import { findClaude, findCodex } from './agent-cli.mjs';

// The command-line entry point that agents and people use after installation:
//   observer doctor                      installation and service health
//   observer review begin|publish|last   the daily review
//   observer alerts here|status|target   where real-time alerts are delivered
//   observer connect codex|claude        register the plugin with an agent
const dir = dirname(fileURLToPath(import.meta.url));
const monitor = resolve(dir, 'incident-monitor.mjs');
const print = value => console.log(JSON.stringify(value));
const option = (args, name) => { const index = args.indexOf(name); return index >= 0 ? args[index + 1] : undefined; };
const hash = /^[a-f0-9]{64}$/;

function lastPublication() {
  const publication = readReviewPublication(installedReviewDir);
  return publication && { day: publication.source.day, after: publication.source.after, through: publication.source.through,
    headHash: publication.source.anchor.payload.head_hash, publicationHash: reviewPublicationHash(publication) };
}

function reviewBegin(args) {
  const after = option(args, '--after'), previousHash = option(args, '--previous-hash');
  let start, source = 'log_start';
  if (after !== undefined || previousHash !== undefined) {
    if (!/^\d+$/.test(after ?? '') || !hash.test(previousHash ?? '')) throw Error('Use --after ID together with --previous-hash HASH');
    start = { after: Number(after), previousHash }; source = 'argument';
  } else {
    const last = lastPublication();
    if (last) { start = { after: last.through, previousHash: last.headHash }; source = 'last_publication'; }
  }
  const digest = buildReviewDigest(start);
  digest.start.source = digest.start.uncovered ? 'retention_boundary' : source;
  print(digest);
}

function reviewPublish() {
  // Inputs describe a completed review. The exact interval is verified again
  // against the signed log before anything is stored.
  const { anchor, after, previousHash, day, findings, report } = JSON.parse(readFileSync(0, 'utf8'));
  const narrative = report === undefined ? undefined : reviewReportSchema.parse(report);
  const head = anchor?.payload;
  let publication = head && readReviewPublication(installedReviewDir, head.head_id, head.head_hash);
  if (publication) {
    if (publication.source.after !== after || publication.source.day !== day || publication.previousHash !== previousHash) {
      throw Error('The requested interval differs from the published review');
    }
  } else {
    const data = collectReviewSnapshot({ anchor, after, previousHash, day, reviewedOnly: true });
    const view = prepareViewData(data, findings);
    if (narrative) view.report = narrative;
    publication = saveReviewPublication(installedReviewDir, reviewPublication(view, previousHash), view.apps);
  }
  const { through, rowsRead, reviewedRows, outsideDayRows, dayRows } = publication.source;
  print({ day, after, through, headHash: head.head_hash, publicationHash: reviewPublicationHash(publication), rowsRead, reviewedRows, outsideDayRows, dayRows,
    applications: publication.applications.map(({ id, name, records, review }) => ({ id, name, records, review })) });
}

function runMonitor(args, options = {}) {
  return execFileSync(process.execPath, [monitor, ...args], { encoding: 'utf8', timeout: 120000, ...options });
}

function claudeTranscript(session) {
  const projects = resolve(homedir(), '.claude/projects');
  for (const entry of existsSync(projects) ? readdirSync(projects) : []) {
    const path = resolve(projects, entry, session + '.jsonl');
    if (existsSync(path)) return path;
  }
  throw Error('The Claude Code transcript for this session was not found');
}

// Points alerts at the agent session that runs this command.
function alertsHere(args) {
  const environment = process.env;
  const agent = option(args, '--agent') ?? (environment.CODEX_THREAD_ID ? 'codex' : environment.CLAUDECODE ? 'claude' : undefined);
  const session = option(args, '--session') ?? (agent === 'codex' ? environment.CODEX_THREAD_ID : environment.CLAUDE_CODE_SESSION_ID ?? environment.CLAUDE_SESSION_ID);
  const project = realpathSync(option(args, '--project') ?? process.cwd());
  if (!['codex', 'claude'].includes(agent) || !session) throw Error('Run this inside a Codex or Claude Code session, or pass --agent and --session');
  const executable = option(args, '--cli') ?? (agent === 'codex' ? findCodex() : findClaude());
  if (!executable) throw Error('The ' + agent + ' command was not found. Pass --cli with its absolute path.');
  const installer = resolve(dir, 'install-incidents.mjs');
  const result = spawnSync(process.execPath, [installer, agent, executable, project, session, '--replace',
    ...(agent === 'claude' ? ['--transcript', claudeTranscript(session)] : [])], { encoding: 'utf8', timeout: 300000 });
  if (result.status !== 0) throw Error((result.stderr || result.stdout || 'Alert setup failed').trim().slice(-600));
  process.stdout.write(result.stdout.trim().split('\n').at(-1) + '\n');
}

// The agent installers and the skills they copy live in the active release.
function connect(agent) {
  const { release } = JSON.parse(readFileSync(resolve(installedUiDir, 'release.json'), 'utf8'));
  if (typeof release !== 'string' || !release.startsWith(resolve(installedUiDir, 'releases') + '/')) throw Error('Unexpected release location');
  const installer = resolve(release, agent === 'codex' ? 'install-dashboard.mjs' : 'install-claude.mjs');
  const result = spawnSync(process.execPath, [installer], { encoding: 'utf8', timeout: 240000 });
  if (result.status !== 0) throw Error((result.stderr || result.stdout || 'Registration failed').trim().slice(-600));
  process.stdout.write(result.stdout.trim().split('\n').at(-1) + '\n');
}

function doctor() {
  const launch = label => {
    try { return /^\s*pid = \d+$/m.test(execFileSync('/bin/launchctl', ['print', 'gui/' + process.getuid() + '/' + label], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })) ? 'running' : 'loaded'; }
    catch { return 'not loaded'; }
  };
  const report = { installed: existsSync('/Library/PrivilegedHelperTools/local.activity-observer'), ui: installedUiDir,
    services: { mcp: launch('local.activity-observer.mcp'), alerts: launch('local.activity-observer.incidents') } };
  const settings = readSettings();
  report.settings = { path: settingsPath, present: settings.digest !== null, issue: settings.issue,
    expectedAccess: settings.expectedAccess.length, programGroups: settings.programGroups.length };
  for (const [name, args] of [['alerts', ['status']], ['target', ['target']]]) {
    try { report[name] = JSON.parse(runMonitor(args)); } catch (error) { report[name] = { error: String(error.stderr || error.message).trim().slice(0, 200) }; }
  }
  try { report.lastReview = lastPublication(); } catch (error) { report.lastReview = { error: error.message }; }
  try {
    const context = spawnSync(process.execPath, [monitor, 'isolation-check'], { encoding: 'utf8', timeout: 30000 });
    report.collector = context.status === 0 ? 'reachable' : (context.stderr || 'unreachable').trim().slice(0, 200);
  } catch (error) { report.collector = error.message; }
  print(report);
}

const [group, command, ...args] = process.argv.slice(2);
try {
  if (group === 'doctor' && command === undefined) doctor();
  else if (group === 'review' && command === 'begin') reviewBegin(args);
  else if (group === 'review' && command === 'publish' && !args.length) reviewPublish();
  else if (group === 'review' && command === 'last' && !args.length) print(lastPublication());
  else if (group === 'alerts' && command === 'here') alertsHere(args);
  else if (group === 'connect' && ['codex', 'claude'].includes(command) && !args.length) connect(command);
  else if (group === 'alerts' && ['status', 'target'].includes(command) && !args.length) process.stdout.write(runMonitor([command]));
  else if (group === 'alerts' && command === 'replay') process.stdout.write(runMonitor(['replay', ...args], { timeout: 900000 }));
  else throw Error('Use: observer doctor | review begin [--after ID --previous-hash HASH] | review publish | review last | alerts here | alerts status | alerts target | alerts replay [AFTER HASH] | connect codex|claude');
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
