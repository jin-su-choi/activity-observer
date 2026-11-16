import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, realpathSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { resolve } from 'node:path';
import { installedUiDir } from './published-review.mjs';
import { incidentDir } from './incident-store.mjs';

// Registers the real-time detector and the agent session that receives its
// alerts. The detector scans every 30 seconds as a per-user LaunchAgent.
const usage = 'Usage: install-incidents AGENT CLI PROJECT SESSION [--transcript PATH] [--after ID --previous-hash HASH] [--replace]';
const [agent, cli, project, sessionId, ...flags] = process.argv.slice(2);
const flag = name => { const index = flags.indexOf(name); return index >= 0 ? flags[index + 1] : undefined; };
const transcript = flag('--transcript'), after = flag('--after'), previousHash = flag('--previous-hash');
const replace = flags.includes('--replace');
if (!['codex', 'claude'].includes(agent) || !cli || !project || !sessionId || (agent === 'claude') !== Boolean(transcript) ||
    (after === undefined) !== (previousHash === undefined) || (after !== undefined && (!/^\d+$/.test(after) || !/^[a-f0-9]{64}$/.test(previousHash)))) {
  throw Error(usage);
}

const label = 'local.activity-observer.incidents';
const domain = 'gui/' + process.getuid();
const launchAgents = resolve(homedir(), 'Library/LaunchAgents');
const plist = resolve(launchAgents, label + '.plist');
const script = resolve(installedUiDir, 'incident-monitor.mjs');
const policy = resolve(installedUiDir, 'incident.sb');
const launcher = resolve(installedUiDir, 'incident-launch.sh');
const lock = resolve(incidentDir, 'scan.lock');
if (![script, policy, launcher].every(existsSync)) throw Error('Install Activity Observer first: ./setup.sh');

mkdirSync(incidentDir, { recursive: true, mode: 0o700 });
mkdirSync(launchAgents, { recursive: true });
const execute = (binary, args, timeout = 20000) => execFileSync(binary, args, { timeout, stdio: 'inherit' });
const scanner = (args, timeout) => execute('/usr/bin/lockf', ['-k', '-t', '5', lock, '/usr/bin/sandbox-exec',
  '-f', policy, process.execPath, script, ...args], timeout);
scanner(['isolation-check']);

// The monitor verifies that the session exists and belongs to the project.
const target = resolve(incidentDir, 'target.json');
const identity = { agent, command: realpathSync(cli), project: realpathSync(project), sessionId, transcript };
const same = (a, b) => typeof a === 'string' && typeof b === 'string' ? a.normalize('NFC') === b.normalize('NFC') : a === b;
const saved = existsSync(target) ? JSON.parse(readFileSync(target, 'utf8')) : null;
const unchanged = saved && Object.keys(identity).every(key => same(saved[key], identity[key]));
if (saved && !unchanged && !replace) throw Error('Alerts already go to another session. Pass --replace to move them.');
if (!unchanged) execute(process.execPath, [script, saved ? 'retarget' : 'configure', agent, cli, project, sessionId, ...(transcript ? [transcript] : [])], 60000);

// Without a state the detector first reads the retained log to learn what is
// usual on this Mac. Nothing is reported from that pass.
if (!existsSync(resolve(incidentDir, 'state.json'))) scanner(['seed', ...(after ? [after, previousHash] : [])], 900000);

const xml = text => String(text).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
const args = ['/usr/bin/lockf', '-k', '-t', '0', lock, '/bin/sh', launcher, process.execPath, script, policy];
const content = [
  '<?xml version="1.0" encoding="UTF-8"?>',
  '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
  '<plist version="1.0"><dict>',
  '  <key>Label</key><string>' + label + '</string>',
  '  <key>ProgramArguments</key><array>' + args.map(arg => '<string>' + xml(arg) + '</string>').join('') + '</array>',
  '  <key>WorkingDirectory</key><string>' + xml(installedUiDir) + '</string>',
  '  <key>RunAtLoad</key><true/>',
  '  <key>StartInterval</key><integer>30</integer>',
  '  <key>ProcessType</key><string>Background</string>',
  '  <key>Umask</key><integer>63</integer>',
  '</dict></plist>', ''
].join('\n');
const launch = (args, options) => execFileSync('/bin/launchctl', args, { timeout: 10000, stdio: ['ignore', 'pipe', 'pipe'], ...options });
const loaded = () => { try { launch(['print', domain + '/' + label]); return true; } catch { return false; } };
if (!existsSync(plist) || readFileSync(plist, 'utf8') !== content) {
  if (loaded()) launch(['bootout', domain + '/' + label]);
  const temporary = plist + '.' + process.pid + '.tmp';
  writeFileSync(temporary, content, { flag: 'wx', mode: 0o600 });
  renameSync(temporary, plist);
}
for (let attempt = 0; !loaded(); attempt++) {
  try { launch(['bootstrap', domain, plist]); }
  catch (error) {
    if (attempt >= 24) throw error;
    await new Promise(done => setTimeout(done, 200));
  }
}
console.log(JSON.stringify({ service: label, agent, sessionId, project: identity.project, pollSeconds: 30 }));
