import { execFileSync } from 'node:child_process';
import { randomBytes, createHash } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { installedUiDir } from './published-review.mjs';
import { observerPort, observerUrl } from './paths.mjs';

const dir = dirname(fileURLToPath(import.meta.url));
const domain = `gui/${process.getuid()}`;
const label = 'local.activity-observer.mcp';
const job = domain + '/' + label;
const policy = '/Library/Application Support/ActivityObserver/policies/mcp-http.sb';
const relayPolicy = '/Library/Application Support/ActivityObserver/policies/relay.sb';
// Starts the shared local MCP server. Agents are connected by install-dashboard.mjs
// (Codex) and install-claude.mjs (Claude).
const privateFile = (path, text, mode = 0o600) => {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = path + '.' + process.pid + '.tmp';
  writeFileSync(temporary, text, { mode, flag: 'wx' });
  renameSync(temporary, path);
};
for (const path of [policy, relayPolicy]) {
  const info = lstatSync(path);
  const hash = data => createHash('sha256').update(data).digest('hex');
  if (!info.isFile() || info.uid !== 0 || info.mode & 0o022 ||
      hash(readFileSync(path)) !== hash(readFileSync(resolve(dir, typeof AO_PREPARED_RELEASE !== 'undefined' && AO_PREPARED_RELEASE ? 'Policies' : '../Policies', path.split('/').at(-1))))) {
    throw Error('Install the approved root-owned MCP policies first');
  }
}
const connectionPath = resolve(installedUiDir, 'connection.json');
if (!existsSync(connectionPath)) privateFile(connectionPath,
  JSON.stringify({ url: observerUrl, token: randomBytes(32).toString('hex') }) + '\n');
const info = lstatSync(connectionPath);
if (!info.isFile() || info.uid !== process.getuid() || info.mode & 0o077) throw Error('Unexpected MCP connection permissions');
const connection = JSON.parse(readFileSync(connectionPath, 'utf8'));
if (connection.url !== observerUrl || !/^[a-f0-9]{64}$/.test(connection.token)) throw Error('Unexpected MCP connection');
const xml = value => value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
const arguments_ = ['/usr/bin/sandbox-exec', '-D', 'AO_NODE=' + process.execPath, '-f', policy,
  process.execPath, resolve(installedUiDir, 'shared-server.mjs')];
const plist = resolve(homedir(), 'Library/LaunchAgents', label + '.plist');
privateFile(plist, `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>${label}</string>
<key>ProgramArguments</key><array>${arguments_.map(value => '<string>' + xml(value) + '</string>').join('')}</array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>10</integer>
<key>ProcessType</key><string>Background</string><key>LowPriorityIO</key><true/>
<key>StandardOutPath</key><string>/dev/null</string><key>StandardErrorPath</key><string>/dev/null</string>
</dict></plist>\n`);
const launch = args => execFileSync('/bin/launchctl', args, { timeout: 10000, stdio: ['ignore', 'pipe', 'pipe'] });
let loaded = false;
try { launch(['print', job]); loaded = true; } catch {}
if (loaded) launch(['bootout', job]);
// launchd can return from bootout before the old registration is released.
// Give that transition a bounded retry instead of leaving the service stopped.
for (let attempt = 0; ; attempt++) {
  try { launch(['bootstrap', domain, plist]); break; }
  catch (error) {
    if (error.status !== 5 || attempt >= 24) throw error;
    await new Promise(resolve => setTimeout(resolve, 200));
  }
}
const auth = { Authorization: 'Bearer ' + connection.token };
let healthy = false;
for (let i = 0; i < 30; i++) {
  try {
    const response = await fetch(observerUrl.replace('/mcp', '/health'), { headers: auth, signal: AbortSignal.timeout(1000) });
    const result = response.ok && await response.json();
    const jobState = launch(['print', job]).toString();
    const pid = Number(/^\s*pid = (\d+)$/m.exec(jobState)?.[1]);
    healthy = result?.healthy && Number.isSafeInteger(pid) && pid > 0 && result.pid === pid;
    if (healthy) break;
  } catch {}
  await new Promise(resolve => setTimeout(resolve, 200));
}
if (!healthy) {
  launch(['bootout', job]);
  throw Error('The isolated local MCP server did not become healthy');
}
privateFile(resolve(dir, 'dist/shared-mcp-config.json'), JSON.stringify({
  mcpServers: { 'activity-observer': { type: 'http', url: observerUrl, headers: auth } }
}, null, 2) + '\n');

console.log(JSON.stringify({ service: label, port: observerPort, isolated: true }));
