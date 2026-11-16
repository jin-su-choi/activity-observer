import { execFileSync } from 'node:child_process';
import { cpSync, existsSync, lstatSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { installedUiDir } from './published-review.mjs';
import { observerUrl } from './paths.mjs';
import { findClaude } from './agent-cli.mjs';
import { pluginVersion } from './plugin-version.mjs';

// Registers the Claude Code plugin: the skills and a connection to the local
// MCP server. Claude connects through a small sandboxed relay, so no token is
// written into a plugin file.
const ui = dirname(fileURLToPath(import.meta.url));
const name = 'activity-observer', marketplace = 'activity-observer-local';
const root = resolve(installedUiDir, '../claude-marketplace');
const plugin = resolve(root, 'plugins', name);
const relay = resolve(installedUiDir, 'mcp-relay');
const relayPolicy = '/Library/Application Support/ActivityObserver/policies/relay.sb';
const server = { command: '/usr/bin/sandbox-exec', args: ['-D', 'AO_RELAY=' + relay, '-f', relayPolicy, relay] };
if (!existsSync(relay) || !existsSync(relayPolicy)) throw Error('Install Activity Observer first: ./setup.sh');

function writeJson(path, data, mode = 0o600) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = path + '.' + process.pid + '.tmp';
  writeFileSync(temporary, JSON.stringify(data, null, 2) + '\n', { mode, flag: 'wx' });
  renameSync(temporary, path);
}

rmSync(plugin, { recursive: true, force: true });
writeJson(resolve(root, '.claude-plugin/marketplace.json'), {
  name: marketplace, owner: { name: 'Activity Observer' }, metadata: { description: 'Activity Observer, built and installed from source on this Mac.' },
  plugins: [{ name, source: './plugins/' + name, description: 'Turn your agent into the security reviewer of this Mac.' }]
});
writeJson(resolve(plugin, '.claude-plugin/plugin.json'), {
  name, version: pluginVersion, description: 'Review what programs do on this Mac: daily reviews, real-time alerts and an activity dashboard backed by a signed local log.',
  author: { name: 'Activity Observer contributors' }, license: 'MIT'
});
writeJson(resolve(plugin, '.mcp.json'), { mcpServers: { [name]: server } });
writeFileSync(resolve(plugin, 'README.md'), [
  '# Activity Observer', '',
  'Turns your agent into the security reviewer of this Mac. The plugin connects Claude Code to the local Activity Observer',
  'server, which serves a signed log of what programs did: network connections, input and screen access, installs,',
  'autostart items and changes to sensitive files. Its skills teach the agent to work as a security analyst:',
  'setup, security-analyst, daily-review, incident-review and deep-inspection. Every review ends in a verdict.', '',
  'The collector has to be installed first with setup.sh from the repository. Then say: Set up Activity Observer.', ''
].join('\n'), { mode: 0o600 });
cpSync(resolve(ui, 'skills'), resolve(plugin, 'skills'), { recursive: true });

// Entries that earlier versions wrote outside the plugin are replaced by it.
const ours = entry => entry?.url === observerUrl || entry?.args?.some?.(value => typeof value === 'string' && value.endsWith('/mcp-relay'));
const replaceJson = (path, data) => {
  const temporary = path + '.activity-observer.tmp';
  writeFileSync(temporary, JSON.stringify(data, null, 2) + '\n', { mode: lstatSync(path).mode & 0o777 });
  renameSync(temporary, path);
};
const claudeState = resolve(homedir(), '.claude.json');
if (existsSync(claudeState)) {
  const data = JSON.parse(readFileSync(claudeState, 'utf8'));
  let changed = false;
  for (const scope of [data, ...Object.values(data.projects ?? {})]) {
    if (ours(scope?.mcpServers?.[name])) { delete scope.mcpServers[name]; changed = true; }
  }
  if (changed) replaceJson(claudeState, data);
}
// Claude Desktop chats use the same relay.
const desktop = resolve(homedir(), 'Library/Application Support/Claude/claude_desktop_config.json');
let desktopConfigured = false;
if (existsSync(desktop)) {
  const data = JSON.parse(readFileSync(desktop, 'utf8'));
  data.mcpServers = { ...data.mcpServers, [name]: server };
  replaceJson(desktop, data);
  desktopConfigured = true;
}

const claude = findClaude();
let registered = false, note;
if (!claude) note = 'Claude Code was not found. Set CLAUDE_CLI_PATH to its absolute path and run this again.';
else {
  const run = args => execFileSync(claude, ['plugin', ...args], { encoding: 'utf8', timeout: 90000, stdio: ['ignore', 'pipe', 'pipe'] });
  const output = error => String(error.stderr ?? '') + String(error.stdout ?? '');
  // The reason is on the error stream. Progress text goes to the other one.
  const reason = error => (String(error.stderr ?? '').trim() || String(error.stdout ?? '').trim() || error.message).split('\n').at(-1).slice(0, 400);
  try {
    run(['validate', plugin]);
    try { run(['marketplace', 'add', root]); }
    catch (error) { if (!/already/i.test(output(error))) throw error; run(['marketplace', 'update', marketplace]); }
    try { run(['install', name + '@' + marketplace]); }
    catch (error) { if (!/already installed/i.test(output(error))) throw error; run(['update', name + '@' + marketplace]); }
    registered = true;
  } catch (error) {
    note = 'Claude Code did not accept the registration: ' + reason(error) +
      ' Register it by hand: claude plugin marketplace add "' + root + '" and then claude plugin install ' + name + '@' + marketplace;
  }
}
console.log(JSON.stringify({ plugin: name + '@' + marketplace, version: pluginVersion, path: plugin, registered, desktopConfigured, ...(note && { note }) }));
