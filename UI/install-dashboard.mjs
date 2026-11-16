import { execFileSync } from 'node:child_process';
import { copyFile, cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { installedUiDir } from './published-review.mjs';
import { observerUrl } from './paths.mjs';
import { homedir } from 'node:os';
import { serverI18n } from './i18n-server.mjs';
import { findCodex } from './agent-cli.mjs';
import { pluginVersion } from './plugin-version.mjs';

const ui = dirname(fileURLToPath(import.meta.url));
const name = 'activity-observer';
const marketplace = 'activity-observer-local';
const root = resolve(installedUiDir, '../dashboard-marketplace');
const iconPath = './assets/activity-observer.png';
// Plugin metadata is written once, in the macOS language at install time.
const { s } = serverI18n();
const description = s('plugin.description');
// The shared local server and its token are created by the installation.
const connection = JSON.parse(await readFile(resolve(installedUiDir, 'connection.json'), 'utf8').catch(() => 'null'));
if (connection?.url !== observerUrl || !/^[a-f0-9]{64}$/.test(connection.token)) throw Error('Install Activity Observer first: ./setup.sh');
const server = { url: connection.url, headers: { Authorization: 'Bearer ' + connection.token } };
const codexBinary = findCodex();
if (!codexBinary) throw Error('Codex CLI was not found. Set CODEX_CLI_PATH to its absolute executable path.');
const codex = args => execFileSync(codexBinary, ['plugin', ...args], { cwd: ui, encoding: 'utf8', timeout: 45000 });
const registered = codex(['marketplace', 'list']).split('\n').find(line => line.startsWith(marketplace + ' '));
if (registered && registered.slice(marketplace.length).trim() !== root) throw Error('The marketplace name is already in use');

async function writeJson(path, data) {
  const file = resolve(root, path);
  await mkdir(dirname(file), { recursive: true, mode: 0o700 });
  await writeFile(file, JSON.stringify(data, null, 2) + '\n', { mode: 0o600 });
}

const pluginIcon = resolve(root, 'plugins/activity-observer', iconPath);
await mkdir(dirname(pluginIcon), { recursive: true, mode: 0o700 });
await copyFile(resolve(ui, iconPath), pluginIcon);
await writeJson('plugins/activity-observer/.codex-plugin/plugin.json', {
  name, version: pluginVersion, description, requires_local_executor: true, mcpServers: './.mcp.json', skills: './skills/',
  interface: { displayName: 'Activity Observer', shortDescription: s('plugin.short'), longDescription: description,
    category: 'Productivity', logo: iconPath, composerIcon: iconPath, defaultPrompt: [s('plugin.prompt')] },
  extensions: { 'com.openai': { onboardingSkill: './skills/setup/SKILL.md' } }
});
// The skills are replaced as a whole so that a removed one does not linger.
await rm(resolve(root, 'plugins/activity-observer/skills'), { recursive: true, force: true });
await cp(resolve(ui, 'skills'), resolve(root, 'plugins/activity-observer/skills'), { recursive: true });
await writeJson('plugins/activity-observer/.mcp.json', {
  // Codex uses http_headers; Claude's HTTP configuration uses headers.
  mcpServers: { 'activity-observer': { type: 'http', url: server.url, http_headers: server.headers } }
});
await writeJson('.agents/plugins/marketplace.json', {
  name: marketplace, interface: { displayName: s('plugin.marketplace') },
  plugins: [{ name, source: { source: 'local', path: './plugins/activity-observer' },
    policy: { installation: 'AVAILABLE', authentication: 'ON_INSTALL' }, category: 'Productivity' }]
});

if (!registered) codex(['marketplace', 'add', root, '--json']);
JSON.parse(codex(['add', `${name}@${marketplace}`, '--json']));
const userConfig = await readFile(resolve(homedir(), '.codex/config.toml'), 'utf8');
for (const oldName of ['activity-observer', 'activity-observer-dashboard']) {
  if (userConfig.includes(`[mcp_servers.${oldName}]`)) {
    execFileSync(codexBinary, ['mcp', 'remove', oldName], { encoding: 'utf8', timeout: 15000 });
  }
}
// Connected clients can retain old stdio workers after config reload. They
// reconnect through HTTP, or through the small compatibility adapter.
const oldEntry = resolve(installedUiDir, 'mcp-server.mjs');
const oldCommands = new Set([
  process.execPath + ' ' + oldEntry + ' --stdio',
  process.execPath + ' ' + oldEntry + ' --stdio --dashboard'
]);
const processes = execFileSync('/bin/ps', ['-U', String(process.getuid()), '-o', 'pid=,command='], { encoding: 'utf8' });
let retired = 0;
for (const line of processes.split('\n')) {
  const match = /^\s*(\d+)\s+(.*)$/.exec(line);
  if (!match || !oldCommands.has(match[2])) continue;
  const pid = Number(match[1]);
  try {
    const current = execFileSync('/bin/ps', ['-p', String(pid), '-o', 'command='], { encoding: 'utf8' }).trim();
    if (oldCommands.has(current)) { process.kill(pid, 'SIGTERM'); retired++; }
  } catch (error) { if (error.code !== 'ESRCH' && error.status !== 1) throw error; }
}
console.log(JSON.stringify({ installed: true, plugin: `${name}@${marketplace}`, version: pluginVersion, retiredWorkers: retired }));
