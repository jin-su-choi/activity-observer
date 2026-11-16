import { accessSync, constants, existsSync, readdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { isAbsolute, resolve } from 'node:path';

// Locates an agent's command-line tool. Desktop apps bundle one that is not on
// the PATH, so their known locations are checked as well.
function executable(path) {
  if (!path || !isAbsolute(path)) return false;
  try { accessSync(path, constants.X_OK); return true; } catch { return false; }
}
const onPath = name => (process.env.PATH ?? '').split(':').filter(Boolean).map(entry => resolve(entry, name));

export function findCodex() {
  return [process.env.CODEX_CLI_PATH, process.env.CODEX_APP_RUNTIME_CLI_PATH,
    '/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex',
    '/Applications/Codex.app/Contents/Resources/codex', ...onPath('codex')].find(executable) ?? null;
}

export function findClaude() {
  const bundled = [];
  const versions = resolve(homedir(), 'Library/Application Support/Claude/claude-code');
  if (existsSync(versions)) {
    const newestFirst = readdirSync(versions).sort((a, b) => b.localeCompare(a, undefined, { numeric: true }));
    for (const version of newestFirst) {
      const builds = resolve(versions, version);
      try { for (const build of readdirSync(builds)) bundled.push(resolve(builds, build, 'claude.app/Contents/MacOS/claude')); } catch { /* Not a directory. */ }
    }
  }
  return [process.env.CLAUDE_CLI_PATH, ...onPath('claude'), resolve(homedir(), '.claude/local/claude'),
    resolve(homedir(), '.local/bin/claude'), ...bundled].find(executable) ?? null;
}
