import { canonicalToken } from './i18n.mjs';

// Rows are grouped into programs for display. Built-in groups cover the agents
// themselves, common developer tools and macOS services. Everything else is
// grouped by the identifier the collector recorded, which is the bundle
// identifier of the outermost app bundle or the executable name.
const type = key => canonicalToken('type', key);
const builtin = {
  codex: ['Codex', 'square-terminal', type('app')],
  git: ['Git', 'git-branch', type('tool')],
  claude: ['Claude', 'asterisk', type('app')],
  python: ['Python', 'braces', type('tool')],
  claudeCode: ['Claude Code', 'terminal', type('tool')],
  node: ['Node.js', 'hexagon', type('tool')],
  gh: ['GitHub CLI', 'git-pull-request', type('tool')],
  system: [canonicalToken('program', 'system'), 'component', type('system')],
  observer: ['Activity Observer', 'shield-check', type('system')],
  inventory: [canonicalToken('program', 'inventory'), 'package', type('inventory')],
  unresolved: [canonicalToken('program', 'unresolved'), 'file-question', type('records')],
  files: [canonicalToken('program', 'files'), 'file-lock', type('records')]
};

// "/Applications/Foo.app/Contents/..." is shown as "Foo".
export function bundleName(path) {
  const match = typeof path === 'string' && /^(.*?\/([^/]+)\.app)(?:\/|$)/.exec(path);
  return match ? match[2] : null;
}

function matches(group, app, path) {
  const { match } = group;
  return Boolean(match.app?.includes(app) || match.appPrefix?.some(prefix => app.startsWith(prefix)) ||
    match.pathPrefix?.some(prefix => path.startsWith(prefix)) || match.pathContains?.some(part => path.includes(part)));
}

export function createPrograms(groups = []) {
  const first = groups.filter(group => group.order !== 'last'), last = groups.filter(group => group.order === 'last');
  const custom = new Map(groups.filter(group => group.name).map(group => [group.id, [group.name, group.icon, type(group.type)]]));
  function identity(row) {
    const a = row.app || '', p = row.path || '';
    if (!p && row.kind.startsWith('network_')) return 'unresolved';
    if (a === 'sensitive-file' && row.kind === 'sensitive_file_changed') return 'files';
    for (const group of first) if (matches(group, a, p)) return group.id;
    if (a === 'com.openai.codex' || a === 'codex' || a === 'com.openai.sky.CUAService' ||
        p.startsWith('/Applications/ChatGPT.app/') || p.startsWith('/Applications/Codex.app/')) return 'codex';
    if (a === 'com.anthropic.claude-code') return 'claudeCode';
    if (a === 'com.anthropic.claudefordesktop') return 'claude';
    if (a === 'gh') return 'gh';
    if (a === 'node') return 'node';
    if (a.startsWith('python') || a === 'com.apple.python3') return 'python';
    if (a.startsWith('git') || a === 'scalar') return 'git';
    if (p.startsWith('/opt/homebrew/')) return 'inventory';
    if (a.includes('activity-observer') || a === 'protected-writer') return 'observer';
    for (const group of last) if (matches(group, a, p)) return group.id;
    if (a === 'macOS.capture-service' || p.startsWith('/System/') || a === 'trustd') return 'system';
    return `other:${a}`;
  }
  // Returns [name, icon, type, named]. `named` is false while the name is only
  // the recorded identifier and a later row may still supply the bundle name.
  function describe(id, row) {
    const known = custom.get(id) ?? builtin[id];
    if (known) return [...known, true];
    const name = bundleName(row.path);
    return [name ?? row.app, 'app-window', type('program'), Boolean(name)];
  }
  return { identity, describe };
}
