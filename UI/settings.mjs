import { lstatSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { installedUiDir } from './paths.mjs';
import { isTimeZone } from './zone.mjs';

// Optional settings written by the Mac's owner. They can name program groups
// and list programs whose keyboard, screen or audio access is expected. The
// detector reports every change to this file, so an edit cannot go unnoticed.
export const settingsPath = resolve(installedUiDir, 'settings.json');
export const accessKinds = ['keyboard', 'hid', 'screen', 'audio', 'camera'];
export const programTypes = ['app', 'tool', 'system', 'inventory', 'verification', 'records', 'program'];
const reservedGroups = new Set(['codex', 'claude', 'claudeCode', 'git', 'python', 'node', 'gh', 'system', 'observer', 'inventory', 'unresolved', 'files']);
const sizeLimit = 64 * 1024;

const text = (value, limit) => typeof value === 'string' && value.length > 0 && value.length <= limit && !/[\u0000-\u001f\u007f]/.test(value);
const textList = (value, limit = 32) => Array.isArray(value) && value.length > 0 && value.length <= limit && value.every(item => text(item, 1024));

function expectedAccess(entry) {
  if (!text(entry?.app, 1024) || !text(entry.path, 4096) || !entry.path.startsWith('/') ||
      !Array.isArray(entry.access) || !entry.access.length || entry.access.some(kind => !accessKinds.includes(kind))) {
    throw Error('Each expectedAccess entry needs app, an absolute path and access kinds');
  }
  return { app: entry.app, path: entry.path, access: [...new Set(entry.access)] };
}

function programGroup(entry, seen) {
  const match = entry?.match;
  const fields = ['app', 'appPrefix', 'pathPrefix', 'pathContains'].filter(name => match?.[name] !== undefined);
  // An entry with a built-in id adds rows to that group and keeps its name.
  const extension = reservedGroups.has(entry?.id);
  if (!/^[A-Za-z][A-Za-z0-9_-]{0,31}$/.test(entry?.id ?? '') || seen.has(entry.id) ||
      (extension ? entry.name !== undefined || entry.icon !== undefined || entry.type !== undefined : !text(entry.name, 80)) ||
      !fields.length || fields.some(name => !textList(match[name])) ||
      (entry.icon !== undefined && !/^[a-z0-9-]{1,40}$/.test(entry.icon)) ||
      (entry.type !== undefined && !programTypes.includes(entry.type)) ||
      (entry.order !== undefined && !['first', 'last'].includes(entry.order))) {
    throw Error('Each programGroups entry needs a unique id, a name and a match rule');
  }
  seen.add(entry.id);
  return { id: entry.id, ...(!extension && { name: entry.name, icon: entry.icon ?? 'app-window', type: entry.type ?? 'program' }),
    order: entry.order ?? 'first', match: Object.fromEntries(fields.map(name => [name, [...match[name]]])) };
}

export function parseSettings(source) {
  const data = JSON.parse(source);
  if (data?.schema !== 1 || Array.isArray(data)) throw Error('Unsupported settings schema');
  const seen = new Set();
  if (data.legacyTimeZone !== undefined && !isTimeZone(data.legacyTimeZone)) throw Error('legacyTimeZone is not a time zone');
  return {
    expectedAccess: (data.expectedAccess ?? []).slice(0, 64).map(expectedAccess),
    programGroups: (data.programGroups ?? []).slice(0, 64).map(entry => programGroup(entry, seen)),
    legacyTimeZone: data.legacyTimeZone
  };
}

const none = { expectedAccess: [], programGroups: [], legacyTimeZone: undefined };
let cached;

// A missing file means no settings. An unreadable or invalid file also yields
// none, with the reason in `issue`, so a broken edit never widens an allowance.
export function readSettings(path = settingsPath) {
  // Row-by-row callers ask often; the file is checked at most once a second.
  if (cached?.path === path && Date.now() - cached.checked < 1000) return cached.value;
  let info;
  try { info = lstatSync(path); }
  catch (error) {
    if (error.code === 'ENOENT') return { ...none, digest: null, issue: null };
    return { ...none, digest: null, issue: 'unreadable' };
  }
  if (cached?.path === path && cached.modified === info.mtimeMs && cached.size === info.size && cached.inode === info.ino) {
    cached.checked = Date.now();
    return cached.value;
  }
  let value;
  try {
    if (!info.isFile() || info.uid !== process.getuid() || (info.mode & 0o022) || info.size > sizeLimit) throw Error('Unsafe settings file');
    const source = readFileSync(path, 'utf8');
    value = { ...parseSettings(source), digest: createHash('sha256').update(source).digest('hex'), issue: null };
  } catch (error) {
    value = { ...none, digest: 'invalid', issue: String(error.message).slice(0, 160) };
  }
  cached = { path, modified: info.mtimeMs, size: info.size, inode: info.ino, value, checked: Date.now() };
  return value;
}
