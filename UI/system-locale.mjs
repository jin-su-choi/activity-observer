import { readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { resolve } from 'node:path';

// The MCP server and the incident monitor run under launchd without LANG, and
// their sandboxes cannot run the defaults tool. They read the preferred
// languages straight from the user's global preferences.
function binaryLanguages(data) {
  if (data.length < 40 || data.toString('latin1', 0, 8) !== 'bplist00') return [];
  const trailer = data.subarray(data.length - 32);
  const offsetSize = trailer[6], referenceSize = trailer[7];
  const count = Number(trailer.readBigUInt64BE(8)), top = Number(trailer.readBigUInt64BE(16)), table = Number(trailer.readBigUInt64BE(24));
  const unsigned = (position, size) => {
    if (position < 0 || position + size > data.length) throw RangeError('Invalid property list');
    let value = 0;
    for (let index = 0; index < size; index++) value = value * 256 + data[position + index];
    return value;
  };
  const offset = index => {
    if (index >= count) throw RangeError('Invalid property list');
    return unsigned(table + index * offsetSize, offsetSize);
  };
  const header = position => {
    const marker = unsigned(position, 1), type = marker >> 4;
    let length = marker & 15, body = position + 1;
    if (length === 15) {
      const size = 1 << (unsigned(body, 1) & 15);
      length = unsigned(body + 1, size);
      body += 1 + size;
    }
    return { type, length, body };
  };
  const string = index => {
    const { type, length, body } = header(offset(index));
    if (type === 5) return data.toString('latin1', body, body + length);
    if (type === 6) return Buffer.from(data.subarray(body, body + length * 2)).swap16().toString('utf16le');
    return null;
  };
  const root = header(offset(top));
  if (root.type !== 13) return [];
  for (let index = 0; index < root.length; index++) {
    if (string(unsigned(root.body + index * referenceSize, referenceSize)) !== 'AppleLanguages') continue;
    const list = header(offset(unsigned(root.body + (root.length + index) * referenceSize, referenceSize)));
    if (list.type !== 10) return [];
    return Array.from({ length: Math.min(list.length, 8) }, (_, item) => string(unsigned(list.body + item * referenceSize, referenceSize)))
      .filter(language => typeof language === 'string');
  }
  return [];
}

export function parsePreferredLanguages(data) {
  try {
    if (data.toString('latin1', 0, 6) === 'bplist') return binaryLanguages(data);
    const list = /<key>AppleLanguages<\/key>\s*<array>([\s\S]*?)<\/array>/.exec(data.toString('utf8'));
    return list ? [...list[1].matchAll(/<string>([^<]*)<\/string>/g)].map(match => match[1]) : [];
  } catch { return []; }
}

const preferences = resolve(homedir(), 'Library/Preferences/.GlobalPreferences.plist');
let cached;

// Returns macOS preferred languages, most preferred first. Environment locale
// variables are the fallback for shells and other systems.
export function systemLanguages(path = preferences) {
  let languages = [];
  try {
    const info = statSync(path);
    if (cached?.path === path && cached.modified === info.mtimeMs && cached.size === info.size) return cached.languages;
    if (info.isFile() && info.size <= 8 * 1024 * 1024) languages = parsePreferredLanguages(readFileSync(path));
    if (languages.length) cached = { path, modified: info.mtimeMs, size: info.size, languages };
  } catch { /* Fall back to the environment. */ }
  return languages.length ? languages : [process.env.LC_ALL, process.env.LC_MESSAGES, process.env.LANG].filter(Boolean);
}
