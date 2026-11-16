// Synthetic activity for the README images: one day on a fictional Mac.
// Addresses come from the ranges reserved for documentation (RFC 5737).
import { createHash } from 'node:crypto';

export const timeZone = 'America/Los_Angeles';
export const timeOn = day => (hour, minute = 0, second = 0) =>
  Date.parse(`${day}T${[hour, minute, second].map(part => String(part).padStart(2, '0')).join(':')}-08:00`) / 1000;

const kb = 1e3, mb = 1e6;
const programs = {
  safari: ['com.apple.Safari', '/Applications/Safari.app/Contents/MacOS/Safari', 612],
  slack: ['com.tinyspeck.slackmacgap', '/Applications/Slack.app/Contents/MacOS/Slack', 733],
  zoom: ['us.zoom.xos', '/Applications/zoom.us.app/Contents/MacOS/zoom.us', 2190],
  code: ['com.microsoft.VSCode', '/Applications/Visual Studio Code.app/Contents/MacOS/Electron', 901],
  codex: ['com.openai.codex', '/Applications/ChatGPT.app/Contents/MacOS/ChatGPT', 540],
  claude: ['com.anthropic.claude-code', '/Users/alex/.local/share/claude/versions/2.1.321/claude', 1877],
  drive: ['com.google.drivefs', '/Applications/Google Drive.app/Contents/MacOS/Google Drive', 688],
  figma: ['com.figma.Desktop', '/Applications/Figma.app/Contents/MacOS/Figma', 1204],
  magnet: ['com.crowdcafe.windowmagnet', '/Applications/Magnet.app/Contents/MacOS/Magnet', 598],
  launcher: ['com.lumagames.launcher', '/Applications/Luma Launcher.app/Contents/MacOS/Luma Launcher', 4821],
  git: ['git-remote-https', '/opt/homebrew/Cellar/git/2.47.1/libexec/git-core/git-remote-https', 0],
  node: ['node', '/opt/homebrew/Cellar/node/22.11.0/bin/node', 3310],
  trustd: ['trustd', '/usr/libexec/trustd', 211]
};
// How busy each hour is, from 0 to 1.
const pace = [0, 0, 0, 0, 0, 0, 0, 0, .3, .8, 1, .9, .4, .85, 1, .95, .8, .6, .35, .3, .45, .4, .25, .1];
// Program, traffic blocks in a busy hour, first and last hour, destination,
// protocol, bytes received and sent per block.
const routine = [
  ['safari', 6, 8, 23, '198.51.100.14:443', 'tcp', 7.6 * mb, 270 * kb],
  ['safari', 2, 9, 22, '198.51.100.88:443', 'udp', 18 * mb, 700 * kb],
  ['codex', 5, 9, 22, '198.51.100.130:443', 'tcp', 1.5 * mb, 1.1 * mb],
  ['slack', 3.5, 8, 18, '198.51.100.40:443', 'tcp', 560 * kb, 86 * kb],
  ['claude', 4, 10, 18, '198.51.100.152:443', 'tcp', 830 * kb, 510 * kb],
  ['code', 1.2, 9, 18, '198.51.100.61:443', 'tcp', 1.1 * mb, 240 * kb],
  ['git', 2.5, 9, 18, '198.51.100.77:443', 'tcp', 560 * kb, 78 * kb],
  ['node', 1.2, 10, 17, '198.51.100.93:443', 'tcp', 1.4 * mb, 96 * kb],
  ['figma', 2, 13, 17, '198.51.100.170:443', 'tcp', 6 * mb, 900 * kb],
  ['drive', .8, 8, 23, '198.51.100.115:443', 'tcp', 2.6 * mb, 3.9 * mb],
  ['trustd', .9, 8, 23, '198.51.100.201:443', 'tcp', 90 * kb, 14 * kb]
];

export const launcher = { id: 'other:com.lumagames.launcher', app: programs.launcher[0], path: programs.launcher[1], pid: programs.launcher[2],
  usual: '198.51.100.20:443', remote: '203.0.113.77:443',
  // What the launcher sent to the address it had never contacted: [hour, minute, second, bytes].
  uploads: [[13, 41, 4, 9 * mb], [13, 42, 30, 14 * mb], [13, 44, 10, 18 * mb]],
  icon: 'data:image/png;base64,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' };

export function demoRows(day) {
  const at = timeOn(day), rows = [];
  let seed = 20261116;
  // Deterministic variation, so the charts look like a day and render the same every time.
  const random = () => (seed = (seed * 1664525 + 1013904223) >>> 0) / 2 ** 32;
  const add = (kind, [app, path, pid], first, last, count, detail, source = 'networkstatistics') =>
    rows.push({ kind, app, path, pid, count, first, last, day, source, priority: 1, detail: JSON.stringify(detail) });
  // One block of traffic: the connections, then the bytes of the same minute.
  const traffic = (program, start, remote, protocol, opens, received, sent) => {
    add('network_open', program, start, start + 40, opens, { remote, protocol, process_name: program[1].split('/').pop() });
    add('network_bytes', [program[0], program[1], 0], start, start + 55, 1, { remote, protocol, rx_delta: Math.round(received), tx_delta: Math.round(sent),
      samples: 12, interval_start: start, interval_end: start + 55, aggregated_by_application: false, aggregated_by_executable: true });
  };
  const moment = (kind, name, time, detail = {}, source = 'nsworkspace') => add(kind, programs[name], time, time, 1, detail, source);
  const usage = (kind, name, from, to) => {
    const detail = { evidence: 'OS active usage attribution', attribution: kind.slice(0, 3) + ':' + programs[name][0] };
    moment(kind + '_started', name, from, detail, 'os_privacy_attribution');
    moment(kind + '_stopped', name, to, detail, 'os_privacy_attribution');
  };

  for (const [name, rate, from, to, remote, protocol, received, sent] of routine) {
    for (let hour = from; hour <= to; hour++) {
      const blocks = Math.round(rate * pace[hour] * (.6 + .8 * random()));
      for (let block = 0; block < blocks; block++) {
        const weight = .4 + 1.2 * random();
        traffic(programs[name], at(hour, Math.floor(random() * 58), Math.floor(random() * 60)), remote, protocol,
          1 + Math.floor(random() * 6), received * weight, sent * weight);
      }
    }
  }
  moment('keyboard_observer_active', 'magnet', at(8, 41), { taps: [{ events: ['key_down', 'key_up'] }] }, 'cgeventtap');
  moment('application_launched', 'safari', at(8, 43));
  moment('application_launched', 'slack', at(8, 44));
  moment('application_launched', 'code', at(9, 5));
  add('program_updated', ['com.microsoft.VSCode', '/Applications/Visual Studio Code.app', 0], at(9, 12), at(9, 12), 1, {
    previous: { version: '1.96.0', team_id: 'UBF8T346G9' }, current: { version: '1.96.1', team_id: 'UBF8T346G9', app: 'com.microsoft.VSCode' }, changed_paths: [] }, 'fsevents');
  moment('application_launched', 'zoom', at(10, 28));
  for (const kind of ['camera', 'microphone', 'screen']) usage(kind, 'zoom', at(10, 31), at(11, 22));
  traffic(programs.zoom, at(10, 33), '198.51.100.210:8801', 'udp', 14, 210 * mb, 164 * mb);
  moment('application_terminated', 'zoom', at(11, 25));
  moment('application_launched', 'figma', at(13, 2));
  usage('microphone', 'slack', at(16, 2), at(16, 19));
  // The launcher checks for updates in the morning and downloads from its usual
  // server over lunch. Then it uploads to an address it had never contacted.
  moment('application_launched', 'launcher', at(12, 7));
  for (const [hour, minute, opens, received, sent] of [[9, 16, 1, 1.2 * mb, 30 * kb], [10, 47, 1, 1.2 * mb, 30 * kb], [12, 8, 11, 46 * mb, 220 * kb],
      [12, 25, 3, 8 * mb, 90 * kb], [12, 41, 6, 22 * mb, 110 * kb], [12, 55, 2, 2 * mb, 40 * kb], [13, 14, 4, 12 * mb, 90 * kb], [13, 33, 2, 2 * mb, 50 * kb]]) {
    traffic(programs.launcher, at(hour, minute), launcher.usual, 'tcp', opens, received, sent);
  }
  for (const [hour, minute, second, sent] of launcher.uploads) traffic(programs.launcher, at(hour, minute, second), launcher.remote, 'tcp', 2, 52 * kb, sent);

  let previous = '0'.repeat(64);
  return rows.sort((a, b) => a.last - b.last).map((row, index) => {
    const id = index + 1, chain_hash = createHash('sha256').update(previous + id + row.kind + row.path).digest('hex');
    const linked = { id, ...row, chain_prev: previous, chain_hash };
    previous = chain_hash;
    return linked;
  });
}
