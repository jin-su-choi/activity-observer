import { lstat } from 'node:fs/promises';
import { dirname, isAbsolute } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execute = promisify(execFile);
export function createFinderRevealer(view, { run = execute, platform = process.platform } = {}) {
  const paths = new Map();
  view.apps.forEach((app, appIndex) => {
    appIndex = view.applicationIndex ?? appIndex;
    for (const [type, rows] of [['e', app.activity], ['n', app.endpoints]]) rows.forEach((row, rowIndex) => {
      row.locations.forEach((location, i) => {
        if (typeof location.path === 'string' && isAbsolute(location.path) && !location.path.includes('\0')) {
          paths.set(`a${appIndex}-${type}${rowIndex}:${i}`, location.path);
        }
      });
    });
  });
  return async ({ locationId, throughId }) => {
    if (platform !== 'darwin') throw Error('Finder is available only on the local Mac');
    if (throughId !== view.source.through || !paths.has(locationId)) throw Error('Location is not part of this displayed review');
    const requested = paths.get(locationId);
    let revealed = requested;
    for (;;) {
      try { await lstat(revealed); break; }
      catch (e) {
        if (!['ENOENT', 'ENOTDIR'].includes(e.code) || dirname(revealed) === revealed) throw e;
        revealed = dirname(revealed);
      }
    }
    // The installed adapter can select a local file through the verified CLI.
    const command = '/usr/bin/open';
    const action = '-R';
    await run(command, [action, revealed], { timeout: 10000, maxBuffer: 16384 });
    return { opened: true, requestedPath: requested, revealedPath: revealed, parentFallback: revealed !== requested };
  };
}
