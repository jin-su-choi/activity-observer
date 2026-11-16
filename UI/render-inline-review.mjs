import { readFile, writeFile } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { renderAppFragment } from './build-widget.mjs';
import { readPublishedReview } from './published-review.mjs';

const { values } = parseArgs({ options: {
  through: { type: 'string' },
  'expected-head-hash': { type: 'string' },
  out: { type: 'string' }
} });
const { through, 'expected-head-hash': expectedHash, out } = values;
if (!/^\d+$/.test(through || '') || !/^[0-9a-f]{64}$/.test(expectedHash || '') || !out || !isAbsolute(out) || !out.endsWith('.html')) {
  throw Error('Supply --through, --expected-head-hash, and an absolute --out HTML path');
}

const view = await readPublishedReview(fileURLToPath(new URL('./dist/', import.meta.url)));
if (!view || String(view.source.through) !== through || view.source.anchor.payload.head_hash !== expectedHash) {
  throw Error('Published presentation does not match the completed review');
}

// Encode log strings as JSON data before placing them in a script element.
const snapshot = JSON.stringify(JSON.stringify(view)).replaceAll('<', '\\u003c');
const languages = (await readFile(new URL('./i18n.mjs', import.meta.url), 'utf8')).replace(/^export /gm, '');
const runtime = `
${languages}
const root = document.getElementById('security-activity');
const i18n = createI18n(resolveLocale(navigator.languages ?? [], navigator.language));
applyStaticText(root, i18n);
const view = localizeView(JSON.parse(${snapshot}), i18n);

function contextFrom(globals) {
  return {
    theme: globals?.theme,
    displayMode: globals?.displayMode,
    containerDimensions: typeof globals?.maxHeight === 'number' ? { maxHeight: globals.maxHeight } : undefined
  };
}

window.mountActivityObserver(view, {
  i18n,
  context: contextFrom(window.openai),
  drawIcons() { globalThis.lucide?.createIcons({ attrs: { width: 16, height: 16 } }); },
  canReveal: false,
  canMessage: typeof window.openai?.sendFollowUpMessage === 'function',
  async updateSelection(selection) {
    try { await window.openai?.setWidgetState?.({ modelContent: selection }); } catch {}
  },
  investigate(prompt) {
    return window.openai.sendFollowUpMessage({ title: i18n.t('summary.title'), prompt });
  }
});

window.addEventListener('openai:set_globals', event => {
  root.__observer.applyHostContext(contextFrom(event.detail?.globals));
});

import('https://persistent.oaistatic.com/plugins/visualize/charts/1.2.3/element.js')
  .then(({ mountChart }) => root.__observer.connectChartFactory(mountChart))
  .catch(() => root.__observer.chartFailure());
`;

const html = renderAppFragment(runtime);
const bytes = Buffer.byteLength(html);
if (bytes > 1_000_000) throw Error('Inline review exceeds the visualization size limit');

try {
  await writeFile(out, html, { flag: 'wx', mode: 0o600 });
} catch (error) {
  if (error.code !== 'EEXIST' || await readFile(out, 'utf8') !== html) throw error;
}

console.log(JSON.stringify({ path: out, day: view.source.day, through: view.source.through,
  rows: view.source.rowsRead, reviewed: view.source.reviewedRows, bytes }));
