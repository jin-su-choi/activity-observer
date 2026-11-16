// A local MCP Apps host for clients that cannot embed an MCP App themselves.
// The child UI uses the same standard AppBridge as an embedding agent harness.
import { AppBridge, PostMessageTransport } from '@modelcontextprotocol/ext-apps/app-bridge';
import { createI18n, resolveLocale } from './i18n.mjs';

const text = createI18n(resolveLocale(navigator.languages ?? [], navigator.language));
document.documentElement.lang = text.locale;
document.getElementById('fullscreen').textContent = text.t('host.fullscreen');
const token = location.hash.substring(1);
const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };
const response = await fetch('/view', { headers });
if (!response.ok) throw Error('Local viewer authorization failed');
const { html, result, tool } = await response.json();
const frame = document.getElementById('review');
let displayMode = 'inline';
const context = () => ({ theme: matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light',
  displayMode, locale: navigator.language, timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
  containerDimensions: { height: displayMode === 'fullscreen' ? innerHeight : 760, width: frame.clientWidth },
  toolInfo: { tool, id: 'local-review' } });
const bridge = new AppBridge(null, { name: 'Activity Observer Local Host', version: '0.1.0' },
  { serverTools: {} }, { hostContext: context() });
bridge.oncalltool = async params => {
  const response = await fetch('/call', { method: 'POST', headers,
    body: JSON.stringify({ name: params.name, arguments: params.arguments }) });
  if (!response.ok) throw Error('Local tool request failed');
  return response.json();
};
bridge.oninitialized = async () => { await bridge.sendToolInput({ arguments: {} }); await bridge.sendToolResult(result); };
bridge.onrequestdisplaymode = async ({ mode }) => { setMode(mode); return { mode: displayMode }; };
await bridge.connect(new PostMessageTransport(frame.contentWindow, frame.contentWindow));
frame.srcdoc = html;
const updateContext = () => { const next = context(); frame.style.height = next.containerDimensions.height + 'px'; bridge.setHostContext(next); };
function setMode(mode) {
  displayMode = mode === 'fullscreen' ? 'fullscreen' : 'inline';
  document.body.dataset.mode = displayMode;
  document.getElementById('fullscreen').textContent = text.t(displayMode === 'fullscreen' ? 'host.exitFullscreen' : 'host.fullscreen');
  updateContext();
}
window.addEventListener('resize', updateContext);
matchMedia('(prefers-color-scheme: dark)').addEventListener('change', updateContext);
document.getElementById('fullscreen').addEventListener('click', () => setMode(displayMode === 'fullscreen' ? 'inline' : 'fullscreen'));
window.addEventListener('pagehide', () => {
  fetch('/close', { method: 'POST', headers, keepalive: true }).catch(() => {});
});
