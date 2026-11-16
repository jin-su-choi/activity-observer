// A minimal MCP Apps host for the README images. Each iframe on the page gets
// the real widget and a bridge that answers its tool calls with synthetic data.
import { AppBridge, PostMessageTransport } from '@modelcontextprotocol/ext-apps/app-bridge';

const scene = document.body.dataset.scene;
const json = { 'Content-Type': 'application/json' };

async function connect(frame) {
  const { widget, tool, mode = 'inline' } = frame.dataset;
  const [html, initial] = await Promise.all([
    fetch('/widget/' + widget + '.html').then(response => response.text()),
    fetch('/result?scene=' + scene + '&tool=' + tool).then(response => response.json())
  ]);
  const context = () => ({ theme: 'dark', displayMode: mode, availableDisplayModes: ['inline', 'fullscreen'], locale: 'en-US', timeZone: 'America/Los_Angeles',
    containerDimensions: mode === 'inline' ? { width: frame.clientWidth, maxHeight: 900 } : { height: frame.clientHeight, width: frame.clientWidth },
    toolInfo: { tool: initial.tool, id: 'demo-' + widget } });
  const bridge = new AppBridge(null, { name: 'Activity Observer demo host', version: '1.0.0' },
    { serverTools: {}, updateModelContext: { text: {} } }, { hostContext: context() });
  bridge.oncalltool = async params => (await fetch('/call', { method: 'POST', headers: json,
    body: JSON.stringify({ scene, name: params.name, arguments: params.arguments }) })).json();
  bridge.onupdatemodelcontext = async params => { window.dispatchEvent(new CustomEvent('demo-context', { detail: params })); return {}; };
  bridge.onrequestdisplaymode = async () => ({ mode });
  bridge.onsizechange = ({ height }) => { if (mode === 'inline' && height) frame.style.height = Math.ceil(height) + 'px'; };
  bridge.oninitialized = async () => {
    await bridge.sendToolInput({ arguments: initial.arguments ?? {} });
    await bridge.sendToolResult(initial.result);
    frame.dataset.ready = 'true';
  };
  await bridge.connect(new PostMessageTransport(frame.contentWindow, frame.contentWindow));
  frame.srcdoc = html;
}

for (const frame of document.querySelectorAll('iframe[data-widget]')) connect(frame);
