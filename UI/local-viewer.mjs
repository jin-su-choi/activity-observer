import { createServer } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { readConnection } from './shared-server.mjs';

const dir = dirname(fileURLToPath(import.meta.url));
export async function startLocalViewer({ dashboard = false } = {}) {
  const connection = readConnection();
  const client = new Client({ name: 'activity-observer-local-viewer', version: '0.1.0' },
    { capabilities: { extensions: { 'io.modelcontextprotocol/ui': { mimeTypes: ['text/html;profile=mcp-app'] } } } });
  await client.connect(new StreamableHTTPClientTransport(new URL(connection.url), {
    requestInit: { headers: { Authorization: 'Bearer ' + connection.token } }
  }));
  const tools = await client.listTools();
  const tool = tools.tools.find(t => t.name === (dashboard ? 'open_activity_dashboard' : 'show_activity_review'));
  const result = await client.callTool({ name: tool.name, arguments: {} });
  const resource = await client.readResource({ uri: tool._meta.ui.resourceUri });
  const hostJs = await readFile(resolve(dir, 'dist/local-host.js'));
  const token = randomBytes(32).toString('hex');
  const html = resource.contents[0].text.replace('<head>', `<head><meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; base-uri 'none'; form-action 'none'">`);
  const hostHtml = `<!doctype html><html><head><meta charset="utf-8"><title>Activity Observer</title><meta name="viewport" content="width=device-width,initial-scale=1"><style>html{color-scheme:light dark}body{margin:24px;font-family:-apple-system,sans-serif}#review{display:block;width:100%;height:760px;border:0}#fullscreen{display:block;margin:0 0 12px auto;border:0;background:none;color:inherit;font:inherit}body[data-mode=fullscreen]{margin:0}body[data-mode=fullscreen] #fullscreen{position:fixed;z-index:2;right:12px;top:12px}</style></head><body><button id="fullscreen" type="button"></button><iframe id="review" title="Activity Observer" sandbox="allow-scripts" allow="fullscreen"></iframe><script type="module" src="/host.js"></script></body></html>`;
  let origin, closing = false, closeTimer;
  const close = async () => {
    if (closing) return;closing = true;clearTimeout(closeTimer);
    http.closeAllConnections();http.close();await client.close();
  };
  const http = createServer(async (req, res) => {
    try {
      if (req.headers.host !== origin.substring(7) || req.headers.origin && req.headers.origin !== origin) { res.writeHead(403).end();return; }
      res.setHeader('Cache-Control', 'no-store');res.setHeader('Referrer-Policy', 'no-referrer');res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; frame-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
      if (req.method === 'GET' && req.url === '/') { clearTimeout(closeTimer);res.setHeader('Content-Type', 'text/html; charset=utf-8');res.end(hostHtml);return; }
      if (req.method === 'GET' && req.url === '/host.js') { res.setHeader('Content-Type', 'text/javascript; charset=utf-8');res.end(hostJs);return; }
      const provided = Buffer.from(req.headers.authorization || '');
      const expected = Buffer.from('Bearer ' + token);
      if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) { res.writeHead(403).end();return; }
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      if (req.method === 'GET' && req.url === '/view') { res.end(JSON.stringify({ html, result, tool }));return; }
      if (req.method === 'POST' && req.url === '/close') { res.end('{}');clearTimeout(closeTimer);closeTimer=setTimeout(close,2000);return; }
      if (req.method !== 'POST' || req.url !== '/call') { res.writeHead(404).end();return; }
      if (!req.headers['content-type']?.startsWith('application/json')) { res.writeHead(415).end();return; }
      let text = '';
      for await (const chunk of req) { text += chunk; if (text.length > 4096) { res.writeHead(413).end();return; } }
      const params = JSON.parse(text);
      if (!['reveal_in_finder', 'read_activity_review_view', 'read_activity_review_cards', 'read_activity_review_icons', 'read_activity_period_view'].includes(params.name) ||
          Object.keys(params).some(key => !['name', 'arguments'].includes(key))) { res.writeHead(403).end();return; }
      res.end(JSON.stringify(await client.callTool(params)));
    } catch { if (!res.headersSent) res.writeHead(400);res.end('{"error":"Request failed"}'); }
  });
  await new Promise(resolve => http.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${http.address().port}`;
  return { url: origin + '/#' + token, close };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const viewer = await startLocalViewer({ dashboard: process.argv.includes('--dashboard') });
  console.log(viewer.url);
  process.once('SIGINT', () => viewer.close());process.once('SIGTERM', () => viewer.close());
}
