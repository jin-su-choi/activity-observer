import { createServer } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { lstatSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { Readable } from 'node:stream';
import { createMcpHandler } from '@modelcontextprotocol/server';
import { createObserverServer, createObserverState, loadBundle } from './mcp-server.mjs';
import { checkMcpIsolation, installedMcpBuild } from './build-widget.mjs';
import { installedReviewDir, installedUiDir } from './published-review.mjs';

import { observerPort, observerUrl } from './paths.mjs';
export { observerPort, observerUrl } from './paths.mjs';

export function releaseIdleCaches(state){
  state.displayed.clear();
  for(const period of state.periods.values()){period.programs.clear();delete period.catalog;}
  state.detailTransfers.clear();state.detailed=null;
}

export function readConnection(path = resolve(installedUiDir, 'connection.json')) {
  const info = lstatSync(path);
  if (!info.isFile() || info.uid !== process.getuid() || info.mode & 0o077 || info.size > 2048) {
    throw Error('Invalid local MCP connection file');
  }
  const config = JSON.parse(readFileSync(path, 'utf8'));
  if (config.url !== observerUrl || !/^[a-f0-9]{64}$/.test(config.token)) throw Error('Invalid local MCP connection');
  return config;
}

export async function startSharedServer({ bundle, connection = readConnection(), port = observerPort } = {}) {
  checkMcpIsolation();
  if (!bundle) {
    const dir = dirname(fileURLToPath(import.meta.url));
    bundle = await loadBundle(installedMcpBuild ? dir : resolve(dir, 'dist'), installedReviewDir);
  }
  const state = createObserverState();
  const handler = createMcpHandler(() => createObserverServer(bundle, undefined, { state }),
    { legacy: 'stateless', maxRequestBodySize: 262144, maxSubscriptions: 16 });
  const expected = Buffer.from('Bearer ' + connection.token);
  let boundPort = port;
  let active = 0, lastUse = Date.now();
  const server = createServer(async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    const host = `127.0.0.1:${boundPort}`;
    const auth = Buffer.from(req.headers.authorization ?? '');
    if (req.headers.host !== host || req.headers.origin || req.socket.remoteAddress !== '127.0.0.1') {
      res.writeHead(403).end(); return;
    }
    if (auth.length !== expected.length || !timingSafeEqual(auth, expected)) {
      res.writeHead(401).end(); return;
    }
    if (req.url === '/health' && req.method === 'GET') {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ healthy: true, pid: process.pid, activeRequests: active }));
      return;
    }
    if (req.url !== '/mcp') { res.writeHead(404).end(); return; }
    if (!['POST', 'GET', 'DELETE'].includes(req.method)) { res.writeHead(405).end(); return; }
    if (active >= 16) { res.setHeader('Retry-After', '1'); res.writeHead(503).end(); return; }
    active++;
    lastUse = Date.now();
    const controller = new AbortController();
    const abort = () => { if (!res.writableFinished) controller.abort(); };
    res.once('close', abort);
    try {
      const chunks = [];
      let bytes = 0;
      for await (const chunk of req) {
        bytes += chunk.length;
        if (bytes > 262144) { res.writeHead(413).end(); return; }
        chunks.push(chunk);
      }
      const body = req.method === 'POST' ? Buffer.concat(chunks) : undefined;
      const request = new Request(`http://${host}/mcp`, {
        method: req.method, headers: req.headers, body, signal: controller.signal
      });
      const response = await handler.fetch(request);
      res.writeHead(response.status, Object.fromEntries(response.headers));
      if (response.body) {
        const stream = Readable.fromWeb(response.body);
        res.once('close', () => stream.destroy());
        stream.on('error', () => res.destroy());
        stream.pipe(res);
        await new Promise(resolve => { res.once('finish', resolve); res.once('close', resolve); });
      } else res.end();
    } catch {
      if (!res.headersSent) res.writeHead(500).end();
      else res.destroy();
    } finally {
      res.removeListener('close', abort);
      active--;
      lastUse = Date.now();
    }
  });
  server.requestTimeout = 160000;
  server.headersTimeout = 10000;
  server.keepAliveTimeout = 5000;
  server.maxConnections = 64;
  // Drop heavy detail caches, but keep the bounded query references used by
  // open views. Their catalog can be reconstructed against the same anchor.
  const cleanup = setInterval(() => {
    if (active || state.detailRequests.size || Date.now() - lastUse < 60000) return;
    releaseIdleCaches(state);
  }, 30000);
  cleanup.unref();
  await new Promise((accept, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', accept);
  });
  boundPort = server.address().port;
  return {
    server, state,
    async close() {
      clearInterval(cleanup);
      await handler.close();
      server.closeAllConnections();
      await new Promise(resolve => server.close(resolve));
    }
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const shared = await startSharedServer();
  const stop = () => shared.close().finally(() => process.exit(0));
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
}
