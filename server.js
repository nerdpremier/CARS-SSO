import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number.parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '127.0.0.1';

const STATIC_REWRITES = new Map([
  // SPA entrypoints
  ['/', 'index.html'],
  ['/login', 'index.html'],
  ['/register', 'index.html'],
  ['/mfa', 'index.html'],
  ['/welcome', 'index.html'],
  ['/developer', 'index.html'],

  // Keep legacy pages available (optional)
  ['/forgot-password', 'forgot-password.html'],
  ['/reset-password', 'reset-password.html'],
  ['/oauth/authorize', 'authorize.html'],
]);

const API_REWRITES = new Map([
  ['/api/auth', 'api/auth.js'],
  ['/api/assess', 'api/assess.js'],
  ['/api/session', 'api/session.js'],
  ['/api/session-risk', 'api/session-risk.js'],
  ['/api/logout', 'api/logout.js'],
  ['/api/logout-redirect', 'api/logout.js'],
  ['/api/csrf', 'api/csrf.js'],
  ['/api/cleanup', 'api/logout.js'],
  ['/api/mfa', 'api/mfa.js'],
  ['/api/password', 'api/password.js'],
]);

function contentTypeFor(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  switch (ext) {
    case '.html': return 'text/html; charset=utf-8';
    case '.css': return 'text/css; charset=utf-8';
    case '.js': return 'text/javascript; charset=utf-8';
    case '.json': return 'application/json; charset=utf-8';
    case '.svg': return 'image/svg+xml';
    case '.png': return 'image/png';
    case '.jpg':
    case '.jpeg': return 'image/jpeg';
    case '.ico': return 'image/x-icon';
    default: return 'application/octet-stream';
  }
}

function enhanceRes(res) {
  res.status = (code) => {
    res.statusCode = code;
    return res;
  };
  res.json = (data) => {
    if (!res.headersSent) res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify(data));
    return res;
  };
  res.send = (data = '') => {
    if (data == null) data = '';
    if (Buffer.isBuffer(data)) {
      res.end(data);
      return res;
    }
    if (typeof data === 'object') {
      if (!res.headersSent) res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.end(JSON.stringify(data));
      return res;
    }
    res.end(String(data));
    return res;
  };
  res.redirect = (location) => {
    res.statusCode = 302;
    res.setHeader('Location', location);
    res.end();
    return res;
  };
  return res;
}

async function readJsonBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  if (chunks.length === 0) return undefined;
  const raw = Buffer.concat(chunks).toString('utf8');
  if (!raw) return undefined;
  return JSON.parse(raw);
}

async function serveStatic(res, relativeFilePath) {
  const safeRel = relativeFilePath.replace(/^[\\/]+/, '');
  const absolutePath = path.resolve(__dirname, safeRel);
  const rootPath = path.resolve(__dirname);

  // prevent path traversal
  if (!absolutePath.startsWith(rootPath + path.sep) && absolutePath !== rootPath) {
    return res.status(400).send('Bad request');
  }

  const buf = await fs.readFile(absolutePath);
  res.setHeader('Content-Type', contentTypeFor(absolutePath));
  res.status(200).send(buf);
}

const handlerCache = new Map();
async function loadApiHandler(entryPath) {
  const abs = path.resolve(__dirname, entryPath);
  const url = pathToFileURL(abs).toString();
  if (!handlerCache.has(url)) {
    const mod = await import(url);
    if (typeof mod.default !== 'function') throw new Error(`Missing default export in ${entryPath}`);
    handlerCache.set(url, mod.default);
  }
  return handlerCache.get(url);
}

const server = http.createServer(async (req, res) => {
  enhanceRes(res);

  try {
    const u = new URL(req.url || '/', `http://${req.headers.host || `${HOST}:${PORT}`}`);
    const pathname = u.pathname;

    // mimic Vercel: req.query
    req.query = Object.fromEntries(u.searchParams.entries());

    // OAuth combined router: /api/oauth/:path*
    if (pathname.startsWith('/api/oauth/')) {
      if (req.method === 'POST' && req.headers['content-type']?.includes('application/json')) {
        req.body = await readJsonBody(req);
      }
      const handler = await loadApiHandler('api/oauth.js');
      return await handler(req, res);
    }

    // Exact API rewrites
    const apiEntry = API_REWRITES.get(pathname);
    if (apiEntry) {
      if (req.method === 'POST' && req.headers['content-type']?.includes('application/json')) {
        req.body = await readJsonBody(req);
      }
      const handler = await loadApiHandler(apiEntry);
      return await handler(req, res);
    }

    // Static page rewrites
    const page = STATIC_REWRITES.get(pathname);
    if (page) {
      return await serveStatic(res, page);
    }

    // Serve direct static file requests (e.g. /style.css)
    if (pathname.startsWith('/')) {
      const file = pathname.slice(1);
      if (file) {
        return await serveStatic(res, file);
      }
    }

    return res.status(404).send('Not found');
  } catch (err) {
    console.error('[dev-server] error:', err);
    if (!res.headersSent) res.status(500);
    return res.send('Internal server error');
  }
});

server.listen(PORT, HOST, () => {
  console.log(`[dev-server] listening on http://${HOST}:${PORT}`);
});

