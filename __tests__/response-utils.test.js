import { requireJson, setSecurityHeadersWithOptions } from '../lib/response-utils.js';

function makeRes() {
  const headers = {};
  const res = {
    statusCode: 200,
    headersSent: false,
    setHeader: (k, v) => { headers[k] = v; },
    status: (code) => { res.statusCode = code; return res; },
    json: (obj) => { res._json = obj; return res; },
  };
  res._headers = headers;
  return res;
}

describe('response-utils', () => {
  test('setSecurityHeadersWithOptions applies CSP and frame policy', () => {
    const res = makeRes();
    setSecurityHeadersWithOptions(res, {
      framePolicy: 'SAMEORIGIN',
      csp: "default-src 'none'",
      cacheControl: 'no-store',
      pragmaNoCache: true,
    });

    expect(res._headers['X-Frame-Options']).toBe('SAMEORIGIN');
    expect(res._headers['Content-Security-Policy']).toBe("default-src 'none'");
    expect(res._headers['Cache-Control']).toBe('no-store');
    expect(res._headers['Pragma']).toBe('no-cache');
  });

  test('requireJson rejects non-json content-type', () => {
    const req = { headers: { 'content-type': 'text/plain' }, body: {} };
    const res = makeRes();
    const ok = requireJson(req, res);
    expect(ok).toBe(false);
    expect(res.statusCode).toBe(415);
    expect(res._json).toEqual({ error: 'Content-Type must be application/json' });
  });

  test('requireJson rejects array bodies', () => {
    const req = { headers: { 'content-type': 'application/json' }, body: [] };
    const res = makeRes();
    const ok = requireJson(req, res);
    expect(ok).toBe(false);
    expect(res.statusCode).toBe(400);
    expect(res._json).toEqual({ error: 'Invalid request body' });
  });

  test('requireJson accepts plain object bodies', () => {
    const req = { headers: { 'content-type': 'application/json; charset=utf-8' }, body: { a: 1 } };
    const res = makeRes();
    const ok = requireJson(req, res);
    expect(ok).toBe(true);
    expect(res.statusCode).toBe(200);
  });
});

