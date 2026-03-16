// ============================================================
// 🔐 oauth.js — OAuth 2.0 Combined Handler (Single Serverless Function)
//
// รวม 7 OAuth endpoints ไว้ในไฟล์เดียว เพื่อไม่เกิน Vercel function limit
// Route ด้วย URL path ที่ตรวจจาก req.url:
//
//   /api/oauth/clients      → handleClients()     (GET / POST / DELETE / PATCH)
//   /api/oauth/authorize    → handleAuthorize()   (GET / POST) — รองรับ PKCE
//   /api/oauth/token        → handleToken()       (POST) — authorization_code + refresh_token
//   /api/oauth/userinfo     → handleUserinfo()    (GET) — scope-aware
//   /api/oauth/revoke       → handleRevoke()      (POST)
//   /api/oauth/sso-exchange → handleSsoExchange() (GET) — one-time SSO token → user info
//
// vercel.json rewrite:
//   { "source": "/api/oauth/:path*", "destination": "/api/oauth.js" }
//
// Features:
//   PKCE (RFC 7636)  — code_challenge_method=S256 สำหรับ public clients (SPA/mobile)
//   Scope            — 'profile' | 'email' | 'openid' (per-client + per-request)
//   Refresh Token    — 30-day TTL, single-use rotation
//   SSO Exchange     — one-time token สำหรับ redirect-back flow
//   Client Rotate    — PATCH /api/oauth/clients (rotate client_secret)
// ============================================================
import '../startup-check.js';
import { getClientIp }    from '../lib/ip-utils.js';
import {
    setSecurityHeadersWithOptions,
} from '../lib/response-utils.js';
import { handleClients } from '../lib/oauth/clients.js';
import { handleAuthorize } from '../lib/oauth/authorize.js';
import { handleToken } from '../lib/oauth/token.js';
import { handleUserinfo } from '../lib/oauth/userinfo.js';
import { handleRevoke } from '../lib/oauth/revoke.js';
import { handleSsoExchange } from '../lib/oauth/sso-exchange.js';

// ─── Main Router ───────────────────────────────────────────────
// ตรวจ URL path แล้ว dispatch ไปยัง sub-handler ที่ถูกต้อง
// req.url format บน Vercel: "/api/oauth/token?foo=bar"
// ดึง sub-path ด้วย regex เพื่อไม่ต้องพึ่ง URL parsing library
export default async function handler(req, res) {
    setSecurityHeadersWithOptions(res, {
        framePolicy: 'SAMEORIGIN',
        csp: "default-src 'none'",
        cacheControl: 'no-store, no-cache',
        pragmaNoCache: true,
    });

    const ip = getClientIp(req);

    // ดึง sub-path จาก URL: "/api/oauth/token" → "token"
    const match = req.url?.match(/\/api\/oauth\/([^/?]+)/);
    const sub   = match?.[1];

    switch (sub) {
        case 'clients':      return handleClients(req, res, ip);
        case 'authorize':    return handleAuthorize(req, res, ip);
        case 'token':        return handleToken(req, res, ip);
        case 'revoke':       return handleRevoke(req, res, ip);
        case 'userinfo':     return handleUserinfo(req, res, ip);
        case 'sso-exchange': return handleSsoExchange(req, res, ip);
        default:
            return res.status(404).json({ error: 'OAuth endpoint not found' });
    }
}
