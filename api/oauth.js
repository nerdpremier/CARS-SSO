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
import { pool }           from '../lib/db.js';
import { checkRateLimit } from '../lib/rate-limit.js';
import { getClientIp }    from '../lib/ip-utils.js';
import { validateCsrfToken } from '../lib/csrf-utils.js';
import jwt    from 'jsonwebtoken';
import { parse } from 'cookie';
import { auditLog } from '../lib/response-utils.js';
import crypto from 'crypto';

// ─── Constants ────────────────────────────────────────────────
const USER_REGEX               = /^[a-zA-Z0-9]+$/;
const MAX_CLIENTS_PER_USER     = 10;
const CODE_TTL_MINUTES         = 10;
const ACCESS_TOKEN_TTL_SECONDS = 3600;          // 1 ชั่วโมง
const REFRESH_TOKEN_TTL_DAYS   = 30;            // 30 วัน

// Scopes ที่ระบบรองรับ — ต้องตรงกับ schema.sql comment
const VALID_SCOPES = new Set(['profile', 'email', 'openid']);
const DEFAULT_SCOPE = ['profile'];

// ─── Shared Utilities ─────────────────────────────────────────

// parseScope: แปลง scope string → validated array
// ตัด scope ที่ไม่อยู่ใน VALID_SCOPES ออก, default เป็น ['profile']
function parseScope(scopeStr, allowedScopes = [...VALID_SCOPES]) {
    if (!scopeStr || typeof scopeStr !== 'string') return DEFAULT_SCOPE;
    const requested = scopeStr.trim().split(/\s+/).filter(s => VALID_SCOPES.has(s));
    const allowed   = requested.filter(s => allowedScopes.includes(s));
    return allowed.length > 0 ? allowed : DEFAULT_SCOPE;
}




// hashToken: SHA-256 สำหรับ high-entropy random token
// ไม่ต้องการ salt เพราะ 256-bit random input ทำ preimage attack ไม่คุ้มค่า
function hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
}

// hashClientSecret: HMAC-SHA256 ด้วย pepper
// เหมาะกว่า bcrypt สำหรับ high-entropy random string (256-bit)
function hashClientSecret(secret) {
    return crypto
        .createHmac('sha256', process.env.OAUTH_SECRET_PEPPER)
        .update(secret)
        .digest('hex');
}

// safeHexEqual: timing-safe string comparison ป้องกัน timing attack
// รองรับ hex string เท่านั้น — ต้องตรวจ format ก่อน Buffer.from()
//   Buffer.from('ZZZ', 'hex') = empty buffer (length 0)
//   timingSafeEqual(Buffer(0), Buffer(N)) throw RangeError → crash
//   HEX_REGEX ป้องกัน non-hex input เข้า Buffer.from()
const HEX_REGEX = /^[0-9a-f]+$/i;
function safeHexEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;
    if (!HEX_REGEX.test(a) || !HEX_REGEX.test(b)) return false;
    try {
        const aBuf = Buffer.from(a, 'hex');
        const bBuf = Buffer.from(b, 'hex');
        if (aBuf.length !== bBuf.length) return false;
        return crypto.timingSafeEqual(aBuf, bBuf);
    } catch {
        return false;
    }
}

// verifySessionCookie: ตรวจ JWT จาก session cookie + DB revocation check
// ใช้เฉพาะ /authorize endpoint (consent flow)
// คืน decoded payload ถ้า valid active session, null ถ้าไม่ valid
async function verifySessionCookie(req) {
    const cookies = parse(req.headers.cookie || '');
    const token   = cookies.session_token;
    if (!token) return null;

    let decoded;
    try {
        decoded = jwt.verify(token, process.env.JWT_SECRET, {
            issuer: 'auth-service', audience: 'api'
        });
    } catch { return null; }

    if (!decoded.jti) return null;
    if (!decoded.username || typeof decoded.username !== 'string' ||
        decoded.username.length > 32 || !USER_REGEX.test(decoded.username)) return null;

    // ── DB revocation check (logout blacklist + password reset) ──
    try {
        const result = await pool.query(
            `SELECT u.sessions_revoked_at, rt.jti AS revoked_jti
             FROM users u
             LEFT JOIN revoked_tokens rt ON rt.jti = $2 AND rt.expires_at > NOW()
             WHERE u.username = $1`,
            [decoded.username, decoded.jti]
        );
        if (result.rows.length === 0) return null;
        const { sessions_revoked_at, revoked_jti } = result.rows[0];
        if (revoked_jti) return null;
        if (sessions_revoked_at && typeof decoded.iat === 'number') {
            if (new Date(decoded.iat * 1000) < new Date(sessions_revoked_at)) return null;
        }
    } catch (dbErr) {
        console.error('[WARN] oauth.js verifySessionCookie DB error:', dbErr.message);
        return null;
    }

    return decoded;
}

function setSecurityHeaders(res, framePolicy = 'DENY') {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', framePolicy);
    res.setHeader('Content-Security-Policy', "default-src 'none'");
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
    res.setHeader('Cache-Control', 'no-store, no-cache');
    res.setHeader('Pragma', 'no-cache');
}

function requireJson(req, res) {
    if (!req.headers['content-type']?.includes('application/json')) {
        res.status(415).json({ error: 'Content-Type must be application/json' });
        return false;
    }
    if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
        res.status(400).json({ error: 'Invalid request body' });
        return false;
    }
    return true;
}

// ─── Sub-handlers ─────────────────────────────────────────────

// ── /api/oauth/clients ────────────────────────────────────────
// Developer Portal API: ลงทะเบียน / ดู / ลบ client app
// Auth: session_token cookie (same-origin จาก developer-portal.html)
// ใช้ cookie แทน Bearer เพราะ httpOnly cookie อ่านจาก JS ไม่ได้
async function handleClients(req, res, ip) {
    try {
        if (await checkRateLimit(`ip:${ip}:oauth-clients`, 20, 60_000)) {
            auditLog('OAUTH_CLIENTS_RATE_LIMIT', { ip });
            return res.status(429).json({ error: 'Too many requests. Please try again later.' });
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit error (oauth-clients), failing open:', rlErr.message);
    }

    // verifySessionCookie: ตรวจ httpOnly cookie + DB revocation
    // เหมาะกับ same-origin portal มากกว่า Bearer
    const decoded = await verifySessionCookie(req);
    if (!decoded) {
        return res.status(401).json({ error: 'Unauthorized. Please sign in first.' });
    }
    const username = decoded.username;

    try {
        // ── POST: สร้าง client app ─────────────────────────
        if (req.method === 'POST') {
            if (!requireJson(req, res)) return;
            const { name, redirect_uris, allowed_scopes: reqScopes } = req.body;

            if (typeof name !== 'string' || !name.trim() || name.length > 128)
                return res.status(400).json({ error: 'App name must be a non-empty string (max 128 characters)' });

            if (!Array.isArray(redirect_uris) || redirect_uris.length === 0 || redirect_uris.length > 10)
                return res.status(400).json({ error: 'redirect_uris must be an array with 1-10 entries' });

            for (const uri of redirect_uris) {
                if (typeof uri !== 'string' || uri.length > 512)
                    return res.status(400).json({ error: 'Each redirect_uri must be a string (max 512 characters)' });
                let parsed;
                try { parsed = new URL(uri); } catch {
                    return res.status(400).json({ error: 'One or more redirect_uris has an invalid URL format' });
                }
                const isLocalhost = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';
                if (parsed.protocol !== 'https:' && !isLocalhost)
                    return res.status(400).json({ error: 'All redirect_uris must use HTTPS (or localhost for development)' });
            }

            // Validate allowed_scopes (optional — default ['profile'])
            let allowedScopes = DEFAULT_SCOPE;
            if (reqScopes !== undefined) {
                if (!Array.isArray(reqScopes) || reqScopes.some(s => !VALID_SCOPES.has(s)))
                    return res.status(400).json({ error: `allowed_scopes contains invalid values — supported: ${[...VALID_SCOPES].join(', ')}` });
                allowedScopes = reqScopes.length > 0 ? reqScopes : DEFAULT_SCOPE;
            }

            const countRow = await pool.query(
                'SELECT COUNT(*) FROM oauth_clients WHERE owner_username = $1', [username]
            );
            if (parseInt(countRow.rows[0].count, 10) >= MAX_CLIENTS_PER_USER)
                return res.status(400).json({ error: `Maximum ${MAX_CLIENTS_PER_USER} apps per account` });

            const clientId     = 'c_' + crypto.randomBytes(16).toString('hex');
            const clientSecret = crypto.randomBytes(32).toString('hex');
            const secretHash   = hashClientSecret(clientSecret);

            await pool.query(
                `INSERT INTO oauth_clients (client_id, client_secret_hash, name, redirect_uris, allowed_scopes, owner_username)
                 VALUES ($1, $2, $3, $4, $5, $6)`,
                [clientId, secretHash, name.trim(), redirect_uris, allowedScopes, username]
            );

            auditLog('OAUTH_CLIENT_CREATED', { username, clientId, ip });
            return res.status(201).json({
                client_id:      clientId,
                client_secret:  clientSecret,
                name:           name.trim(),
                redirect_uris,
                allowed_scopes: allowedScopes,
                notice:         '⚠️ Save your client_secret now — it cannot be retrieved again'
            });
        }

        // ── GET: ดูรายการ ──────────────────────────────────
        if (req.method === 'GET') {
            const result = await pool.query(
                `SELECT client_id, name, redirect_uris, allowed_scopes, created_at
                 FROM oauth_clients WHERE owner_username = $1 ORDER BY created_at DESC`,
                [username]
            );
            return res.status(200).json({ clients: result.rows });
        }

        // ── PATCH: Rotate client_secret ────────────────────
        // ใช้เมื่อ secret รั่ว — ออก secret ใหม่ทันที, revoke token เก่าทั้งหมด
        if (req.method === 'PATCH') {
            if (!requireJson(req, res)) return;
            const { client_id } = req.body;
            if (!client_id || typeof client_id !== 'string' || client_id.length > 128)
                return res.status(400).json({ error: 'client_id is required' });

            const newSecret     = crypto.randomBytes(32).toString('hex');
            const newSecretHash = hashClientSecret(newSecret);

            const rotateClient = await pool.connect();
            try {
                await rotateClient.query('BEGIN');

                const result = await rotateClient.query(
                    `UPDATE oauth_clients SET client_secret_hash = $1
                     WHERE client_id = $2 AND owner_username = $3
                     RETURNING client_id`,
                    [newSecretHash, client_id, username]
                );
                if (result.rowCount === 0) {
                    await rotateClient.query('ROLLBACK');
                    return res.status(404).json({ error: 'App not found or does not belong to you' });
                }

                // Revoke token ทั้งหมดของ client นี้ — บังคับ re-auth
                await rotateClient.query(
                    `UPDATE oauth_tokens SET revoked_at = NOW()
                     WHERE client_id = $1 AND revoked_at IS NULL`,
                    [client_id]
                );

                await rotateClient.query('COMMIT');
                auditLog('OAUTH_CLIENT_SECRET_ROTATED', { username, clientId: client_id, ip });
                return res.status(200).json({
                    client_id,
                    client_secret: newSecret,
                    notice:        '⚠️ New secret issued — all previous tokens have been revoked'
                });
            } catch (err) {
                try { await rotateClient.query('ROLLBACK'); } catch { /* ignore */ }
                throw err;
            } finally {
                rotateClient.release();
            }
        }

        // ── DELETE: ลบ client app ──────────────────────────
        if (req.method === 'DELETE') {
            if (!requireJson(req, res)) return;
            const { client_id } = req.body;
            if (!client_id || typeof client_id !== 'string' || client_id.length > 128)
                return res.status(400).json({ error: 'client_id is required' });

            const deleteClient = await pool.connect();
            try {
                await deleteClient.query('BEGIN');

                // ตรวจเจ้าของก่อนลบ (ป้องกัน delete client ของคนอื่น)
                const ownerCheck = await deleteClient.query(
                    'SELECT client_id FROM oauth_clients WHERE client_id = $1 AND owner_username = $2',
                    [client_id, username]
                );
                if (ownerCheck.rowCount === 0) {
                    await deleteClient.query('ROLLBACK');
                    return res.status(404).json({ error: 'App not found or does not belong to you' });
                }

                // Revoke tokens ทั้งหมดของ client นี้ก่อนลบ
                // ป้องกัน: ลบ client แล้ว tokens ยังใช้ได้ (ถ้าไม่มี CASCADE DELETE ใน schema)
                await deleteClient.query(
                    `UPDATE oauth_tokens SET revoked_at = NOW()
                     WHERE client_id = $1 AND revoked_at IS NULL`,
                    [client_id]
                );

                await deleteClient.query(
                    'DELETE FROM oauth_clients WHERE client_id = $1 AND owner_username = $2',
                    [client_id, username]
                );

                await deleteClient.query('COMMIT');
            } catch (err) {
                try { await deleteClient.query('ROLLBACK'); } catch { /* ignore */ }
                throw err;
            } finally {
                deleteClient.release();
            }

            auditLog('OAUTH_CLIENT_DELETED', { username, clientId: client_id, ip });
            return res.status(200).json({ success: true });
        }

        return res.status(405).json({ error: 'Method not allowed' });
    } catch (err) {
        console.error('[ERROR] oauth.js handleClients:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
}

// ── /api/oauth/authorize ──────────────────────────────────────
// Consent flow: GET แสดงข้อมูล app, POST รับผลการตัดสินใจ
// Auth: session_token cookie
async function handleAuthorize(req, res, ip) {
    try {
        if (await checkRateLimit(`ip:${ip}:oauth-authorize`, 30, 60_000)) {
            auditLog('OAUTH_AUTHORIZE_RATE_LIMIT', { ip });
            return res.status(429).json({ error: 'Too many requests. Please try again later.' });
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit error (oauth-authorize), failing open:', rlErr.message);
    }

    // ── GET: ตรวจ params + session → ส่งข้อมูลสำหรับ consent UI ──
    if (req.method === 'GET') {
        const { client_id, redirect_uri, response_type, state, scope,
                code_challenge, code_challenge_method } = req.query;

        if (response_type !== 'code')
            return res.status(400).json({ error: 'unsupported_response_type' });
        if (!client_id || typeof client_id !== 'string' || client_id.length > 128)
            return res.status(400).json({ error: 'invalid_request: missing or invalid client_id' });
        if (!redirect_uri || typeof redirect_uri !== 'string' || redirect_uri.length > 512)
            return res.status(400).json({ error: 'invalid_request: missing or invalid redirect_uri' });
        if (!state || typeof state !== 'string' || state.length > 256)
            return res.status(400).json({ error: 'invalid_request: missing or invalid state' });

        // PKCE validation (optional, but if present must be S256)
        if (code_challenge !== undefined) {
            if (code_challenge_method !== 'S256')
                return res.status(400).json({ error: 'invalid_request: code_challenge_method must be S256' });
            if (typeof code_challenge !== 'string' || code_challenge.length < 43 || code_challenge.length > 128)
                return res.status(400).json({ error: 'invalid_request: invalid code_challenge' });
        }

        let clientResult;
        try {
            clientResult = await pool.query(
                'SELECT name, redirect_uris, allowed_scopes FROM oauth_clients WHERE client_id = $1',
                [client_id]
            );
        } catch (dbErr) {
            console.error('[ERROR] oauth.js handleAuthorize GET DB:', dbErr.message);
            return res.status(500).json({ error: 'Internal server error' });
        }

        if (clientResult.rows.length === 0)
            return res.status(400).json({ error: 'invalid_client: unknown client_id' });

        const { name: appName, redirect_uris, allowed_scopes } = clientResult.rows[0];

        if (!redirect_uris.includes(redirect_uri))
            return res.status(400).json({ error: 'invalid_redirect_uri: URI not registered' });

        // คำนวณ effective scope = intersection of requested + allowed
        const effectiveScope = parseScope(scope, allowed_scopes);

        const decoded = await verifySessionCookie(req);
        if (!decoded) {
            return res.status(401).json({ error: 'unauthenticated', app_name: appName });
        }

        auditLog('OAUTH_CONSENT_VIEW', { username: decoded.username, clientId: client_id, ip });
        return res.status(200).json({
            app_name: appName, client_id, redirect_uri, state,
            username: decoded.username,
            scope:    effectiveScope,
        });
    }

    // ── POST: รับผลการตัดสินใจ Allow / Deny ───────────────
    if (req.method === 'POST') {
        if (!requireJson(req, res)) return;

        // CSRF: ป้องกัน cross-site form submission ที่หลอกให้ user allow โดยไม่รู้ตัว
        // authorize.js ส่ง X-CSRF-Token header พร้อมทุก POST
        if (!validateCsrfToken(req)) {
            return res.status(403).json({ error: 'invalid_request: CSRF token invalid or missing' });
        }

        const { client_id, redirect_uri, state, approved,
                scope, code_challenge, code_challenge_method } = req.body;

        if (!client_id || typeof client_id !== 'string' || client_id.length > 128)
            return res.status(400).json({ error: 'invalid_request: missing or invalid client_id' });
        if (!redirect_uri || typeof redirect_uri !== 'string' || redirect_uri.length > 512)
            return res.status(400).json({ error: 'invalid_request: missing or invalid redirect_uri' });
        if (!state || typeof state !== 'string' || state.length > 256)
            return res.status(400).json({ error: 'invalid_request: missing or invalid state' });

        // PKCE validation
        if (code_challenge !== undefined) {
            if (code_challenge_method !== 'S256')
                return res.status(400).json({ error: 'invalid_request: code_challenge_method must be S256' });
            if (typeof code_challenge !== 'string' || code_challenge.length < 43 || code_challenge.length > 128)
                return res.status(400).json({ error: 'invalid_request: invalid code_challenge' });
        }

        const decoded = await verifySessionCookie(req);
        if (!decoded) return res.status(401).json({ error: 'session_expired: please sign in again' });

        let clientRow;
        try {
            const uriResult = await pool.query(
                `SELECT allowed_scopes FROM oauth_clients
                 WHERE client_id = $1 AND $2 = ANY(redirect_uris)`,
                [client_id, redirect_uri]
            );
            if (uriResult.rows.length === 0)
                return res.status(400).json({ error: 'invalid_client or invalid_redirect_uri' });
            clientRow = uriResult.rows[0];
        } catch (dbErr) {
            console.error('[ERROR] oauth.js handleAuthorize POST DB:', dbErr.message);
            return res.status(500).json({ error: 'Internal server error' });
        }

        // ── Deny ──────────────────────────────────────────
        if (!approved) {
            auditLog('OAUTH_CONSENT_DENIED', { username: decoded.username, clientId: client_id, ip });
            const denyUrl = new URL(redirect_uri);
            denyUrl.searchParams.set('error', 'access_denied');
            denyUrl.searchParams.set('state', state);
            return res.status(200).json({ redirect_url: denyUrl.toString() });
        }

        // ── Allow: ออก authorization_code ─────────────────
        const effectiveScope = parseScope(scope, clientRow.allowed_scopes);
        const code           = crypto.randomBytes(32).toString('hex');
        const codeHash       = hashToken(code);
        const expiresAt      = new Date(Date.now() + CODE_TTL_MINUTES * 60 * 1000);

        try {
            await pool.query(
                `INSERT INTO oauth_codes
                 (code_hash, client_id, username, redirect_uri, scope,
                  code_challenge, code_challenge_method, expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
                [codeHash, client_id, decoded.username, redirect_uri,
                 effectiveScope,
                 code_challenge || null,
                 code_challenge ? 'S256' : null,
                 expiresAt]
            );
        } catch (dbErr) {
            console.error('[ERROR] oauth.js handleAuthorize insert code:', dbErr.message);
            return res.status(500).json({ error: 'Internal server error' });
        }

        auditLog('OAUTH_CODE_ISSUED', { username: decoded.username, clientId: client_id, scope: effectiveScope, ip });

        const redirectUrl = new URL(redirect_uri);
        redirectUrl.searchParams.set('code', code);
        redirectUrl.searchParams.set('state', state);
        return res.status(200).json({ redirect_url: redirectUrl.toString() });
    }

    return res.status(405).json({ error: 'Method not allowed' });
}

// ── /api/oauth/token ──────────────────────────────────────────
// แลก authorization_code → access_token + refresh_token (server-to-server)
// หรือ refresh_token → access_token ใหม่ (token rotation)
async function handleToken(req, res, ip) {
    if (req.method !== 'POST') return res.status(405).send();

    try {
        if (await checkRateLimit(`ip:${ip}:oauth-token`, 20, 60_000)) {
            auditLog('OAUTH_TOKEN_RATE_LIMIT', { ip });
            return res.status(429).json({ error: 'too_many_requests' });
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit error (oauth-token), failing open:', rlErr.message);
    }

    if (!requireJson(req, res)) return;
    const { grant_type, code, redirect_uri, client_id, client_secret,
            code_verifier, refresh_token } = req.body;

    if (!grant_type || !['authorization_code', 'refresh_token'].includes(grant_type))
        return res.status(400).json({ error: 'unsupported_grant_type' });
    if (!client_id     || typeof client_id     !== 'string' || client_id.length     > 128) return res.status(400).json({ error: 'invalid_request: client_id is required' });
    if (!client_secret || typeof client_secret !== 'string' || client_secret.length > 256) return res.status(400).json({ error: 'invalid_request: client_secret is required' });

    const tokenClient = await pool.connect();
    try {
        await tokenClient.query('BEGIN');

        // ── ตรวจ client credentials ─────────────────────────
        const clientResult = await tokenClient.query(
            'SELECT client_secret_hash FROM oauth_clients WHERE client_id = $1',
            [client_id]
        );
        if (clientResult.rows.length === 0) {
            await tokenClient.query('ROLLBACK');
            auditLog('OAUTH_TOKEN_INVALID_CLIENT', { clientId: client_id, ip });
            hashClientSecret(client_secret); // dummy ป้องกัน timing attack
            return res.status(401).json({ error: 'invalid_client' });
        }
        if (!safeHexEqual(clientResult.rows[0].client_secret_hash, hashClientSecret(client_secret))) {
            await tokenClient.query('ROLLBACK');
            auditLog('OAUTH_TOKEN_WRONG_SECRET', { clientId: client_id, ip });
            return res.status(401).json({ error: 'invalid_client' });
        }

        // ══════════════════════════════════════════════════════
        // GRANT: authorization_code
        // ══════════════════════════════════════════════════════
        if (grant_type === 'authorization_code') {
            if (!code         || typeof code         !== 'string' || code.length         > 128) return res.status(400).json({ error: 'invalid_request: code is required' });
            if (!redirect_uri || typeof redirect_uri !== 'string' || redirect_uri.length > 512) return res.status(400).json({ error: 'invalid_request: redirect_uri is required' });

            // FOR UPDATE: lock row ป้องกัน concurrent redemption race condition
            const codeHash   = hashToken(code);
            const codeResult = await tokenClient.query(
                `SELECT id, username, redirect_uri, scope, expires_at, used,
                        code_challenge, code_challenge_method
                 FROM oauth_codes WHERE code_hash = $1 AND client_id = $2 FOR UPDATE`,
                [codeHash, client_id]
            );

            if (codeResult.rows.length === 0) {
                await tokenClient.query('ROLLBACK');
                auditLog('OAUTH_TOKEN_INVALID_CODE', { clientId: client_id, ip });
                return res.status(400).json({ error: 'invalid_grant' });
            }

            const codeRow = codeResult.rows[0];

            if (codeRow.used) {
                await tokenClient.query('ROLLBACK');
                auditLog('OAUTH_TOKEN_CODE_REUSE', {
                    clientId: client_id, username: codeRow.username, ip, note: 'possible code interception'
                });
                return res.status(400).json({ error: 'invalid_grant: code already used' });
            }
            if (new Date() > new Date(codeRow.expires_at)) {
                await tokenClient.query('ROLLBACK');
                return res.status(400).json({ error: 'invalid_grant: code has expired' });
            }
            if (codeRow.redirect_uri !== redirect_uri) {
                await tokenClient.query('ROLLBACK');
                auditLog('OAUTH_TOKEN_URI_MISMATCH', { clientId: client_id, ip });
                return res.status(400).json({ error: 'invalid_grant: redirect_uri mismatch' });
            }

            // ── PKCE verification (RFC 7636 S256) ─────────────
            // ถ้า code มี challenge → ต้องส่ง verifier, ถ้าไม่มี challenge → verifier ไม่จำเป็น
            if (codeRow.code_challenge) {
                if (!code_verifier || typeof code_verifier !== 'string' ||
                    code_verifier.length < 43 || code_verifier.length > 128) {
                    await tokenClient.query('ROLLBACK');
                    auditLog('OAUTH_TOKEN_PKCE_MISSING', { clientId: client_id, ip });
                    return res.status(400).json({ error: 'invalid_grant: code_verifier missing or invalid' });
                }
                // S256: BASE64URL(SHA256(ASCII(code_verifier))) == code_challenge
                const verifierHash = crypto
                    .createHash('sha256')
                    .update(code_verifier)
                    .digest('base64url');
                // [FIX] timing-safe comparison ป้องกัน timing oracle บน PKCE challenge
                // !== คืนเร็วเมื่อ prefix ต่างกัน → attacker retry code เดิม (used=FALSE จาก ROLLBACK)
                // แล้ววัด response time เพื่อ brute-force code_verifier ทีละ character
                // แก้: เปรียบเทียบ Base64URL string ผ่าน Buffer.from() + timingSafeEqual
                // Base64URL ใช้ alphabet [A-Za-z0-9\-_=] ซึ่ง valid UTF-8 ทุกตัว → Buffer.from safe
                let pkceMatch = false;
                try {
                    const verifierBuf  = Buffer.from(verifierHash,           'utf8');
                    const challengeBuf = Buffer.from(codeRow.code_challenge, 'utf8');
                    pkceMatch = verifierBuf.length === challengeBuf.length &&
                        crypto.timingSafeEqual(verifierBuf, challengeBuf);
                } catch {
                    pkceMatch = false;
                }
                if (!pkceMatch) {
                    await tokenClient.query('ROLLBACK');
                    auditLog('OAUTH_TOKEN_PKCE_FAIL', { clientId: client_id, ip });
                    return res.status(400).json({ error: 'invalid_grant: code_verifier mismatch' });
                }
            }

            await tokenClient.query('UPDATE oauth_codes SET used = TRUE WHERE id = $1', [codeRow.id]);

            const scope       = codeRow.scope || DEFAULT_SCOPE;
            const accessToken = crypto.randomBytes(32).toString('hex');
            const accessHash  = hashToken(accessToken);
            const accessExp   = new Date(Date.now() + ACCESS_TOKEN_TTL_SECONDS * 1000);

            await tokenClient.query(
                `INSERT INTO oauth_tokens (token_hash, token_type, client_id, username, scope, expires_at)
                 VALUES ($1, 'access', $2, $3, $4, $5)`,
                [accessHash, client_id, codeRow.username, scope, accessExp]
            );

            // ── Refresh Token ──────────────────────────────────
            const refreshToken = crypto.randomBytes(32).toString('hex');
            const refreshHash  = hashToken(refreshToken);
            const refreshExp   = new Date(Date.now() + REFRESH_TOKEN_TTL_DAYS * 86400 * 1000);

            await tokenClient.query(
                `INSERT INTO oauth_tokens (token_hash, token_type, client_id, username, scope, expires_at)
                 VALUES ($1, 'refresh', $2, $3, $4, $5)`,
                [refreshHash, client_id, codeRow.username, scope, refreshExp]
            );

            await tokenClient.query('COMMIT');
            auditLog('OAUTH_TOKEN_ISSUED', { clientId: client_id, username: codeRow.username, scope, ip });

            return res.status(200).json({
                access_token:  accessToken,
                token_type:    'Bearer',
                expires_in:    ACCESS_TOKEN_TTL_SECONDS,
                refresh_token: refreshToken,
                scope:         scope.join(' '),
            });
        }

        // ══════════════════════════════════════════════════════
        // GRANT: refresh_token (single-use rotation)
        // ══════════════════════════════════════════════════════
        if (grant_type === 'refresh_token') {
            if (!refresh_token || typeof refresh_token !== 'string' || refresh_token.length > 128) {
                await tokenClient.query('ROLLBACK');
                return res.status(400).json({ error: 'invalid_request: refresh_token is required' });
            }

            const rtHash  = hashToken(refresh_token);
            // FOR UPDATE: ป้องกัน concurrent refresh race condition
            const rtResult = await tokenClient.query(
                `SELECT id, username, scope, expires_at, revoked_at, client_id
                 FROM oauth_tokens
                 WHERE token_hash = $1 AND token_type = 'refresh' AND client_id = $2 FOR UPDATE`,
                [rtHash, client_id]
            );

            if (rtResult.rows.length === 0) {
                await tokenClient.query('ROLLBACK');
                auditLog('OAUTH_REFRESH_INVALID', { clientId: client_id, ip });
                return res.status(400).json({ error: 'invalid_grant' });
            }

            const rt = rtResult.rows[0];

            if (rt.revoked_at) {
                await tokenClient.query('ROLLBACK');
                // Token ถูก revoke แล้ว → อาจเป็น token reuse attack → revoke ทั้งหมดของ client+user
                // try/catch แยก: ถ้า revoke-all fail → ยัง return 400 + audit log เสมอ
                // ถ้าไม่มี try/catch: pool.query throw → outer catch → return 500 + audit log หาย
                try {
                    await pool.query(
                        `UPDATE oauth_tokens SET revoked_at = NOW()
                         WHERE client_id = $1 AND username = $2 AND revoked_at IS NULL`,
                        [client_id, rt.username]
                    );
                } catch (revokeErr) {
                    console.error('[ERROR] oauth.js refresh reuse revoke-all failed:', revokeErr.message);
                }
                auditLog('OAUTH_REFRESH_REUSE_REVOKE_ALL', {
                    clientId: client_id, username: rt.username, ip, note: 'possible token theft'
                });
                return res.status(400).json({ error: 'invalid_grant: refresh_token already used' });
            }
            if (new Date() > new Date(rt.expires_at)) {
                await tokenClient.query('ROLLBACK');
                return res.status(400).json({ error: 'invalid_grant: refresh_token has expired' });
            }

            // Revoke refresh token เก่า (rotation)
            await tokenClient.query(
                'UPDATE oauth_tokens SET revoked_at = NOW() WHERE id = $1',
                [rt.id]
            );

            const scope       = rt.scope || DEFAULT_SCOPE;
            const accessToken = crypto.randomBytes(32).toString('hex');
            const accessHash  = hashToken(accessToken);
            const accessExp   = new Date(Date.now() + ACCESS_TOKEN_TTL_SECONDS * 1000);

            await tokenClient.query(
                `INSERT INTO oauth_tokens (token_hash, token_type, client_id, username, scope, expires_at)
                 VALUES ($1, 'access', $2, $3, $4, $5)`,
                [accessHash, client_id, rt.username, scope, accessExp]
            );

            // ออก refresh token ใหม่ (rotation)
            const newRefreshToken = crypto.randomBytes(32).toString('hex');
            const newRefreshHash  = hashToken(newRefreshToken);
            const newRefreshExp   = new Date(Date.now() + REFRESH_TOKEN_TTL_DAYS * 86400 * 1000);

            await tokenClient.query(
                `INSERT INTO oauth_tokens (token_hash, token_type, client_id, username, scope, expires_at)
                 VALUES ($1, 'refresh', $2, $3, $4, $5)`,
                [newRefreshHash, client_id, rt.username, scope, newRefreshExp]
            );

            await tokenClient.query('COMMIT');
            auditLog('OAUTH_TOKEN_REFRESHED', { clientId: client_id, username: rt.username, ip });

            return res.status(200).json({
                access_token:  accessToken,
                token_type:    'Bearer',
                expires_in:    ACCESS_TOKEN_TTL_SECONDS,
                refresh_token: newRefreshToken,
                scope:         scope.join(' '),
            });
        }

    } catch (err) {
        try { await tokenClient.query('ROLLBACK'); } catch { /* ignore */ }
        console.error('[ERROR] oauth.js handleToken:', err);
        return res.status(500).json({ error: 'server_error' });
    } finally {
        tokenClient.release();
    }
}

// ── /api/oauth/userinfo ───────────────────────────────────────
// คืนข้อมูล user เมื่อ external app มี valid access_token
async function handleUserinfo(req, res, ip) {
    if (req.method !== 'GET') return res.status(405).send();

    try {
        if (await checkRateLimit(`ip:${ip}:oauth-userinfo`, 120, 60_000)) {
            auditLog('OAUTH_USERINFO_RATE_LIMIT', { ip });
            return res.status(429).json({ error: 'too_many_requests' });
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit error (oauth-userinfo), failing open:', rlErr.message);
    }

    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
        res.setHeader('WWW-Authenticate', 'Bearer realm="oauth", error="invalid_token"');
        return res.status(401).json({ error: 'invalid_token' });
    }
    const token = authHeader.slice(7).trim();
    if (!token || token.length > 128) {
        res.setHeader('WWW-Authenticate', 'Bearer realm="oauth", error="invalid_token"');
        return res.status(401).json({ error: 'invalid_token' });
    }

    // Probabilistic cleanup: 2% ต่อ request — ลบ expired tokens (fire-and-forget)
    // ใช้ crypto.randomInt แทน Math.random สำหรับ consistency ใน security-sensitive file
    if (crypto.randomInt(100) < 2) {
        pool.query(`DELETE FROM oauth_tokens WHERE expires_at < NOW()`)
            .catch(err => console.error('[WARN] oauth_tokens cleanup error:', err.message));
        pool.query(`DELETE FROM oauth_codes WHERE expires_at < NOW() AND used = TRUE`)
            .catch(err => console.error('[WARN] oauth_codes cleanup error:', err.message));
    }

    try {
        const result = await pool.query(
            `SELECT ot.username, ot.client_id, ot.expires_at, ot.revoked_at, ot.scope,
                    u.email, u.id AS user_id, u.email_verified
             FROM oauth_tokens ot
             JOIN users u ON u.username = ot.username
             WHERE ot.token_hash = $1 AND ot.token_type = 'access'`,
            [hashToken(token)]
        );

        // ไม่แยกแยะ "ไม่มี" vs "expired" vs "revoked" ป้องกัน token enumeration
        if (result.rows.length === 0) {
            res.setHeader('WWW-Authenticate', 'Bearer realm="oauth", error="invalid_token"');
            return res.status(401).json({ error: 'invalid_token' });
        }

        const row = result.rows[0];

        if (row.revoked_at) {
            auditLog('OAUTH_USERINFO_REVOKED_TOKEN', { clientId: row.client_id, ip });
            res.setHeader('WWW-Authenticate', 'Bearer realm="oauth", error="invalid_token"');
            return res.status(401).json({ error: 'invalid_token' });
        }
        if (new Date() > new Date(row.expires_at)) {
            res.setHeader('WWW-Authenticate',
                'Bearer realm="oauth", error="invalid_token", error_description="token expired"');
            return res.status(401).json({ error: 'invalid_token' });
        }

        // ── Scope-aware response ───────────────────────────
        const scope    = row.scope || DEFAULT_SCOPE;
        const response = {};

        if (scope.includes('openid'))  response.sub      = String(row.user_id);
        if (scope.includes('profile')) response.username = row.username;
        // email คืนเฉพาะ email_verified = TRUE เท่านั้น
        if (scope.includes('email') && row.email_verified)
            response.email = row.email;

        return res.status(200).json(response);

    } catch (err) {
        console.error('[ERROR] oauth.js handleUserinfo:', err);
        return res.status(500).json({ error: 'server_error' });
    }
}

// ── /api/oauth/sso-exchange ───────────────────────────────────
// แลก one-time sso_token → user info (สำหรับ redirect-back SSO flow)
//
// Flow:
//   1. User login สำเร็จใน CARS SSO
//   2. auth.js / verify-mfa.js INSERT sso_token → redirect ?sso_token=xxx
//   3. Third-party app GET /api/oauth/sso-exchange?token=xxx
//   4. ตรวจ token → mark used → คืน user info
//
// Security:
//   - Token single-use (used=TRUE หลังแลก)
//   - TTL 5 นาที
//   - Rate limited per IP
//   - ไม่ต้องการ client_secret (เพราะใช้เฉพาะ redirect flow ที่ origin มาจาก SSO เอง)
async function handleSsoExchange(req, res, ip) {
    if (req.method !== 'GET') return res.status(405).send();

    try {
        if (await checkRateLimit(`ip:${ip}:sso-exchange`, 30, 60_000)) {
            auditLog('SSO_EXCHANGE_RATE_LIMIT', { ip });
            return res.status(429).json({ error: 'too_many_requests' });
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit error (sso-exchange), failing open:', rlErr.message);
    }

    const { token } = req.query;
    if (!token || typeof token !== 'string' || token.length > 36) {
        return res.status(400).json({ error: 'invalid_request: missing or invalid token' });
    }

    // UUID format validation (sso_token ใช้ randomUUID ก่อน hash)
    const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (!UUID_REGEX.test(token)) {
        return res.status(400).json({ error: 'invalid_request: invalid token format' });
    }

    // [BUG-005 FIX] hash token ก่อน lookup — DB เก็บ hash ไม่ใช่ raw UUID
    const tokenHash = hashToken(token);

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // FOR UPDATE: ป้องกัน concurrent exchange race condition
        const result = await client.query(
            `SELECT st.id, st.user_id, st.used, st.expires_at, u.username, u.email, u.email_verified
             FROM sso_tokens st
             JOIN users u ON u.id = st.user_id
             WHERE st.token = $1 FOR UPDATE`,
            [tokenHash]
        );

        if (result.rows.length === 0) {
            await client.query('ROLLBACK');
            auditLog('SSO_EXCHANGE_INVALID', { ip });
            return res.status(400).json({ error: 'invalid_token' });
        }

        const row = result.rows[0];

        if (row.used) {
            await client.query('ROLLBACK');
            auditLog('SSO_EXCHANGE_REUSE', { username: row.username, ip, note: 'possible token theft' });
            return res.status(400).json({ error: 'invalid_token: token already used' });
        }

        if (new Date() > new Date(row.expires_at)) {
            await client.query('ROLLBACK');
            auditLog('SSO_EXCHANGE_EXPIRED', { ip });
            return res.status(400).json({ error: 'invalid_token: token has expired' });
        }

        // Mark as used — single-use
        await client.query(
            'UPDATE sso_tokens SET used = TRUE WHERE id = $1',
            [row.id]
        );

        await client.query('COMMIT');
        auditLog('SSO_EXCHANGE_SUCCESS', { username: row.username, ip });

        return res.status(200).json({
            user_id:  row.user_id,
            username: row.username,
            // [FIX] คืน email เฉพาะ email_verified = TRUE เพื่อไม่ leak unverified address
            // ช่วยให้ third-party app ที่รับ sso_token ไม่ต้องเรียก /userinfo ซ้ำ
            ...(row.email_verified ? { email: row.email } : {}),
        });

    } catch (err) {
        try { await client.query('ROLLBACK'); } catch { /* ignore */ }
        console.error('[ERROR] oauth.js handleSsoExchange:', err);
        return res.status(500).json({ error: 'server_error' });
    } finally {
        client.release();
    }
}

// ── /api/oauth/revoke ─────────────────────────────────────────
// ยกเลิก access_token ก่อน expire (ตาม RFC 7009)
async function handleRevoke(req, res, ip) {
    if (req.method !== 'POST') return res.status(405).send();

    try {
        if (await checkRateLimit(`ip:${ip}:oauth-revoke`, 20, 60_000)) {
            return res.status(429).json({ error: 'too_many_requests' });
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit error (oauth-revoke), failing open:', rlErr.message);
    }

    if (!requireJson(req, res)) return;
    const { token, client_id, client_secret } = req.body;

    if (!token         || typeof token         !== 'string' || token.length         > 128) return res.status(400).json({ error: 'invalid_request: token is required' });
    if (!client_id     || typeof client_id     !== 'string' || client_id.length     > 128) return res.status(400).json({ error: 'invalid_request: client_id is required' });
    if (!client_secret || typeof client_secret !== 'string' || client_secret.length > 256) return res.status(400).json({ error: 'invalid_request: client_secret is required' });

    try {
        const clientResult = await pool.query(
            'SELECT client_secret_hash FROM oauth_clients WHERE client_id = $1', [client_id]
        );
        if (clientResult.rows.length === 0) {
            hashClientSecret(client_secret); // dummy ป้องกัน timing attack
            return res.status(401).json({ error: 'invalid_client' });
        }
        if (!safeHexEqual(clientResult.rows[0].client_secret_hash, hashClientSecret(client_secret))) {
            auditLog('OAUTH_REVOKE_WRONG_SECRET', { clientId: client_id, ip });
            return res.status(401).json({ error: 'invalid_client' });
        }

        // [FIX] RFC 7009 section 2: revoke associated tokens ด้วย
        // หา username + token_type จาก token ที่ส่งมา แล้ว revoke ทั้ง access + refresh
        // ของ client+user นั้น ป้องกัน: revoke access_token แต่ refresh_token ยังขอใหม่ได้
        const targetHash = hashToken(token);
        const tokenRow = await pool.query(
            `SELECT username, token_type FROM oauth_tokens
             WHERE token_hash = $1 AND client_id = $2`,
            [targetHash, client_id]
        );

        if (tokenRow.rows.length > 0) {
            const { username: tokenUsername } = tokenRow.rows[0];
            // Revoke ทั้ง access + refresh ของ client+user นี้ (ไม่เฉพาะ token ที่ส่งมา)
            const result = await pool.query(
                `UPDATE oauth_tokens SET revoked_at = NOW()
                 WHERE client_id = $1 AND username = $2 AND revoked_at IS NULL`,
                [client_id, tokenUsername]
            );
            if (result.rowCount > 0) auditLog('OAUTH_TOKEN_REVOKED', { clientId: client_id, username: tokenUsername, ip });
        }
        // คืน 200 เสมอ ไม่ว่า token จะมีอยู่หรือไม่ (ตาม RFC 7009)
        return res.status(200).json({ success: true });

    } catch (err) {
        console.error('[ERROR] oauth.js handleRevoke:', err);
        return res.status(500).json({ error: 'server_error' });
    }
}

// ─── Main Router ───────────────────────────────────────────────
// ตรวจ URL path แล้ว dispatch ไปยัง sub-handler ที่ถูกต้อง
// req.url format บน Vercel: "/api/oauth/token?foo=bar"
// ดึง sub-path ด้วย regex เพื่อไม่ต้องพึ่ง URL parsing library
export default async function handler(req, res) {
    setSecurityHeaders(res, 'SAMEORIGIN');

    const ip = getClientIp(req);

    // ดึง sub-path จาก URL: "/api/oauth/token" → "token"
    const match = req.url?.match(/\/api\/oauth\/([^/?]+)/);
    const sub   = match?.[1];

    switch (sub) {
        case 'clients':      return handleClients(req, res, ip);
        case 'authorize':    return handleAuthorize(req, res, ip);
        case 'token':        return handleToken(req, res, ip);
        case 'userinfo':     return handleUserinfo(req, res, ip);
        case 'revoke':       return handleRevoke(req, res, ip);
        case 'sso-exchange': return handleSsoExchange(req, res, ip);
        default:
            return res.status(404).json({ error: 'OAuth endpoint not found' });
    }
}
