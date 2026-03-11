// ============================================================
// 🔐 oauth.js — OAuth 2.0 Combined Handler (Single Serverless Function)
//
// รวม 5 OAuth endpoints ไว้ในไฟล์เดียว เพื่อไม่เกิน Vercel limit (12 functions)
// Route ด้วย URL path ที่ตรวจจาก req.url:
//
//   /api/oauth/clients   → handleClients()   (GET / POST / DELETE)
//   /api/oauth/authorize → handleAuthorize() (GET / POST)
//   /api/oauth/token     → handleToken()     (POST)
//   /api/oauth/userinfo  → handleUserinfo()  (GET)
//   /api/oauth/revoke    → handleRevoke()    (POST)
//
// vercel.json rewrite:
//   { "source": "/api/oauth/:path*", "destination": "/api/oauth.js" }
//
// Shared utilities (module-level, สร้างครั้งเดียว):
//   hashToken()         — SHA-256 สำหรับ code / access_token
//   hashClientSecret()  — HMAC-SHA256 ด้วย OAUTH_SECRET_PEPPER
//   safeHexEqual()      — timing-safe compare
//   verifyBearerSession() — ตรวจ JWT Bearer header
//   verifySessionCookie() — ตรวจ JWT session cookie + DB revocation
//   setSecurityHeaders()  — security response headers
//   auditLog()            — structured JSON logging
// ============================================================
import '../startup-check.js';
import { pool }           from '../lib/db.js';
import { checkRateLimit } from '../lib/rate-limit.js';
import { getClientIp }    from '../lib/ip-utils.js';
import jwt    from 'jsonwebtoken';
import { parse } from 'cookie';
import crypto from 'crypto';

// ─── Constants ────────────────────────────────────────────────
const USER_REGEX              = /^[a-zA-Z0-9]+$/;
const MAX_CLIENTS_PER_USER    = 10;
const CODE_TTL_MINUTES        = 10;
const ACCESS_TOKEN_TTL_SECONDS = 3600; // 1 ชั่วโมง

// ─── Shared Utilities ─────────────────────────────────────────

function auditLog(event, fields) {
    console.log(JSON.stringify({ event, ts: new Date().toISOString(), ...fields }));
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
        .createHmac('sha256', process.env.OAUTH_SECRET_PEPPER || process.env.JWT_SECRET)
        .update(secret)
        .digest('hex');
}

// safeHexEqual: timing-safe string comparison ป้องกัน timing attack
function safeHexEqual(a, b) {
    if (a.length !== b.length) return false;
    try {
        return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
    } catch {
        return false;
    }
}

// verifyBearerSession: ตรวจ JWT จาก Authorization: Bearer header
// ใช้เฉพาะ /clients endpoint (developer API)
// คืน decoded payload ถ้า valid, null ถ้าไม่ valid
function verifyBearerSession(req) {
    const auth = req.headers.authorization;
    if (!auth?.startsWith('Bearer ')) return null;
    const token = auth.slice(7);
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET, {
            issuer: 'auth-service', audience: 'api'
        });
        if (!decoded.jti) return null;
        if (!decoded.username || typeof decoded.username !== 'string' ||
            decoded.username.length > 32 || !USER_REGEX.test(decoded.username)) return null;
        return decoded;
    } catch {
        return null;
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
        res.status(400).json({ error: 'ข้อมูลไม่ถูกต้อง' });
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
            return res.status(429).json({ error: 'ส่งคำขอบ่อยเกินไป กรุณารอสักครู่' });
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit error (oauth-clients), failing open:', rlErr.message);
    }

    // verifySessionCookie: ตรวจ httpOnly cookie + DB revocation
    // เหมาะกับ same-origin portal มากกว่า Bearer
    const decoded = await verifySessionCookie(req);
    if (!decoded) {
        return res.status(401).json({ error: 'Unauthorized: กรุณา login ก่อน' });
    }
    const username = decoded.username;

    try {
        // ── POST: สร้าง client app ─────────────────────────
        if (req.method === 'POST') {
            if (!requireJson(req, res)) return;
            const { name, redirect_uris } = req.body;

            if (typeof name !== 'string' || !name.trim() || name.length > 128)
                return res.status(400).json({ error: 'name ต้องเป็น string ไม่เกิน 128 ตัวอักษร' });

            if (!Array.isArray(redirect_uris) || redirect_uris.length === 0 || redirect_uris.length > 10)
                return res.status(400).json({ error: 'redirect_uris ต้องเป็น array มี 1–10 รายการ' });

            for (const uri of redirect_uris) {
                if (typeof uri !== 'string' || uri.length > 512)
                    return res.status(400).json({ error: `redirect_uri ไม่ถูกต้อง: ${uri}` });
                let parsed;
                try { parsed = new URL(uri); } catch {
                    return res.status(400).json({ error: `redirect_uri format ไม่ถูกต้อง: ${uri}` });
                }
                const isLocalhost = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';
                if (parsed.protocol !== 'https:' && !isLocalhost)
                    return res.status(400).json({ error: `redirect_uri ต้องเป็น HTTPS (ยกเว้น localhost): ${uri}` });
            }

            const countRow = await pool.query(
                'SELECT COUNT(*) FROM oauth_clients WHERE owner_username = $1', [username]
            );
            if (parseInt(countRow.rows[0].count, 10) >= MAX_CLIENTS_PER_USER)
                return res.status(400).json({ error: `สร้าง client app ได้สูงสุด ${MAX_CLIENTS_PER_USER} apps ต่อ account` });

            const clientId     = 'c_' + crypto.randomBytes(16).toString('hex');
            const clientSecret = crypto.randomBytes(32).toString('hex');
            const secretHash   = hashClientSecret(clientSecret);

            await pool.query(
                `INSERT INTO oauth_clients (client_id, client_secret_hash, name, redirect_uris, owner_username)
                 VALUES ($1, $2, $3, $4, $5)`,
                [clientId, secretHash, name.trim(), redirect_uris, username]
            );

            auditLog('OAUTH_CLIENT_CREATED', { username, clientId, ip });
            return res.status(201).json({
                client_id:     clientId,
                client_secret: clientSecret,
                name:          name.trim(),
                redirect_uris,
                notice:        '⚠️ บันทึก client_secret ไว้ด้วย จะไม่สามารถดูซ้ำได้อีก'
            });
        }

        // ── GET: ดูรายการ ──────────────────────────────────
        if (req.method === 'GET') {
            const result = await pool.query(
                `SELECT client_id, name, redirect_uris, created_at
                 FROM oauth_clients WHERE owner_username = $1 ORDER BY created_at DESC`,
                [username]
            );
            return res.status(200).json({ clients: result.rows });
        }

        // ── DELETE: ลบ client app ──────────────────────────
        if (req.method === 'DELETE') {
            if (!requireJson(req, res)) return;
            const { client_id } = req.body;
            if (!client_id || typeof client_id !== 'string' || client_id.length > 128)
                return res.status(400).json({ error: 'ต้องระบุ client_id' });

            const result = await pool.query(
                'DELETE FROM oauth_clients WHERE client_id = $1 AND owner_username = $2',
                [client_id, username]
            );
            if (result.rowCount === 0)
                return res.status(404).json({ error: 'ไม่พบ client app หรือไม่ใช่ของคุณ' });

            auditLog('OAUTH_CLIENT_DELETED', { username, clientId: client_id, ip });
            return res.status(200).json({ success: true });
        }

        return res.status(405).json({ error: 'Method not allowed' });
    } catch (err) {
        console.error('[ERROR] oauth.js handleClients:', err);
        return res.status(500).json({ error: 'เซิร์ฟเวอร์ขัดข้อง' });
    }
}

// ── /api/oauth/authorize ──────────────────────────────────────
// Consent flow: GET แสดงข้อมูล app, POST รับผลการตัดสินใจ
// Auth: session_token cookie
async function handleAuthorize(req, res, ip) {
    try {
        if (await checkRateLimit(`ip:${ip}:oauth-authorize`, 30, 60_000)) {
            auditLog('OAUTH_AUTHORIZE_RATE_LIMIT', { ip });
            return res.status(429).json({ error: 'ส่งคำขอบ่อยเกินไป กรุณารอสักครู่' });
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit error (oauth-authorize), failing open:', rlErr.message);
    }

    // ── GET: ตรวจ params + session → ส่งข้อมูลสำหรับ consent UI ──
    if (req.method === 'GET') {
        const { client_id, redirect_uri, response_type, state } = req.query;

        if (response_type !== 'code')
            return res.status(400).json({ error: 'unsupported_response_type' });
        if (!client_id || typeof client_id !== 'string' || client_id.length > 128)
            return res.status(400).json({ error: 'invalid_request: client_id ขาดหรือไม่ถูกต้อง' });
        if (!redirect_uri || typeof redirect_uri !== 'string' || redirect_uri.length > 512)
            return res.status(400).json({ error: 'invalid_request: redirect_uri ขาดหรือไม่ถูกต้อง' });
        if (!state || typeof state !== 'string' || state.length > 256)
            return res.status(400).json({ error: 'invalid_request: state ขาดหรือไม่ถูกต้อง' });

        let clientResult;
        try {
            clientResult = await pool.query(
                'SELECT name, redirect_uris FROM oauth_clients WHERE client_id = $1',
                [client_id]
            );
        } catch (dbErr) {
            console.error('[ERROR] oauth.js handleAuthorize GET DB:', dbErr.message);
            return res.status(500).json({ error: 'เซิร์ฟเวอร์ขัดข้อง' });
        }

        if (clientResult.rows.length === 0)
            return res.status(400).json({ error: 'invalid_client: client_id ไม่ถูกต้อง' });

        const { name: appName, redirect_uris } = clientResult.rows[0];

        if (!redirect_uris.includes(redirect_uri))
            return res.status(400).json({ error: 'invalid_redirect_uri: ไม่ได้ลงทะเบียน URI นี้' });

        const decoded = await verifySessionCookie(req);
        if (!decoded) {
            return res.status(401).json({ error: 'unauthenticated', app_name: appName });
        }

        auditLog('OAUTH_CONSENT_VIEW', { username: decoded.username, clientId: client_id, ip });
        return res.status(200).json({
            app_name: appName, client_id, redirect_uri, state, username: decoded.username
        });
    }

    // ── POST: รับผลการตัดสินใจ Allow / Deny ───────────────
    if (req.method === 'POST') {
        if (!requireJson(req, res)) return;
        const { client_id, redirect_uri, state, approved } = req.body;

        if (!client_id || typeof client_id !== 'string' || client_id.length > 128)
            return res.status(400).json({ error: 'invalid_request: client_id ขาดหรือไม่ถูกต้อง' });
        if (!redirect_uri || typeof redirect_uri !== 'string' || redirect_uri.length > 512)
            return res.status(400).json({ error: 'invalid_request: redirect_uri ขาดหรือไม่ถูกต้อง' });
        if (!state || typeof state !== 'string' || state.length > 256)
            return res.status(400).json({ error: 'invalid_request: state ขาดหรือไม่ถูกต้อง' });

        const decoded = await verifySessionCookie(req);
        if (!decoded) return res.status(401).json({ error: 'session_expired: กรุณา login ใหม่' });

        let uriResult;
        try {
            uriResult = await pool.query(
                `SELECT 1 FROM oauth_clients WHERE client_id = $1 AND $2 = ANY(redirect_uris)`,
                [client_id, redirect_uri]
            );
        } catch (dbErr) {
            console.error('[ERROR] oauth.js handleAuthorize POST DB:', dbErr.message);
            return res.status(500).json({ error: 'เซิร์ฟเวอร์ขัดข้อง' });
        }

        if (uriResult.rows.length === 0)
            return res.status(400).json({ error: 'invalid_client หรือ invalid_redirect_uri' });

        // ── Deny ──────────────────────────────────────────
        if (!approved) {
            auditLog('OAUTH_CONSENT_DENIED', { username: decoded.username, clientId: client_id, ip });
            const denyUrl = new URL(redirect_uri);
            denyUrl.searchParams.set('error', 'access_denied');
            denyUrl.searchParams.set('state', state);
            return res.status(200).json({ redirect_url: denyUrl.toString() });
        }

        // ── Allow: ออก authorization_code ─────────────────
        // 32-byte random = 256-bit entropy, เก็บเป็น SHA-256 hash
        const code      = crypto.randomBytes(32).toString('hex');
        const codeHash  = hashToken(code);
        const expiresAt = new Date(Date.now() + CODE_TTL_MINUTES * 60 * 1000);

        try {
            await pool.query(
                `INSERT INTO oauth_codes (code_hash, client_id, username, redirect_uri, expires_at)
                 VALUES ($1, $2, $3, $4, $5)`,
                [codeHash, client_id, decoded.username, redirect_uri, expiresAt]
            );
        } catch (dbErr) {
            console.error('[ERROR] oauth.js handleAuthorize insert code:', dbErr.message);
            return res.status(500).json({ error: 'เซิร์ฟเวอร์ขัดข้อง' });
        }

        auditLog('OAUTH_CODE_ISSUED', { username: decoded.username, clientId: client_id, ip });

        const redirectUrl = new URL(redirect_uri);
        redirectUrl.searchParams.set('code', code);
        redirectUrl.searchParams.set('state', state);
        return res.status(200).json({ redirect_url: redirectUrl.toString() });
    }

    return res.status(405).json({ error: 'Method not allowed' });
}

// ── /api/oauth/token ──────────────────────────────────────────
// แลก authorization_code → access_token (server-to-server)
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
    const { grant_type, code, redirect_uri, client_id, client_secret } = req.body;

    if (grant_type !== 'authorization_code')
        return res.status(400).json({ error: 'unsupported_grant_type' });
    if (!code          || typeof code          !== 'string' || code.length          > 128) return res.status(400).json({ error: 'invalid_request: code ขาด' });
    if (!redirect_uri  || typeof redirect_uri  !== 'string' || redirect_uri.length  > 512) return res.status(400).json({ error: 'invalid_request: redirect_uri ขาด' });
    if (!client_id     || typeof client_id     !== 'string' || client_id.length     > 128) return res.status(400).json({ error: 'invalid_request: client_id ขาด' });
    if (!client_secret || typeof client_secret !== 'string' || client_secret.length > 256) return res.status(400).json({ error: 'invalid_request: client_secret ขาด' });

    const tokenClient = await pool.connect();
    try {
        await tokenClient.query('BEGIN');

        // ── ตรวจ client credentials ───────────────────────
        const clientResult = await tokenClient.query(
            'SELECT client_secret_hash FROM oauth_clients WHERE client_id = $1',
            [client_id]
        );
        if (clientResult.rows.length === 0) {
            await tokenClient.query('ROLLBACK');
            auditLog('OAUTH_TOKEN_INVALID_CLIENT', { clientId: client_id, ip });
            hashClientSecret(client_secret); // dummy computation ป้องกัน timing attack
            return res.status(401).json({ error: 'invalid_client' });
        }

        if (!safeHexEqual(clientResult.rows[0].client_secret_hash, hashClientSecret(client_secret))) {
            await tokenClient.query('ROLLBACK');
            auditLog('OAUTH_TOKEN_WRONG_SECRET', { clientId: client_id, ip });
            return res.status(401).json({ error: 'invalid_client' });
        }

        // ── ตรวจ authorization_code ────────────────────────
        // FOR UPDATE: lock row ป้องกัน concurrent redemption race condition
        const codeHash   = hashToken(code);
        const codeResult = await tokenClient.query(
            `SELECT id, username, redirect_uri, expires_at, used
             FROM oauth_codes WHERE code_hash = $1 AND client_id = $2 FOR UPDATE`,
            [codeHash, client_id]
        );

        if (codeResult.rows.length === 0) {
            await tokenClient.query('ROLLBACK');
            auditLog('OAUTH_TOKEN_INVALID_CODE', { clientId: client_id, ip });
            return res.status(400).json({ error: 'invalid_grant' });
        }

        const codeRow = codeResult.rows[0];

        // code reuse → อาจเป็น code interception → log ไว้ตรวจสอบ
        if (codeRow.used) {
            await tokenClient.query('ROLLBACK');
            auditLog('OAUTH_TOKEN_CODE_REUSE', {
                clientId: client_id, username: codeRow.username, ip, note: 'possible code interception'
            });
            return res.status(400).json({ error: 'invalid_grant: code ถูกใช้แล้ว' });
        }
        if (new Date() > new Date(codeRow.expires_at)) {
            await tokenClient.query('ROLLBACK');
            return res.status(400).json({ error: 'invalid_grant: code หมดอายุแล้ว' });
        }
        if (codeRow.redirect_uri !== redirect_uri) {
            await tokenClient.query('ROLLBACK');
            auditLog('OAUTH_TOKEN_URI_MISMATCH', { clientId: client_id, ip });
            return res.status(400).json({ error: 'invalid_grant: redirect_uri ไม่ตรง' });
        }

        await tokenClient.query('UPDATE oauth_codes SET used = TRUE WHERE id = $1', [codeRow.id]);

        // ── ออก access_token ───────────────────────────────
        const accessToken = crypto.randomBytes(32).toString('hex');
        const tokenHash   = hashToken(accessToken);
        const expiresAt   = new Date(Date.now() + ACCESS_TOKEN_TTL_SECONDS * 1000);

        await tokenClient.query(
            `INSERT INTO oauth_tokens (token_hash, client_id, username, expires_at)
             VALUES ($1, $2, $3, $4)`,
            [tokenHash, client_id, codeRow.username, expiresAt]
        );

        await tokenClient.query('COMMIT');
        auditLog('OAUTH_TOKEN_ISSUED', { clientId: client_id, username: codeRow.username, ip });

        // Response ตาม RFC 6749 Section 5.1
        return res.status(200).json({
            access_token: accessToken,
            token_type:   'Bearer',
            expires_in:   ACCESS_TOKEN_TTL_SECONDS,
        });

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
    if (Math.random() < 0.02) {
        pool.query(`DELETE FROM oauth_tokens WHERE expires_at < NOW()`)
            .catch(err => console.error('[WARN] oauth_tokens cleanup error:', err.message));
        pool.query(`DELETE FROM oauth_codes WHERE expires_at < NOW() AND used = TRUE`)
            .catch(err => console.error('[WARN] oauth_codes cleanup error:', err.message));
    }

    try {
        const result = await pool.query(
            `SELECT username, client_id, expires_at, revoked_at
             FROM oauth_tokens WHERE token_hash = $1`,
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

        return res.status(200).json({ username: row.username });

    } catch (err) {
        console.error('[ERROR] oauth.js handleUserinfo:', err);
        return res.status(500).json({ error: 'server_error' });
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

    if (!token         || typeof token         !== 'string' || token.length         > 128) return res.status(400).json({ error: 'invalid_request: token ขาด' });
    if (!client_id     || typeof client_id     !== 'string' || client_id.length     > 128) return res.status(400).json({ error: 'invalid_request: client_id ขาด' });
    if (!client_secret || typeof client_secret !== 'string' || client_secret.length > 256) return res.status(400).json({ error: 'invalid_request: client_secret ขาด' });

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

        // Revoke เฉพาะ token ที่เป็นของ client นี้ ป้องกัน cross-client revocation
        // คืน 200 เสมอ ไม่ว่า token จะมีอยู่หรือไม่ (ตาม RFC 7009)
        const result = await pool.query(
            `UPDATE oauth_tokens SET revoked_at = NOW()
             WHERE token_hash = $1 AND client_id = $2 AND revoked_at IS NULL`,
            [hashToken(token), client_id]
        );
        if (result.rowCount > 0) auditLog('OAUTH_TOKEN_REVOKED', { clientId: client_id, ip });

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
        case 'clients':   return handleClients(req, res, ip);
        case 'authorize': return handleAuthorize(req, res, ip);
        case 'token':     return handleToken(req, res, ip);
        case 'userinfo':  return handleUserinfo(req, res, ip);
        case 'revoke':    return handleRevoke(req, res, ip);
        default:
            return res.status(404).json({ error: 'OAuth endpoint ไม่มีอยู่' });
    }
}
