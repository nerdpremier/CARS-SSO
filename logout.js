// ============================================================
// 🚪 api/logout.js — Logout + JWT Revocation + Cron Cleanup
//
// รวม 2 handlers ไว้ในไฟล์เดียวเพื่อไม่เกิน Vercel 12-function limit
// Route ด้วย method:
//   POST → logout (เดิม)
//   GET  → cleanup (Vercel Cron: "0 0 * * *")
//
// vercel.json:
//   { "source": "/api/cleanup", "destination": "/api/logout.js" }
//
// Security:
//   POST: CSRF + rate limit (idempotent, คืน success เสมอ)
//   GET:  timing-safe CRON_SECRET check + rate limit
// ============================================================
import '../startup-check.js';
import { serialize, parse }  from 'cookie';
import jwt                   from 'jsonwebtoken';
import { pool }              from '../lib/db.js';
import { validateCsrfToken } from '../lib/csrf-utils.js';
import { checkRateLimit }    from '../lib/rate-limit.js';
import { getClientIp }       from '../lib/ip-utils.js';
import { runCleanup }        from '../lib/cleanup.js';
import { setSecurityHeaders, auditLog, isJsonContentType } from '../lib/response-utils.js';
import crypto from 'crypto';

export default async function handler(req, res) {
    setSecurityHeaders(res);

    const ip = getClientIp(req);

    // ── GET: Cron Cleanup ────────────────────────────────────
    if (req.method === 'GET') {
        res.setHeader('Cache-Control', 'no-store');

        try {
            if (await checkRateLimit(`ip:${ip}:cleanup`, 10, 60_000)) {
                auditLog('CLEANUP_RATE_LIMIT', { ip });
                return res.status(429).json({ error: 'Too many requests' });
            }
        } catch (rlErr) {
            console.error('[WARN] rate-limit DB error (cleanup), failing open:', rlErr.message);
        }

        const authHeader = req.headers.authorization;
        const cronSecret = process.env.CRON_SECRET;

        if (!authHeader || typeof authHeader !== 'string') {
            auditLog('CLEANUP_UNAUTHORIZED', { ip, reason: 'missing_auth' });
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const parts = authHeader.split(' ');
        if (parts.length !== 2 || parts[0] !== 'Bearer' || !parts[1]) {
            auditLog('CLEANUP_UNAUTHORIZED', { ip, reason: 'invalid_auth_format' });
            return res.status(401).json({ error: 'Unauthorized' });
        }

        // timing-safe comparison ป้องกัน brute-force CRON_SECRET
        let authorized = false;
        try {
            const expected = Buffer.from(cronSecret, 'utf8');
            const provided = Buffer.from(parts[1], 'utf8');
            if (expected.length === provided.length) {
                authorized = crypto.timingSafeEqual(expected, provided);
            }
        } catch {
            authorized = false;
        }

        if (!authorized) {
            auditLog('CLEANUP_UNAUTHORIZED', { ip, reason: 'wrong_secret' });
            return res.status(401).json({ error: 'Unauthorized' });
        }

        try {
            const result = await runCleanup();
            auditLog('CLEANUP_COMPLETE', { ip, ...result });
            return res.status(200).json({ success: true, deleted: result });
        } catch (err) {
            console.error('[ERROR] logout.js cleanup:', err);
            return res.status(500).json({ error: 'Internal server error' });
        }
    }

    // ── POST: Logout ─────────────────────────────────────────
    if (req.method !== 'POST') return res.status(405).send();

    if (!isJsonContentType(req)) {
        return res.status(415).json({ error: 'Content-Type must be application/json' });
    }

    if (!validateCsrfToken(req)) {
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }

    try {
        if (await checkRateLimit(`ip:${ip}:logout`, 20, 60_000)) {
            auditLog('LOGOUT_RATE_LIMIT', { ip });
            return res.status(429).json({ error: 'Too many requests. Please try again later.' });
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit DB error (logout), failing open:', rlErr.message);
    }

    const cookies = parse(req.headers.cookie || '');
    const token   = cookies.session_token;

    if (token) {
        let decoded;
        try {
            decoded = jwt.verify(token, process.env.JWT_SECRET, {
                issuer:   'auth-service',
                audience: 'api'
            });
        } catch {
            decoded = null;
        }

        if (decoded?.jti && decoded?.exp) {
            try {
                const expiresAt = new Date(decoded.exp * 1000).toISOString();
                await pool.query(
                    'INSERT INTO revoked_tokens (jti, expires_at) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                    [decoded.jti, expiresAt]
                );
                auditLog('LOGOUT_SUCCESS', { username: decoded.username, jti: decoded.jti, ip });
            } catch (dbErr) {
                console.error('[ERROR] logout.js revoke token DB error:', dbErr.message);
                auditLog('LOGOUT_REVOKE_FAIL', { jti: decoded.jti, ip });
            }
        }
    }

    res.setHeader('Set-Cookie', [
        serialize('session_token', '', {
            httpOnly: true,
            secure:   process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge:   0,
            path:     '/'
        }),
        serialize('csrf_token', '', {
            httpOnly: false,
            secure:   process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge:   0,
            path:     '/'
        })
    ]);

    // Cleanup fire-and-forget — ไม่กระทบ response time
    runCleanup().catch(err => console.error('[WARN] logout cleanup failed:', err.message));

    return res.status(200).json({ success: true });
}
