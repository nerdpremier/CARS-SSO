// ============================================================
// 🚪 api/logout.js — Logout + JWT Revocation
// ทำหน้าที่ 2 อย่างพร้อมกัน:
//   1. Revoke JWT (insert jti ลง revoked_tokens) — ป้องกัน token reuse หลัง logout
//   2. Clear cookies (session_token + csrf_token) — ป้องกัน browser ส่ง token เก่า
//
// Security design:
//   - ทุก response คืน success: true เสมอ (idempotent)
//   - Clear cookie ทำงานเสมอ ไม่ว่า token จะ valid หรือไม่
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

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();

    setSecurityHeaders(res);

    if (!isJsonContentType(req)) {
        return res.status(415).json({ error: 'Content-Type must be application/json' });
    }

    if (!validateCsrfToken(req)) {
        return res.status(403).json({ error: 'CSRF token ไม่ถูกต้อง' });
    }

    const ip = getClientIp(req);
    try {
        if (await checkRateLimit(`ip:${ip}:logout`, 20, 60_000)) {
            auditLog('LOGOUT_RATE_LIMIT', { ip });
            return res.status(429).json({ error: 'ส่งคำขอบ่อยเกินไป กรุณารอสักครู่' });
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

    // Clear ทั้ง session_token และ csrf_token — maxAge: 0 → browser ลบทันที
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
