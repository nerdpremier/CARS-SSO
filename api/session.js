// ============================================================
// 🔍 api/session.js — Session Verification
// ทำหน้าที่ตรวจสอบว่า JWT ใน session cookie ยังใช้งานได้หรือไม่
// ถูกเรียกทุก page load ที่ต้องการ authentication
//
// Verification chain (ตามลำดับ):
//   1. JWT signature + expiry + issuer + audience
//   2. jti ต้องมี (token เก่าที่ไม่มี jti ถูก reject)
//   3. username format validation (ป้องกัน forged payload)
//   4. DB: ตรวจ revoked_tokens (logout blacklist)
//   5. DB: ตรวจ sessions_revoked_at (password reset invalidation)
// ============================================================
import '../startup-check.js';
import jwt          from 'jsonwebtoken';
import { parse }    from 'cookie';
import { pool }     from '../lib/db.js';
import { checkRateLimit } from '../lib/rate-limit.js';
import { getClientIp }    from '../lib/ip-utils.js';
import crypto       from 'crypto';
import {
    setSecurityHeaders, auditLog,
    USER_REGEX,
} from '../lib/response-utils.js';

export default async function handler(req, res) {
    if (req.method !== 'GET') return res.status(405).send();

    setSecurityHeaders(res);
    // no-store: ป้องกัน browser/CDN cache session response
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.setHeader('Pragma', 'no-cache');

    const ip = getClientIp(req);
    try {
        if (await checkRateLimit(`ip:${ip}:session`, 120, 60_000)) {
            auditLog('SESSION_RATE_LIMIT', { ip });
            return res.status(429).json({ authenticated: false });
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit DB error (session), failing open:', rlErr.message);
    }

    // Probabilistic cleanup (5%): session.js ถูกเรียกบ่อยที่สุด → cleanup coverage สูง
    // ใช้ crypto.randomInt แทน Math.random: ไฟล์นี้ sensitive ควรหลีกเลี่ยง PRNG ที่ไม่ใช่ CSPRNG
    if (crypto.randomInt(100) < 5) {
        pool.query("DELETE FROM revoked_tokens WHERE expires_at < NOW()")
            .catch(err => console.error('[WARN] session.js revoked_tokens cleanup error:', err.message));
    }

    const cookies = parse(req.headers.cookie || '');
    const token   = cookies.session_token;

    if (!token) return res.status(401).json({ authenticated: false });

    let decoded;
    try {
        decoded = jwt.verify(token, process.env.JWT_SECRET, {
            issuer:   'auth-service',
            audience: 'api'
        });
    } catch {
        return res.status(401).json({ authenticated: false });
    }

    if (!decoded.jti) {
        return res.status(401).json({ authenticated: false });
    }

    if (!decoded.username ||
        typeof decoded.username !== 'string' ||
        decoded.username.length > 32 ||
        !USER_REGEX.test(decoded.username)) {
        return res.status(401).json({ authenticated: false });
    }

    try {
        // Single query: JOIN users + LEFT JOIN revoked_tokens (ลด round-trips จาก 2 เป็น 1)
        const result = await pool.query(
            `SELECT u.sessions_revoked_at, rt.jti AS revoked_jti
             FROM users u
             LEFT JOIN revoked_tokens rt
               ON rt.jti = $2 AND rt.expires_at > NOW()
             WHERE u.username = $1`,
            [decoded.username, decoded.jti]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ authenticated: false });
        }

        const { sessions_revoked_at, revoked_jti } = result.rows[0];

        if (revoked_jti) {
            auditLog('SESSION_REJECTED_REVOKED_JTI', { username: decoded.username, jti: decoded.jti, ip });
            return res.status(401).json({ authenticated: false });
        }

        if (sessions_revoked_at && typeof decoded.iat === 'number') {
            const issuedAt  = new Date(decoded.iat * 1000);
            const revokedAt = new Date(sessions_revoked_at);
            if (issuedAt < revokedAt) {
                auditLog('SESSION_REJECTED_PASSWORD_RESET', { username: decoded.username, jti: decoded.jti, ip });
                return res.status(401).json({ authenticated: false });
            }
        }

        return res.status(200).json({
            authenticated: true,
            user:          decoded.username,
        });

    } catch (dbErr) {
        console.error('[ERROR] session.js DB:', dbErr.message);
        return res.status(500).json({ authenticated: false });
    }
}
