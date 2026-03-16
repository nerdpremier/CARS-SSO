import { pool } from '../db.js';
import jwt from 'jsonwebtoken';
import { parse } from 'cookie';
import crypto from 'crypto';
import { auditLog, USER_REGEX } from '../response-utils.js';

// Scopes ที่ระบบรองรับ — ต้องตรงกับ schema.sql comment
export const VALID_SCOPES = new Set(['profile', 'email', 'openid']);
export const DEFAULT_SCOPE = ['profile'];

// parseScope: แปลง scope string → validated array
// ตัด scope ที่ไม่อยู่ใน VALID_SCOPES ออก, default เป็น ['profile']
export function parseScope(scopeStr, allowedScopes = [...VALID_SCOPES]) {
    if (!scopeStr || typeof scopeStr !== 'string') return DEFAULT_SCOPE;
    const requested = scopeStr.trim().split(/\s+/).filter(s => VALID_SCOPES.has(s));
    const allowed   = requested.filter(s => allowedScopes.includes(s));
    return allowed.length > 0 ? allowed : DEFAULT_SCOPE;
}

// hashToken: SHA-256 สำหรับ high-entropy random token
// ไม่ต้องการ salt เพราะ 256-bit random input ทำ preimage attack ไม่คุ้มค่า
export function hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
}

// hashClientSecret: HMAC-SHA256 ด้วย pepper
// เหมาะกว่า bcrypt สำหรับ high-entropy random string (256-bit)
export function hashClientSecret(secret) {
    return crypto
        .createHmac('sha256', process.env.OAUTH_SECRET_PEPPER)
        .update(secret)
        .digest('hex');
}

// safeHexEqual: timing-safe string comparison ป้องกัน timing attack
// รองรับ hex string เท่านั้น — ต้องตรวจ format ก่อน Buffer.from()
const HEX_REGEX = /^[0-9a-f]+$/i;
export function safeHexEqual(a, b) {
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
// ใช้เฉพาะ endpoints ที่ต้อง cookie-auth (developer portal + consent flow)
// คืน decoded payload ถ้า valid active session, null ถ้าไม่ valid
export async function verifySessionCookie(req) {
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
        console.error('[WARN] oauth shared verifySessionCookie DB error:', dbErr.message);
        return null;
    }

    auditLog('OAUTH_COOKIE_SESSION_OK', { username: decoded.username });
    return decoded;
}

