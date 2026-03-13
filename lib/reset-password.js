// ============================================================
// 🔐 api/reset-password.js — Execute Password Reset
// ============================================================
import '../startup-check.js';
import { pool }              from '../lib/db.js';
import { validateCsrfToken } from '../lib/csrf-utils.js';
import { checkRateLimit }    from '../lib/rate-limit.js';
import { getClientIp }       from '../lib/ip-utils.js';
import {
    setSecurityHeaders, auditLog,
    PASS_REGEX, TOKEN_REGEX,
    isJsonContentType, isValidBody,
} from '../lib/response-utils.js';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();

    setSecurityHeaders(res);

    if (!isJsonContentType(req)) {
        return res.status(415).json({ error: 'Content-Type must be application/json' });
    }

    if (!validateCsrfToken(req)) {
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }

    const ip = getClientIp(req);
    try {
        if (await checkRateLimit(`ip:${ip}:reset-password`, 10, 3_600_000)) {
            auditLog('RESET_PASSWORD_IP_RATE_LIMIT', { ip });
            return res.status(429).json({ error: 'Too many requests. Please try again later.' });
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit DB error (reset-password), failing open:', rlErr.message);
    }

    if (!isValidBody(req.body)) {
        return res.status(400).json({ error: 'Invalid request data' });
    }

    const { token, password } = req.body;

    if (typeof token !== 'string' || !TOKEN_REGEX.test(token)) {
        return res.status(400).json({ error: 'Invalid reset token' });
    }
    if (typeof password !== 'string' || !password) {
        return res.status(400).json({ error: 'Please enter a new password' });
    }
    if (password.length > 128) {
        return res.status(400).json({ error: 'Password is too long (max 128 characters)' });
    }
    if (!PASS_REGEX.test(password)) {
        return res.status(400).json({ error: 'Password must be at least 8 characters with uppercase, lowercase, a number, and a symbol' });
    }

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    try {
        const client = await pool.connect();
        try {
            await client.query('BEGIN');

            // FOR UPDATE ป้องกัน race condition: token ใช้ได้ครั้งเดียวเท่านั้น
            const userRes = await client.query(
                `SELECT id, username
                 FROM users
                 WHERE reset_token = $1
                   AND reset_expires > NOW()
                 FOR UPDATE`,
                [tokenHash]
            );

            if (!userRes.rows[0]) {
                await client.query('ROLLBACK');
                return res.status(400).json({ error: 'Reset link has expired or is invalid' });
            }

            const { id: userId, username } = userRes.rows[0];

            const newHash = await bcrypt.hash(password, 12);

            // sessions_revoked_at = NOW() → session.js reject JWT ที่ออกก่อน timestamp นี้
            // reset_token = NULL: ป้องกัน token reuse แม้ concurrent request
            await client.query(
                `UPDATE users
                 SET password_hash       = $1,
                     reset_token         = NULL,
                     reset_expires       = NULL,
                     sessions_revoked_at = NOW()
                 WHERE id = $2`,
                [newHash, userId]
            );

            await client.query('COMMIT');

            auditLog('RESET_PASSWORD_SUCCESS', { username, ip });
            return res.status(200).json({ success: true });

        } catch (err) {
            try { await client.query('ROLLBACK'); } catch { /* ignore */ }
            throw err;
        } finally {
            client.release();
        }

    } catch (err) {
        console.error('[ERROR] reset-password.js:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
}
