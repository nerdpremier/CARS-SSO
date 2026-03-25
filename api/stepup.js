// ============================================================
// Step-up MFA for Customer Apps (Bearer)
//
// Purpose:
//   - Provide post-login "step-up" verification for customer apps that use OAuth Bearer tokens
//   - Does NOT rely on SSO web session cookies or sessionStorage
//
// Endpoint:
//   POST /api/stepup
//   Body:
//     { action: "send" }
//     { action: "verify", stepup_id: "<uuid>", code: "123456" }
//
// Auth:
//   Authorization: Bearer <access_token> (opaque, validated via oauth_tokens)
// ============================================================
import '../startup-check.js';
import crypto from 'crypto';
import { pool } from '../lib/db.js';
import { checkRateLimit } from '../lib/rate-limit.js';
import { getClientIp } from '../lib/ip-utils.js';
import { mailTransporter } from '../lib/mailer.js';
import {
    setSecurityHeaders,
    auditLog,
    isJsonContentType,
    isValidBody,
} from '../lib/response-utils.js';
import { ensureStepupChallengesSchema } from '../lib/risk-score.js';

const OTP_REGEX = /^\d{6}$/;
const STEPUP_TTL_MINUTES = 5;
const STEPUP_MAX_ATTEMPTS = 5;
const STEPUP_MAX_SENDS_PER_SESSION = 3;

/**
 * คำนวณค่า hash ของ Token ด้วยอัลกอริทึม SHA-256
 * @param {string} token - ข้อมูล Token ที่ต้องการ hash
 * @returns {string} ค่า hash ในรูปแบบเลขฐานสิบหก (hex string)
 */
function hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * คำนวณค่า hash ของรหัส Step-up (OTP) ด้วย HMAC-SHA256 แบบมี Pepper
 * @param {string} stepupId - รหัสอ้างอิงของการยืนยันแบบ Step-up
 * @param {string} code - รหัส OTP ที่ผู้ใช้กรอก
 * @returns {string} ค่า hash ในรูปแบบเลขฐานสิบหก
 */
function hashStepupCode(stepupId, code) {
    const pepper = process.env.MFA_PEPPER;
    if (!pepper) {
        throw new Error('MFA_PEPPER environment variable not set');
    }
    return crypto
        .createHmac('sha256', pepper)
        .update(`${stepupId}:${code}`)
        .digest('hex');
}

/**
 * ฟังก์ชันสำหรับดึงและตรวจสอบข้อมูลผู้ใช้จาก OAuth Bearer Token
 * โดยเทียบกับฐานข้อมูลว่า Token ยังไม่หมดอายุหรือไม่ถูกยกเลิก
 * @param {import('http').IncomingMessage} req - HTTP Request object
 * @returns {Promise<{username: string, tokenHash: string, sessionJti: string}|null>} ข้อมูลผู้ใช้หาก Token ถูกต้อง, คืน null หากไม่ถูกต้อง
 */
async function requireBearerUser(req) {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith?.('Bearer ')) return null;
    const token = authHeader.slice(7).trim();
    if (!token || token.length > 128) return null;

    const tokenHash = hashToken(token);
    const result = await pool.query(
        `SELECT ot.id, ot.username, ot.expires_at, ot.revoked_at
         FROM oauth_tokens ot
         WHERE ot.token_hash = $1 AND ot.token_type = 'access'`,
        [tokenHash]
    );
    const row = result.rows[0];
    if (!row) return null;
    if (row.revoked_at) return null;
    if (new Date() > new Date(row.expires_at)) return null;
    return { username: row.username, tokenHash, sessionJti: `oauth:${row.id}` };
}

/**
 * API Handler หลักสำหรับการยืนยันตัวตนแบบ Step-up MFA สำหรับ OAuth Bearer
 * รองรับการส่งรหัสไปยังอีเมล (Action: 'send') และการตรวจรหัสผ่าน (Action: 'verify')
 * สำหรับใช้ตอนผู้ใช้ทำธุรกรรมสำคัญ (เช่น การโอนเงิน หรือ การแก้ข้อมูลสำคัญ)
 * @param {import('http').IncomingMessage} req - HTTP Request object
 * @param {import('http').ServerResponse} res - HTTP Response object
 * @returns {Promise<void>}
 */
export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();
    setSecurityHeaders(res);

    if (!isJsonContentType(req)) {
        return res.status(415).json({ error: 'Content-Type must be application/json' });
    }
    if (!isValidBody(req.body)) {
        return res.status(400).json({ error: 'Invalid request data' });
    }

    const ip = getClientIp(req);
    try {
        if (await checkRateLimit(`ip:${ip}:stepup`, 30, 60_000)) {
            auditLog('STEPUP_IP_RATE_LIMIT', { ip });
            return res.status(429).json({ error: 'Too many requests. Please try again later.' });
        }
    } catch (rlErr) {
        console.error('[WARN] stepup.js rate-limit DB error, failing open:', rlErr.message);
    }

    let bearer;
    try {
        bearer = await requireBearerUser(req);
    } catch (err) {
        console.error('[WARN] stepup.js bearer lookup failed:', err.message);
        bearer = null;
    }
    if (!bearer?.username) {
        res.setHeader('WWW-Authenticate', 'Bearer realm="oauth", error="invalid_token"');
        return res.status(401).json({ error: 'Unauthorized' });
    }
    const { username, tokenHash, sessionJti } = bearer;

    await ensureStepupChallengesSchema();

    const action = req.body.action;
    if (action === 'send') {
        try {
            // Limit: ขอ step-up เกิน 3 ครั้งต่อ session → revoke token ทันที
            try {
                const countRes = await pool.query(
                    `SELECT COUNT(*)::int AS cnt
                     FROM stepup_challenges
                     WHERE username = $1 AND session_jti = $2
                       AND created_at > NOW() - INTERVAL '8 hours'`,
                    [username, sessionJti]
                );
                const cnt = Number(countRes.rows[0]?.cnt || 0);
                if (cnt >= STEPUP_MAX_SENDS_PER_SESSION) {
                    await pool.query(
                        `UPDATE oauth_tokens SET revoked_at = NOW()
                         WHERE token_hash = $1 AND token_type = 'access' AND revoked_at IS NULL`,
                        [tokenHash]
                    );
                    auditLog('STEPUP_REVOKE_SEND_LIMIT', { username, ip, sessionJti, cnt });
                    return res.status(403).json({ action: 'revoke', error: 'stepup_send_limit' });
                }
            } catch (limitErr) {
                console.error('[WARN] stepup.js send limit check failed:', limitErr.message);
            }

            const u = await pool.query('SELECT email FROM users WHERE username = $1', [username]);
            const email = u.rows[0]?.email;
            if (!email) return res.status(500).json({ error: 'User email not found' });

            const stepupId = crypto.randomUUID();
            const code = crypto.randomInt(100000, 1000000).toString();
            const codeHash = hashStepupCode(stepupId, code);

            await pool.query(
                `INSERT INTO stepup_challenges (id, username, session_jti, code_hash, expires_at)
                 VALUES ($1, $2, $3, $4, NOW() + INTERVAL '5 minutes')`,
                [stepupId, username, sessionJti, codeHash]
            );

            try {
                await mailTransporter.sendMail({
                    from:    `"B-SSO" <${process.env.EMAIL_USER}>`,
                    to:      email,
                    subject: ' Step-up verification code (B-SSO)',
                    html:    `<p>Your verification code is:</p>
                              <h2 style="letter-spacing:2px">${code}</h2>
                              <p>This code expires in 5 minutes.</p>`,
                });
            } catch (mailErr) {
                console.error('[ERROR] stepup.js sendMail:', mailErr.message);
            }

            auditLog('STEPUP_SENT', { username, ip, stepupId });
            return res.status(200).json({ stepup_id: stepupId, expires_in: STEPUP_TTL_MINUTES * 60 });
        } catch (err) {
            console.error('[ERROR] stepup.js send:', err);
            return res.status(500).json({ error: 'Internal server error' });
        }
    }

    if (action === 'verify') {
        const { stepup_id, code } = req.body;
        if (typeof stepup_id !== 'string') return res.status(400).json({ error: 'Invalid stepup_id' });
        if (typeof code !== 'string' || !OTP_REGEX.test(code)) return res.status(400).json({ error: 'Invalid code' });

        try {
            const id = stepup_id;
            const client = await pool.connect();
            try {
                await client.query('BEGIN');
                const rowRes = await client.query(
                    `SELECT id, code_hash, expires_at, attempts, verified_at
                     FROM stepup_challenges
                     WHERE id = $1 AND username = $2
                     FOR UPDATE`,
                    [id, username]
                );
                const row = rowRes.rows[0];
                if (!row) {
                    await client.query('ROLLBACK');
                    auditLog('STEPUP_INVALID_CHALLENGE', { username, ip, stepupId: id });
                    return res.status(400).json({ error: 'Invalid challenge' });
                }
                if (row.verified_at) {
                    await client.query('ROLLBACK');
                    return res.status(200).json({ success: true });
                }
                if (new Date() > new Date(row.expires_at)) {
                    await client.query('ROLLBACK');
                    auditLog('STEPUP_EXPIRED', { username, ip, stepupId: id });
                    return res.status(400).json({ error: 'Code expired' });
                }
                const attempts = Number(row.attempts || 0);
                if (attempts >= STEPUP_MAX_ATTEMPTS) {
                    await client.query('ROLLBACK');
                    auditLog('STEPUP_MAX_ATTEMPTS_EXCEEDED', {
                        username, ip, stepupId: id, attempts: newAttempts
                    });
                    return res.status(429).json({ error: 'Too many attempts' });
                }

                const newAttempts = attempts + 1;
                await client.query(
                    'UPDATE stepup_challenges SET attempts = $2 WHERE id = $1',
                    [id, newAttempts]
                );

                const inputHash = hashStepupCode(id, code);
                const ok = (row.code_hash && row.code_hash.length === inputHash.length)
                    ? crypto.timingSafeEqual(Buffer.from(row.code_hash, 'hex'), Buffer.from(inputHash, 'hex'))
                    : false;

                if (!ok) {
                    await client.query('COMMIT');
                    auditLog('STEPUP_WRONG_CODE', { username, ip, stepupId: id });
                    return res.status(401).json({ error: 'Wrong code' });
                }

                await client.query('UPDATE stepup_challenges SET verified_at = NOW() WHERE id = $1', [id]);
                await client.query('COMMIT');
            } catch (err) {
                try { await client.query('ROLLBACK'); } catch { /* ignore */ }
                throw err;
            } finally {
                client.release();
            }

            auditLog('STEPUP_VERIFIED', { username, ip, stepupId: stepup_id });
            return res.status(200).json({ success: true });
        } catch (err) {
            console.error('[ERROR] stepup.js verify:', err);
            return res.status(500).json({ error: 'Internal server error' });
        }
    }

    return res.status(400).json({ error: 'Invalid action' });
}

