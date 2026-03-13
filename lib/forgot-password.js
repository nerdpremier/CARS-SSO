// ============================================================
// 🔑 api/forgot-password.js — Password Reset Request
// ทุก response เกี่ยวกับ email คืน SUCCESS_RESPONSE เสมอ (ป้องกัน email enumeration)
// ============================================================
import '../startup-check.js';
import { pool }              from '../lib/db.js';
import { validateCsrfToken } from '../lib/csrf-utils.js';
import { checkRateLimit }    from '../lib/rate-limit.js';
import { getClientIp }       from '../lib/ip-utils.js';
import { mailTransporter }   from '../lib/mailer.js';
import {
    setSecurityHeaders, auditLog,
    EMAIL_REGEX,
    isJsonContentType, isValidBody,
} from '../lib/response-utils.js';
import crypto from 'crypto';

const SUCCESS_RESPONSE = Object.freeze({
    success: true,
    message: 'If this email is registered, you will receive a password reset link shortly.'
});

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
    // fail secure: คืน SUCCESS แทน error เพื่อป้องกัน timing-based email enumeration
    try {
        if (await checkRateLimit(`ip:${ip}:forgot-password`, 5, 3_600_000)) {
            auditLog('FORGOT_PASSWORD_IP_RATE_LIMIT', { ip });
            return res.status(200).json(SUCCESS_RESPONSE);
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit DB error (forgot-password ip), failing open:', rlErr.message);
    }

    if (!isValidBody(req.body)) {
        return res.status(400).json({ error: 'Invalid request data' });
    }

    const { email } = req.body;

    if (typeof email !== 'string' || !email) {
        return res.status(400).json({ error: 'Please enter your email address' });
    }
    if (email.length > 254) {
        return res.status(400).json({ error: 'Email address is too long (max 254 characters)' });
    }
    if (!EMAIL_REGEX.test(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }

    const emailLower = email.toLowerCase();

    // Per-email rate limit: ป้องกัน email flooding ต่อ address
    try {
        if (await checkRateLimit(`email:${emailLower}:forgot-password`, 3, 3_600_000)) {
            auditLog('FORGOT_PASSWORD_EMAIL_RATE_LIMIT', { ip });
            return res.status(200).json(SUCCESS_RESPONSE);
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit DB error (forgot-password email), failing open:', rlErr.message);
    }

    // Verify BASE_URL ก่อนสร้าง reset link
    const baseUrl = process.env.BASE_URL;
    if (!baseUrl?.startsWith('https://')) {
        console.error('[CONFIG] BASE_URL is not a valid HTTPS URL');
        return res.status(200).json(SUCCESS_RESPONSE);
    }

    try {
        // rawToken: 256-bit entropy — ส่งใน email link
        // tokenHash: SHA-256(rawToken) — เก็บใน DB
        // ถ้า DB รั่ว attacker ยังต้องหา rawToken จาก hash (pre-image resistant)
        const rawToken   = crypto.randomBytes(32).toString('hex');
        const tokenHash  = crypto.createHash('sha256').update(rawToken).digest('hex');

        const result = await pool.query(
            `UPDATE users
             SET reset_token   = $1,
                 reset_expires = NOW() + INTERVAL '1 hour'
             WHERE LOWER(email) = $2
             RETURNING id`,
            [tokenHash, emailLower]
        );

        if (result.rowCount === 0) {
            // email ไม่มีใน DB — คืน SUCCESS เสมอ (ป้องกัน enumeration)
            auditLog('FORGOT_PASSWORD_EMAIL_NOT_FOUND', { ip });
            return res.status(200).json(SUCCESS_RESPONSE);
        }

        const resetLink = `${baseUrl}/reset-password?token=${rawToken}`;

        try {
            await mailTransporter.sendMail({
                from:    `"CARS SSO" <${process.env.EMAIL_USER}>`,
                to:      emailLower,
                subject: '🔐 Reset your password — CARS SSO',
                html:    `<p>Click the link below to set a new password:</p>
                          <p><a href="${resetLink}">${resetLink}</a></p>
                          <p>This link expires in 1 hour. If you did not request a password reset, you can safely ignore this email.</p>`
            });
            auditLog('FORGOT_PASSWORD_EMAIL_SENT', { ip });
        } catch (mailErr) {
            console.error('[ERROR] forgot-password.js sendMail:', mailErr.message);
            auditLog('FORGOT_PASSWORD_EMAIL_FAIL', { ip });
        }

        return res.status(200).json(SUCCESS_RESPONSE);

    } catch (err) {
        console.error('[ERROR] forgot-password.js:', err);
        // คืน SUCCESS แม้ error — ป้องกัน leak ว่า email นี้มีในระบบหรือไม่
        return res.status(200).json(SUCCESS_RESPONSE);
    }
}
