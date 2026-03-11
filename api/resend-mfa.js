// ============================================================
// 📨 api/resend-mfa.js — Resend MFA Code
// ============================================================
import '../startup-check.js';
import { pool }              from '../lib/db.js';
import { validateCsrfToken } from '../lib/csrf-utils.js';
import { checkRateLimit }    from '../lib/rate-limit.js';
import { getClientIp }       from '../lib/ip-utils.js';
import { LOGID_TTL_MINUTES, TOTAL_MFA_MAX, RESEND_COOLDOWN_SEC } from '../lib/constants.js';
import { hashMfaCode }       from '../lib/mfa-utils.js';
import { mailTransporter }   from '../lib/mailer.js';
import {
    setSecurityHeaders, auditLog,
    USER_REGEX, LOGID_STRING_REGEX,
    isJsonContentType, isValidBody,
} from '../lib/response-utils.js';
import crypto from 'crypto';

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
        if (await checkRateLimit(`ip:${ip}:resend-mfa`, 20, 60_000)) {
            auditLog('RESEND_MFA_IP_RATE_LIMIT', { ip });
            return res.status(429).json({ error: 'ส่งคำขอบ่อยเกินไป กรุณารอสักครู่' });
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit DB error (resend-mfa), failing open:', rlErr.message);
    }

    if (!isValidBody(req.body)) {
        return res.status(400).json({ error: 'ข้อมูลไม่ถูกต้อง' });
    }

    const { logId, username } = req.body;

    if (typeof username !== 'string' || !username || username.length > 32) {
        return res.status(400).json({ error: 'ข้อมูลไม่ถูกต้อง' });
    }
    if (!USER_REGEX.test(username)) {
        return res.status(400).json({ error: 'ข้อมูลไม่ถูกต้อง' });
    }

    if (logId == null || (typeof logId !== 'string' && typeof logId !== 'number')) {
        return res.status(400).json({ error: 'Session ไม่ถูกต้อง กรุณาเริ่มต้นใหม่' });
    }
    if (typeof logId === 'string' && !LOGID_STRING_REGEX.test(logId)) {
        return res.status(400).json({ error: 'Session ไม่ถูกต้อง กรุณาเริ่มต้นใหม่' });
    }
    const parsedLogId = Number(logId);
    if (!Number.isInteger(parsedLogId) || parsedLogId <= 0 || parsedLogId > Number.MAX_SAFE_INTEGER) {
        return res.status(400).json({ error: 'Session ไม่ถูกต้อง กรุณาเริ่มต้นใหม่' });
    }

    try {
        const client = await pool.connect();
        try {
            await client.query('BEGIN');

            const riskRes = await client.query(
                `SELECT lr.total_mfa_attempts, lr.mfa_resent_at, u.email
                 FROM login_risks lr
                 JOIN users u ON u.username = lr.username
                 WHERE lr.id = $1
                   AND lr.username = $2
                   AND lr.risk_level = 'MEDIUM'
                   AND lr.is_success = FALSE
                   AND lr.created_at > NOW() - make_interval(mins => $3)
                 FOR UPDATE OF lr`,
                [parsedLogId, username, LOGID_TTL_MINUTES]
            );

            if (!riskRes.rows[0]) {
                await client.query('ROLLBACK');
                return res.status(400).json({ error: 'Session หมดอายุ กรุณาเริ่มต้นใหม่' });
            }

            const { total_mfa_attempts, mfa_resent_at, email } = riskRes.rows[0];
            const currentTotal = Number(total_mfa_attempts || 0);

            // +1 guard: สงวน 1 slot สำหรับ verify
            if (currentTotal + 1 >= TOTAL_MFA_MAX) {
                await client.query('ROLLBACK');
                auditLog('MFA_TOTAL_LIMIT_RESEND', { username, ip, total: currentTotal });
                return res.status(429).json({ error: 'ยืนยันรหัสผิดเกินจำนวนที่อนุญาต กรุณาเริ่มต้นใหม่' });
            }

            // Cooldown check
            if (mfa_resent_at) {
                const secondsSinceLast = (Date.now() - new Date(mfa_resent_at).getTime()) / 1000;
                if (secondsSinceLast < RESEND_COOLDOWN_SEC) {
                    await client.query('ROLLBACK');
                    const remaining = Math.ceil(RESEND_COOLDOWN_SEC - secondsSinceLast);
                    return res.status(429).json({
                        error:     `กรุณารอ ${remaining} วินาทีก่อนขอรหัสใหม่`,
                        remaining,
                    });
                }
            }

            const mfaCode = crypto.randomInt(100000, 1000000).toString();
            const mfaHash = hashMfaCode(mfaCode, parsedLogId);

            await client.query(
                `UPDATE login_risks
                 SET mfa_code       = $1,
                     mfa_expires_at = NOW() + INTERVAL '5 minutes',
                     mfa_resent_at  = NOW(),
                     mfa_attempts   = 0
                 WHERE id = $2`,
                [mfaHash, parsedLogId]
            );

            await client.query('COMMIT');

            // ส่ง email หลัง COMMIT
            let emailSent = false;
            try {
                await mailTransporter.sendMail({
                    from:    '"Security System" <no-reply@system.com>',
                    to:      email,
                    subject: '🔒 รหัสยืนยันตัวตนใหม่ (MFA)',
                    html:    `<h2>รหัสใหม่ของคุณคือ: <b style="color:blue;">${mfaCode}</b></h2><p>รหัสนี้มีอายุ 5 นาที</p>`
                });
                emailSent = true;
            } catch (mailErr) {
                console.error('[ERROR] resend-mfa.js sendMail:', mailErr.message);
                auditLog('MFA_RESEND_EMAIL_FAIL', { username, ip });
            }

            if (emailSent) {
                try {
                    await pool.query(
                        `UPDATE login_risks
                         SET total_mfa_attempts = COALESCE(total_mfa_attempts, 0) + 1
                         WHERE id = $1`,
                        [parsedLogId]
                    );
                } catch (dbErr) {
                    console.error('[ERROR] resend-mfa.js total_mfa_attempts increment failed:', dbErr.message);
                }
            }

            auditLog('MFA_RESEND_SUCCESS', { username, ip });
            return res.status(200).json({
                success:       true,
                email_pending: !emailSent,
            });

        } catch (err) {
            try { await client.query('ROLLBACK'); } catch { /* ignore */ }
            throw err;
        } finally {
            client.release();
        }

    } catch (err) {
        console.error('[ERROR] resend-mfa.js:', err);
        return res.status(500).json({ error: 'เซิร์ฟเวอร์ขัดข้อง' });
    }
}
