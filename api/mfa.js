// ============================================================
// 🔐 api/mfa.js — Combined MFA Handler
//
// รวม 3 MFA endpoints ไว้ในไฟล์เดียวเพื่อลด Vercel function count:
//   - /api/mfa         → action: 'verify'
//   - /api/verify-mfa  → action: 'verify'
//   - /api/resend-mfa  → action: 'resend'
//
// ใช้ร่วมกับ vercel.json rewrites:
//   { "source": "/api/mfa",        "destination": "/api/mfa.js" }
//   { "source": "/api/verify-mfa", "destination": "/api/mfa.js?action=verify" }
//   { "source": "/api/resend-mfa", "destination": "/api/mfa.js?action=resend" }
// ============================================================
import '../startup-check.js';
import { pool }                from '../lib/db.js';
import { validateCsrfToken }   from '../lib/csrf-utils.js';
import { checkRateLimit }      from '../lib/rate-limit.js';
import { getClientIp }         from '../lib/ip-utils.js';
import {
    LOGID_TTL_MINUTES,
    MFA_MAX_ATTEMPTS,
    TOTAL_MFA_MAX,
    RESEND_COOLDOWN_SEC,
    SESSION_DURATION_SECONDS,
} from '../lib/constants.js';
import { hashMfaCode }         from '../lib/mfa-utils.js';
import { validateRedirectBack } from '../lib/redirect-utils.js';
import { mailTransporter }     from '../lib/mailer.js';
import { ensureLoginRisksSchema } from '../lib/risk-score.js';
import {
    setSecurityHeaders, auditLog,
    USER_REGEX, LOGID_STRING_REGEX,
    isJsonContentType, isValidBody,
} from '../lib/response-utils.js';
import jwt         from 'jsonwebtoken';
import { serialize } from 'cookie';
import crypto      from 'crypto';

const OTP_REGEX = /^\d{6}$/;

function timingSafeHashEqual(storedHash, inputHash) {
    if (!storedHash || !inputHash) return false;
    if (storedHash.length !== inputHash.length) return false;
    try {
        const storedBuf = Buffer.from(storedHash, 'hex');
        const inputBuf  = Buffer.from(inputHash,  'hex');
        if (storedBuf.length !== inputBuf.length) return false;
        return crypto.timingSafeEqual(storedBuf, inputBuf);
    } catch {
        return false;
    }
}

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
    const action = req.body?.action ?? req.query?.action;

    if (action === 'verify') {
        return handleVerifyMfa(req, res, ip);
    }

    if (action === 'resend') {
        return handleResendMfa(req, res, ip);
    }

    return res.status(400).json({ error: 'Invalid action. Use action: "verify" or "resend"' });
}

async function handleVerifyMfa(req, res, ip) {
    await ensureLoginRisksSchema();
    try {
        if (await checkRateLimit(`ip:${ip}:verify-mfa`, 30, 60_000)) {
            auditLog('VERIFY_MFA_IP_RATE_LIMIT', { ip });
            return res.status(429).json({ error: 'Too many requests. Please try again later.' });
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit DB error (verify-mfa), failing open:', rlErr.message);
    }

    if (!isValidBody(req.body)) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    const { logId, code, remember, username, redirect_back } = req.body;

    if (typeof username !== 'string' || !username || username.length > 32) {
        return res.status(400).json({ error: 'Invalid request data' });
    }
    if (!USER_REGEX.test(username)) {
        return res.status(400).json({ error: 'Invalid request data' });
    }

    if (logId == null || (typeof logId !== 'string' && typeof logId !== 'number')) {
        return res.status(400).json({ error: 'Invalid session. Please sign in again.' });
    }
    if (typeof logId === 'string' && !LOGID_STRING_REGEX.test(logId)) {
        return res.status(400).json({ error: 'Invalid session. Please sign in again.' });
    }
    const parsedLogId = Number(logId);
    if (!Number.isInteger(parsedLogId) || parsedLogId <= 0 || parsedLogId > Number.MAX_SAFE_INTEGER) {
        return res.status(400).json({ error: 'Invalid session. Please sign in again.' });
    }

    if (typeof code !== 'string' || !OTP_REGEX.test(code)) {
        return res.status(400).json({ error: 'Invalid OTP format' });
    }

    try {
        const client = await pool.connect();
        try {
            await client.query('BEGIN');

            const riskRes = await client.query(
                `SELECT lr.mfa_code, lr.mfa_expires_at, lr.mfa_attempts,
                        lr.total_mfa_attempts, lr.risk_level,
                        u.id AS user_id, u.email
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
                return res.status(400).json({ error: 'Session expired. Please sign in again.' });
            }

            const row = riskRes.rows[0];
            const currentAttempts = Number(row.mfa_attempts || 0);
            const currentTotal    = Number(row.total_mfa_attempts || 0);

            if (currentAttempts >= MFA_MAX_ATTEMPTS || currentTotal >= TOTAL_MFA_MAX) {
                await client.query('ROLLBACK');
                auditLog('MFA_ATTEMPT_LIMIT', { username, ip, currentAttempts, currentTotal });
                return res.status(429).json({ error: 'Too many failed attempts. Please sign in again.' });
            }

            if (!row.mfa_expires_at || new Date() > new Date(row.mfa_expires_at)) {
                await client.query('ROLLBACK');
                return res.status(400).json({ error: 'OTP has expired. Please request a new code.' });
            }

            const updateRes = await client.query(
                `UPDATE login_risks
                 SET mfa_attempts       = mfa_attempts + 1,
                     total_mfa_attempts = COALESCE(total_mfa_attempts, 0) + 1
                 WHERE id = $1
                   AND mfa_attempts < $2
                   AND COALESCE(total_mfa_attempts, 0) < $3
                 RETURNING mfa_attempts`,
                [parsedLogId, MFA_MAX_ATTEMPTS, TOTAL_MFA_MAX]
            );

            if (!updateRes.rows[0]) {
                await client.query('ROLLBACK');
                return res.status(429).json({ error: 'Too many failed attempts. Please sign in again.' });
            }

            const inputHash = hashMfaCode(code, parsedLogId);
            if (!timingSafeHashEqual(row.mfa_code, inputHash)) {
                await client.query('COMMIT');
                auditLog('MFA_WRONG_CODE', { username, ip });
                return res.status(401).json({ error: 'Invalid OTP format' });
            }

            await client.query(
                'UPDATE login_risks SET is_success = TRUE WHERE id = $1',
                [parsedLogId]
            );

            if ((remember === true || remember === 'true') && req.body.fingerprint) {
                await client.query(
                    'INSERT INTO user_devices (username, fingerprint) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                    [username, req.body.fingerprint]
                );
            }

            const jti = crypto.randomUUID();
            let token;
            try {
                token = jwt.sign(
                    { username, jti, iss: 'auth-service', aud: 'api' },
                    process.env.JWT_SECRET,
                    { expiresIn: '8h' }
                );
            } catch (jwtErr) {
                await client.query('ROLLBACK');
                console.error('[ERROR] mfa.js verify JWT sign failed:', jwtErr.message);
                return res.status(500).json({ error: 'Internal server error' });
            }

            // ผูก login attempt record กับ session เพื่อให้ behavior.js ดึง pre_login_score มารวมคะแนนได้
            try {
                await client.query(
                    `UPDATE login_risks
                     SET session_jti = $1
                     WHERE id = $2 AND username = $3`,
                    [jti, parsedLogId, username]
                );
            } catch (linkErr) {
                console.error('[WARN] mfa.js link session_jti failed:', linkErr.message);
            }

            await client.query('COMMIT');

            let redirectUrl = null;
            if (redirect_back && row.user_id) {
                const isValidRedirect = await validateRedirectBack(redirect_back);
                if (isValidRedirect) {
                    const sso_token = crypto.randomUUID();
                    try {
                        await pool.query(
                            'INSERT INTO sso_tokens (token, user_id) VALUES ($1, $2)',
                            [sso_token, row.user_id]
                        );
                        redirectUrl = `${redirect_back}?sso_token=${sso_token}`;
                    } catch (ssoErr) {
                        console.error('[WARN] mfa.js verify SSO token insert failed:', ssoErr.message);
                    }
                } else {
                    console.error('[WARN] mfa.js verify: redirect_back not registered:', redirect_back);
                }
            }

            res.setHeader('Set-Cookie', serialize('session_token', token, {
                httpOnly: true,
                secure:   process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge:   SESSION_DURATION_SECONDS,
                path:     '/'
            }));

            auditLog('MFA_VERIFY_SUCCESS', { username, ip });
            return res.status(200).json({ success: true, redirectUrl });

        } catch (err) {
            try { await client.query('ROLLBACK'); } catch { /* ignore */ }
            throw err;
        } finally {
            client.release();
        }

    } catch (err) {
        console.error('[ERROR] mfa.js verify:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
}

async function handleResendMfa(req, res, ip) {
    try {
        if (await checkRateLimit(`ip:${ip}:resend-mfa`, 20, 60_000)) {
            auditLog('RESEND_MFA_IP_RATE_LIMIT', { ip });
            return res.status(429).json({ error: 'Too many requests. Please try again later.' });
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit DB error (resend-mfa), failing open:', rlErr.message);
    }

    if (!isValidBody(req.body)) {
        return res.status(400).json({ error: 'Invalid request data' });
    }

    const { logId, username } = req.body;

    if (typeof username !== 'string' || !username || username.length > 32) {
        return res.status(400).json({ error: 'Invalid request data' });
    }
    if (!USER_REGEX.test(username)) {
        return res.status(400).json({ error: 'Invalid request data' });
    }

    if (logId == null || (typeof logId !== 'string' && typeof logId !== 'number')) {
        return res.status(400).json({ error: 'Invalid session. Please sign in again.' });
    }
    if (typeof logId === 'string' && !LOGID_STRING_REGEX.test(logId)) {
        return res.status(400).json({ error: 'Invalid session. Please sign in again.' });
    }
    const parsedLogId = Number(logId);
    if (!Number.isInteger(parsedLogId) || parsedLogId <= 0 || parsedLogId > Number.MAX_SAFE_INTEGER) {
        return res.status(400).json({ error: 'Invalid session. Please sign in again.' });
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
                return res.status(400).json({ error: 'Session expired. Please sign in again.' });
            }

            const { total_mfa_attempts, mfa_resent_at, email } = riskRes.rows[0];
            const currentTotal = Number(total_mfa_attempts || 0);

            if (currentTotal + 1 >= TOTAL_MFA_MAX) {
                await client.query('ROLLBACK');
                auditLog('MFA_TOTAL_LIMIT_RESEND', { username, ip, total: currentTotal });
                return res.status(429).json({ error: 'Too many failed attempts. Please sign in again.' });
            }

            if (mfa_resent_at) {
                const secondsSinceLast = (Date.now() - new Date(mfa_resent_at).getTime()) / 1000;
                if (secondsSinceLast < RESEND_COOLDOWN_SEC) {
                    await client.query('ROLLBACK');
                    const remaining = Math.ceil(RESEND_COOLDOWN_SEC - secondsSinceLast);
                    return res.status(429).json({
                        error:     `Please wait ${remaining} second${remaining !== 1 ? 's' : ''} before requesting a new code.`,
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

            let emailSent = false;
            try {
                await mailTransporter.sendMail({
                    from:    `"Security System" <${process.env.EMAIL_USER}>`,
                    to:      email,
                    subject: '🔒 Your new verification code (MFA)',
                    html:    `<h2>Your new code is: <b style="color:blue;">${mfaCode}</b></h2><p>This code expires in 5 minutes.</p>`
                });
                emailSent = true;
            } catch (mailErr) {
                console.error('[ERROR] mfa.js resend sendMail:', mailErr.message);
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
                    console.error('[ERROR] mfa.js resend total_mfa_attempts increment failed:', dbErr.message);
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
        console.error('[ERROR] mfa.js resend:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
}
