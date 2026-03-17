// ============================================================
// 🔐 api/auth.js — Register, Login & Email Verification
// ทำหน้าที่ 3 อย่าง:
//   GET  ?action=verify-email&token=xxx — ยืนยัน email หลัง register
//   POST action=register — สร้างบัญชีใหม่ + ส่ง verification email
//   POST action=login    — ตรวจ credentials → ดู risk level
//                           LOW    → ออก JWT ทันที
//                           MEDIUM → ส่ง MFA email → รอ verify-mfa.js
//                           HIGH   → reject ทันที
//
// Security guarantees:
//   - DUMMY_HASH ป้องกัน timing attack เมื่อ username ไม่มีในระบบ
//   - FOR UPDATE บน login_risks ป้องกัน concurrent login race condition
//   - JWT sign ก่อน COMMIT: ถ้า sign fail → ROLLBACK → user retry ได้
//   - email normalized lowercase ตั้งแต่ register → forgot-password ทำงานถูกต้อง
//   - Email verification token = SHA-256(randomBytes(32)) stored in DB
//   - verify-email รวมใน auth.js เพื่อไม่เกิน Vercel 12-function limit
// ============================================================
import '../startup-check.js';
import { pool }                from '../lib/db.js';
import { validateCsrfToken }   from '../lib/csrf-utils.js';
import { checkRateLimit }      from '../lib/rate-limit.js';
import { getClientIp }         from '../lib/ip-utils.js';
import { LOGID_TTL_MINUTES, TOTAL_MFA_MAX, SESSION_DURATION_SECONDS } from '../lib/constants.js';
import { hashMfaCode }         from '../lib/mfa-utils.js';
import { mailTransporter }     from '../lib/mailer.js';
import { validateRedirectBack } from '../lib/redirect-utils.js';
import { ensureLoginRisksSchema } from '../lib/risk-score.js';
import {
    setSecurityHeaders, auditLog,
    USER_REGEX, SAFE_STRING_REGEX, LOGID_STRING_REGEX,
    PASS_REGEX, EMAIL_REGEX,
    isJsonContentType, isValidBody,
} from '../lib/response-utils.js';
import bcrypt      from 'bcryptjs';
import jwt         from 'jsonwebtoken';
import { serialize } from 'cookie';
import crypto      from 'crypto';

// DUMMY_HASH: ป้องกัน timing attack เมื่อ username ไม่มีในระบบ
// cost 12 ต้องตรงกับ production hash — ถ้าต่างกัน timing ต่างกัน = timing leak
const DUMMY_HASH = bcrypt.hashSync('dummy_timing_prevention_fixed_v2', 12);

export default async function handler(req, res) {
    setSecurityHeaders(res);

    // ── GET: ตรวจสอบ email verified status (polling จาก PC) ──
    if (req.method === 'GET') {
        const { action, username } = req.query;

        res.setHeader('Cache-Control', 'no-store');
        const ip = getClientIp(req);

        // ── verify-email: ยืนยัน email (?action=verify-email&token=xxx) ──
        if (action === 'verify-email') {
            const { token } = req.query;

            try {
                if (await checkRateLimit(`ip:${ip}:verify-email`, 10, 60_000)) {
                    auditLog('VERIFY_EMAIL_RATE_LIMIT', { ip });
                    return res.redirect('/login?error=rate_limit');
                }
            } catch (rlErr) {
                console.error('[WARN] rate-limit DB error (verify-email), failing open:', rlErr.message);
            }

            const TOKEN_REGEX = /^[0-9a-f]{64}$/;
            if (!token || typeof token !== 'string' || !TOKEN_REGEX.test(token)) {
                return res.redirect('/login?error=invalid_token');
            }

            const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
            const client    = await pool.connect();
            try {
                await client.query('BEGIN');

                const verifyRes = await client.query(
                    `SELECT ev.id, ev.user_id, ev.expires_at, u.email_verified
                     FROM email_verifications ev
                     JOIN users u ON u.id = ev.user_id
                     WHERE ev.token_hash = $1 FOR UPDATE`,
                    [tokenHash]
                );

                if (!verifyRes.rows[0]) {
                    await client.query('ROLLBACK');
                    return res.redirect('/login?error=invalid_token');
                }

                const row = verifyRes.rows[0];

                if (new Date() > new Date(row.expires_at)) {
                    await client.query('DELETE FROM email_verifications WHERE id = $1', [row.id]);
                    await client.query('COMMIT');
                    auditLog('VERIFY_EMAIL_EXPIRED', { ip });
                    return res.redirect('/login?error=token_expired');
                }

                if (row.email_verified) {
                    await client.query('DELETE FROM email_verifications WHERE id = $1', [row.id]);
                    await client.query('COMMIT');
                    return res.redirect('/login?verified=1');
                }

                await client.query('UPDATE users SET email_verified = TRUE WHERE id = $1', [row.user_id]);
                await client.query('DELETE FROM email_verifications WHERE id = $1', [row.id]);
                await client.query('COMMIT');

                auditLog('VERIFY_EMAIL_SUCCESS', { userId: row.user_id, ip });
                return res.redirect('/login?verified=1');

            } catch (err) {
                try { await client.query('ROLLBACK'); } catch { /* ignore */ }
                console.error('[ERROR] auth.js verify-email:', err);
                return res.redirect('/login?error=server_error');
            } finally {
                client.release();
            }
        }

        // ── poll-verified: PC polling ว่า user verify email แล้วหรือยัง ──
        // ใช้ username เป็น key แทน token เพราะ token ถูก delete หลัง verify แล้ว
        // endpoint นี้คืนแค่ boolean — ไม่เปิดเผยข้อมูลอื่น
        if (action === 'poll-verified') {
            if (!username || typeof username !== 'string' || username.length > 32 || !USER_REGEX.test(username)) {
                return res.status(400).json({ error: 'Invalid username' });
            }

            // rate limit: max 30 requests/นาที ต่อ IP (poll ทุก 3s × 60s = 20 requests max)
            try {
                if (await checkRateLimit(`ip:${ip}:poll-verified`, 30, 60_000)) {
                    return res.status(429).json({ error: 'Too many requests' });
                }
            } catch (rlErr) {
                console.error('[WARN] rate-limit DB error (poll-verified), failing open:', rlErr.message);
            }

            try {
                const result = await pool.query(
                    'SELECT email_verified FROM users WHERE username = $1',
                    [username]
                );
                // ถ้าไม่เจอ username → คืน verified: false (ไม่บอกว่าไม่มี user เพื่อป้องกัน enumeration)
                const verified = result.rows[0]?.email_verified === true;
                return res.status(200).json({ verified });
            } catch (err) {
                console.error('[ERROR] auth.js poll-verified:', err);
                return res.status(500).json({ error: 'Server error' });
            }
        }

        return res.status(405).send();
    }

    if (req.method !== 'POST') return res.status(405).send();

    if (!isJsonContentType(req)) {
        return res.status(415).json({ error: 'Content-Type must be application/json' });
    }

    if (!validateCsrfToken(req)) {
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }

    const ip = getClientIp(req);
    try {
        if (await checkRateLimit(`ip:${ip}:auth`, 10, 60_000)) {
            auditLog('AUTH_IP_RATE_LIMIT', { ip });
            return res.status(429).json({ error: 'Too many requests. Please try again later.' });
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit DB error (auth ip), failing open:', rlErr.message);
    }

    if (!isValidBody(req.body)) {
        return res.status(400).json({ error: 'Invalid request data' });
    }

    const { action, username, email, password, fingerprint, logId, remember, redirect_back } = req.body;
    if (!action || typeof action !== 'string' || action.length > 16) {
        return res.status(400).json({ error: 'Invalid action' });
    }

    try {
        // ═══════════════════════════════════════════════════════
        // 📝 REGISTER
        // ═══════════════════════════════════════════════════════
        if (action === 'register') {
            if (typeof username !== 'string' || typeof email !== 'string' || typeof password !== 'string') {
                return res.status(400).json({ error: 'Invalid request data' });
            }
            if (!username || !email || !password) {
                return res.status(400).json({ error: 'Please fill in all required fields' });
            }
            if (username.length > 32 || email.length > 254 || password.length > 128) {
                return res.status(400).json({ error: 'Input exceeds maximum allowed length' });
            }
            if (!USER_REGEX.test(username)) {
                return res.status(400).json({ error: 'Username may only contain letters and numbers' });
            }
            if (!EMAIL_REGEX.test(email)) {
                return res.status(400).json({ error: 'Invalid email format' });
            }
            if (!PASS_REGEX.test(password)) {
                return res.status(400).json({ error: 'Password must be at least 8 characters with uppercase, lowercase, a number, and a symbol' });
            }

            // store lowercase เสมอ → forgot-password.js match ถูก + ป้องกัน duplicate case
            const emailNormalized = email.toLowerCase();

            const userExist = await pool.query(
                'SELECT id FROM users WHERE username = $1 OR LOWER(email) = $2',
                [username, emailNormalized]
            );
            if (userExist.rows.length > 0) {
                auditLog('REGISTER_DUPLICATE', { username, ip });
                return res.status(400).json({ error: 'Username or email is already registered' });
            }

            const hashed = await bcrypt.hash(password, 12);

            try {
                await pool.query(
                    'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)',
                    [username, emailNormalized, hashed]
                );
            } catch (insertErr) {
                // 23505 = unique_violation: concurrent registrations race
                if (insertErr.code === '23505') {
                    auditLog('REGISTER_DUPLICATE_RACE', { username, ip });
                    return res.status(400).json({ error: 'Username or email is already registered' });
                }
                throw insertErr;
            }

            auditLog('REGISTER_SUCCESS', { username, ip });

            // ── Email Verification ─────────────────────────
            // rawToken = 32 bytes hex (256-bit) — ส่งใน email link
            // tokenHash = SHA-256(rawToken)      — เก็บใน DB
            // TTL = 24 ชั่วโมง
            const rawVerifyToken  = crypto.randomBytes(32).toString('hex');
            const verifyTokenHash = crypto.createHash('sha256').update(rawVerifyToken).digest('hex');

            // INSERT verification record (ถ้า fail → ไม่ block register, แค่ log)
            let verifyInserted = false;
            try {
                await pool.query(
                    `INSERT INTO email_verifications (user_id, token_hash, expires_at)
                     SELECT id, $2, NOW() + INTERVAL '24 hours'
                     FROM users WHERE username = $1`,
                    [username, verifyTokenHash]
                );
                verifyInserted = true;
            } catch (verifyErr) {
                console.error('[WARN] auth.js email_verifications insert failed:', verifyErr.message);
            }

            // ส่ง verification email — await เพื่อให้ Vercel ไม่ตัด connection ก่อน email ส่งเสร็จ
            if (verifyInserted) {
                const baseUrl     = process.env.BASE_URL;
                const verifyLink  = `${baseUrl}/api/auth?action=verify-email&token=${rawVerifyToken}`;
                try {
                    await mailTransporter.sendMail({
                        from:    `"CARS SSO" <${process.env.EMAIL_USER}>`,
                        to:      emailNormalized,
                        subject: '✅ Verify your email — CARS SSO',
                        html:    `<h2>Welcome, ${username}!</h2>
                                  <p>Click the link below to verify your email address:</p>
                                  <p><a href="${verifyLink}">${verifyLink}</a></p>
                                  <p>This link expires in 24 hours.</p>
                                  <p>If you did not create an account, you can safely ignore this email.</p>`
                    });
                    auditLog('REGISTER_VERIFY_EMAIL_SENT', { username, ip });
                } catch (mailErr) {
                    console.error('[WARN] auth.js verification email send failed:', mailErr.message);
                    auditLog('REGISTER_VERIFY_EMAIL_FAIL', { username, ip });
                }
            }

            return res.status(200).json({
                success:            true,
                email_verification: true,  // บอก frontend ให้แสดงข้อความ "กรุณาตรวจสอบอีเมล"
            });
        }

        // ═══════════════════════════════════════════════════════
        // 🔑 LOGIN
        // ═══════════════════════════════════════════════════════
        if (action === 'login') {
            await ensureLoginRisksSchema();
            if (typeof username !== 'string' || typeof password !== 'string') {
                return res.status(400).json({ error: 'Invalid request data' });
            }
            if (!username || !password) {
                return res.status(400).json({ error: 'Please fill in all required fields' });
            }
            if (username.length > 32 || password.length > 128) {
                return res.status(400).json({ error: 'Input exceeds maximum allowed length' });
            }
            if (!USER_REGEX.test(username)) {
                return res.status(400).json({ error: 'Invalid username format' });
            }

            if (fingerprint !== undefined) {
                if (typeof fingerprint !== 'string' || fingerprint.length > 256) {
                    return res.status(400).json({ error: 'Invalid request data' });
                }
                if (!SAFE_STRING_REGEX.test(fingerprint)) {
                    return res.status(400).json({ error: 'Invalid request data' });
                }
            }

            // logId validation
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
                if (await checkRateLimit(`user:${username}:auth`, 5, 60_000)) {
                    auditLog('AUTH_USERNAME_RATE_LIMIT', { username, ip });
                    return res.status(429).json({ error: 'Too many requests. Please try again later.' });
                }
            } catch (rlErr) {
                console.error('[WARN] rate-limit DB error (auth user), failing open:', rlErr.message);
            }

            // DUMMY_HASH path: ป้องกัน timing attack — user ไม่มี vs password ผิด
            const userRes = await pool.query(
                'SELECT id, username, email, password_hash, email_verified FROM users WHERE username = $1',
                [username]
            );
            const user = userRes.rows[0];

            const passwordMatch = user
                ? await bcrypt.compare(password, user.password_hash)
                : await bcrypt.compare(password, DUMMY_HASH).then(() => false);

            if (!user || !passwordMatch) {
                return res.status(401).json({ error: 'Incorrect username or password' });
            }

            // ── ตรวจ email verification ─────────────────────
            // email_verified = FALSE → login ไม่ผ่าน (ป้องกัน unverified account)
            if (!user.email_verified) {
                auditLog('LOGIN_EMAIL_UNVERIFIED', { username, ip });
                return res.status(403).json({
                    error:                 'Please verify your email before signing in',
                    email_not_verified:    true,
                });
            }

            const loginClient = await pool.connect();
            try {
                await loginClient.query('BEGIN');

                const riskRes = await loginClient.query(
                    `SELECT risk_level, total_mfa_attempts
                     FROM login_risks
                     WHERE id = $1 AND username = $2
                       AND is_success = FALSE
                       AND created_at > NOW() - make_interval(mins => $3)
                     FOR UPDATE`,
                    [parsedLogId, username, LOGID_TTL_MINUTES]
                );

                if (!riskRes.rows[0]) {
                    await loginClient.query('ROLLBACK');
                    return res.status(400).json({ error: 'Session expired. Please sign in again.' });
                }

                const { risk_level: dbRiskLevel, total_mfa_attempts } = riskRes.rows[0];

                if (dbRiskLevel === 'HIGH') {
                    await loginClient.query('ROLLBACK');
                    auditLog('LOGIN_BLOCKED_HIGH_RISK', { username, ip });
                    return res.status(403).json({ error: 'High-risk activity detected. Please try again later.' });
                }

                if (dbRiskLevel !== 'LOW' && dbRiskLevel !== 'MEDIUM') {
                    await loginClient.query('ROLLBACK');
                    auditLog('LOGIN_BLOCKED_UNEXPECTED_RISK_LEVEL', { username, ip, dbRiskLevel });
                    return res.status(403).json({ error: 'Unexpected session state. Please sign in again.' });
                }

                // ── MEDIUM path: ส่ง MFA email ─────────────────
                if (dbRiskLevel === 'MEDIUM') {
                    const currentTotal = Number(total_mfa_attempts || 0);

                    // +1 guard: สงวน 1 slot สำหรับ verify
                    if (currentTotal + 1 >= TOTAL_MFA_MAX) {
                        await loginClient.query('ROLLBACK');
                        auditLog('MFA_TOTAL_LIMIT_FIRST_SEND', { username, ip, total: currentTotal });
                        return res.status(429).json({ error: 'Too many failed attempts. Please sign in again.' });
                    }

                    const mfaCode = crypto.randomInt(100000, 1000000).toString();
                    const mfaHash = hashMfaCode(mfaCode, parsedLogId);

                    // reset mfa_attempts = 0: ป้องกัน navigate back แล้ว re-submit
                    await loginClient.query(
                        `UPDATE login_risks
                         SET mfa_code       = $1,
                             mfa_expires_at = NOW() + INTERVAL '5 minutes',
                             mfa_resent_at  = NOW(),
                             mfa_attempts   = 0
                         WHERE id = $2`,
                        [mfaHash, parsedLogId]
                    );

                    await loginClient.query('COMMIT');

                    // ส่ง email หลัง COMMIT: ถ้า fail ก่อน COMMIT → user resend ไม่มี code ใน DB
                    let emailSent = false;
                    try {
                        await mailTransporter.sendMail({
                            from:    `"Security System" <${process.env.EMAIL_USER}>`,
                            to:      user.email,
                            subject: '🔒 Your verification code (MFA)',
                            html:    `<h2>Your code is: <b style="color:blue;">${mfaCode}</b></h2><p>This code expires in 5 minutes.</p>`
                        });
                        emailSent = true;
                    } catch (mailErr) {
                        console.error('[ERROR] auth.js sendMail (MFA):', mailErr.message);
                        auditLog('MFA_EMAIL_FAIL', { username, ip });
                    }

                    // increment total เฉพาะเมื่อ email สำเร็จ — ไม่ penalize เมื่อ SMTP down
                    if (emailSent) {
                        try {
                            await pool.query(
                                `UPDATE login_risks
                                 SET total_mfa_attempts = COALESCE(total_mfa_attempts, 0) + 1
                                 WHERE id = $1`,
                                [parsedLogId]
                            );
                        } catch (dbErr) {
                            console.error('[ERROR] auth.js total_mfa_attempts increment failed:', dbErr.message);
                        }
                    }

                    return res.status(200).json({
                        mfa_required:  true,
                        email_pending: !emailSent
                    });
                }

                // ── LOW path: direct login ──────────────────────
                if ((remember === true || remember === 'true') && fingerprint) {
                    await loginClient.query(
                        'INSERT INTO user_devices (username, fingerprint) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                        [username, fingerprint]
                    );
                }

                await loginClient.query(
                    'UPDATE login_risks SET is_success = TRUE WHERE id = $1 AND username = $2',
                    [parsedLogId, username]
                );

                // JWT sign ก่อน COMMIT: ถ้า sign fail → ROLLBACK → user retry ได้
                const jti = crypto.randomUUID();
                let token;
                try {
                    token = jwt.sign(
                        { username, jti, iss: 'auth-service', aud: 'api' },
                        process.env.JWT_SECRET,
                        { expiresIn: '8h' }
                    );
                } catch (jwtErr) {
                    await loginClient.query('ROLLBACK');
                    console.error('[ERROR] auth.js JWT sign failed:', jwtErr.message);
                    return res.status(500).json({ error: 'Internal server error' });
                }

                // ผูก login attempt record กับ session เพื่อให้ behavior.js ดึง pre_login_score มารวมคะแนนได้
                try {
                    await loginClient.query(
                        `UPDATE login_risks
                         SET session_jti = $1
                         WHERE id = $2 AND username = $3`,
                        [jti, parsedLogId, username]
                    );
                } catch (linkErr) {
                    console.error('[WARN] auth.js link session_jti failed:', linkErr.message);
                }

                await loginClient.query('COMMIT');

                // [BUG-006 FIX] SSO Redirect สำหรับ LOW path
                let redirectUrl = null;
                if (redirect_back && user?.id) {
                    const isValidRedirect = await validateRedirectBack(redirect_back);
                    if (isValidRedirect) {
                        const sso_token = crypto.randomUUID();
                        try {
                            await pool.query(
                                'INSERT INTO sso_tokens (token, user_id) VALUES ($1, $2)',
                                [sso_token, user.id]
                            );
                            redirectUrl = `${redirect_back}?sso_token=${sso_token}`;
                        } catch (ssoErr) {
                            console.error('[WARN] auth.js SSO token insert failed:', ssoErr.message);
                        }
                    } else {
                        console.error('[WARN] auth.js: redirect_back not registered:', redirect_back);
                    }
                }

                res.setHeader('Set-Cookie', serialize('session_token', token, {
                    httpOnly: true,
                    secure:   process.env.NODE_ENV === 'production',
                    sameSite: 'strict',
                    maxAge:   SESSION_DURATION_SECONDS,
                    path:     '/'
                }));

                auditLog('LOGIN_SUCCESS', { username, ip });
                return res.status(200).json({ success: true, redirectUrl });

            } catch (err) {
                try { await loginClient.query('ROLLBACK'); } catch { /* ignore */ }
                throw err;
            } finally {
                loginClient.release();
            }
        }

        return res.status(400).json({ error: 'Invalid action' });

    } catch (err) {
        console.error('[ERROR] auth.js:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
}