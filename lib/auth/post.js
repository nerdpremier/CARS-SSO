import { pool } from '../db.js';
import { validateCsrfToken } from '../csrf-utils.js';
import { checkRateLimit } from '../rate-limit.js';
import { getClientIp } from '../ip-utils.js';
import { LOGID_TTL_MINUTES, TOTAL_MFA_MAX, SESSION_DURATION_SECONDS } from '../constants.js';
import { hashMfaCode } from '../mfa-utils.js';
import { mailTransporter } from '../mailer.js';
import { validateRedirectBack } from '../redirect-utils.js';
import {
    auditLog,
    USER_REGEX, SAFE_STRING_REGEX, LOGID_STRING_REGEX,
    PASS_REGEX, EMAIL_REGEX,
    isJsonContentType, isValidBody,
} from '../response-utils.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { serialize } from 'cookie';
import crypto from 'crypto';

// DUMMY_HASH: ป้องกัน timing attack เมื่อ username ไม่มีในระบบ
const DUMMY_HASH = bcrypt.hashSync('dummy_timing_prevention_fixed_v2', 12);

export async function handleAuthPost(req, res) {
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
                if (insertErr.code === '23505') {
                    auditLog('REGISTER_DUPLICATE_RACE', { username, ip });
                    return res.status(400).json({ error: 'Username or email is already registered' });
                }
                throw insertErr;
            }

            auditLog('REGISTER_SUCCESS', { username, ip });

            const rawVerifyToken  = crypto.randomBytes(32).toString('hex');
            const verifyTokenHash = crypto.createHash('sha256').update(rawVerifyToken).digest('hex');

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
                console.error('[WARN] auth post email_verifications insert failed:', verifyErr.message);
            }

            if (verifyInserted) {
                const baseUrl     = process.env.BASE_URL;
                const verifyLink  = `${baseUrl}/api/auth?action=verify-email&token=${rawVerifyToken}`;
                const safeUsername = username.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
                try {
                    await mailTransporter.sendMail({
                        from:    `"CARS SSO" <${process.env.EMAIL_USER}>`,
                        to:      emailNormalized,
                        subject: '✅ Verify your email — CARS SSO',
                        html:    `<h2>Welcome, ${safeUsername}!</h2>
                                  <p>Click the link below to verify your email address:</p>
                                  <p><a href="${verifyLink}">${verifyLink}</a></p>
                                  <p>This link expires in 24 hours.</p>
                                  <p>If you did not create an account, you can safely ignore this email.</p>`
                    });
                    auditLog('REGISTER_VERIFY_EMAIL_SENT', { username, ip });
                } catch (mailErr) {
                    console.error('[WARN] auth post verification email send failed:', mailErr.message);
                    auditLog('REGISTER_VERIFY_EMAIL_FAIL', { username, ip });
                }
            }

            return res.status(200).json({
                success:            true,
                email_verification: true,
            });
        }

        // ═══════════════════════════════════════════════════════
        // 🔑 LOGIN
        // ═══════════════════════════════════════════════════════
        if (action === 'login') {
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

            if (redirect_back !== undefined) {
                if (typeof redirect_back !== 'string' || redirect_back.length > 512) {
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

                if (dbRiskLevel === 'MEDIUM') {
                    const currentTotal = Number(total_mfa_attempts || 0);
                    if (currentTotal + 1 >= TOTAL_MFA_MAX) {
                        await loginClient.query('ROLLBACK');
                        auditLog('MFA_TOTAL_LIMIT_FIRST_SEND', { username, ip, total: currentTotal });
                        return res.status(429).json({ error: 'Too many failed attempts. Please sign in again.' });
                    }

                    const mfaCode = crypto.randomInt(100000, 1000000).toString();
                    const mfaHash = hashMfaCode(mfaCode, parsedLogId);

                    await loginClient.query(
                        `UPDATE login_risks
                         SET mfa_code             = $1,
                             mfa_expires_at       = NOW() + INTERVAL '5 minutes',
                             mfa_resent_at        = NOW(),
                             mfa_attempts         = 0,
                             total_mfa_attempts   = COALESCE(total_mfa_attempts, 0) + 1
                         WHERE id = $2`,
                        [mfaHash, parsedLogId]
                    );

                    await loginClient.query('COMMIT');

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
                        console.error('[ERROR] auth post sendMail (MFA):', mailErr.message);
                        auditLog('MFA_EMAIL_FAIL', { username, ip });
                    }

                    return res.status(200).json({
                        mfa_required:  true,
                        email_pending: !emailSent
                    });
                }

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

                const jti = crypto.randomUUID();
                let token;
                try {
                    token = jwt.sign(
                        { username, jti },
                        process.env.JWT_SECRET,
                        { expiresIn: SESSION_DURATION_SECONDS, issuer: 'auth-service', audience: 'api' }
                    );
                } catch (jwtErr) {
                    await loginClient.query('ROLLBACK');
                    console.error('[ERROR] auth post JWT sign failed:', jwtErr.message);
                    return res.status(500).json({ error: 'Internal server error' });
                }

                await loginClient.query('COMMIT');

                let redirectUrl = null;
                if (redirect_back && user?.id) {
                    let isHttps = false;
                    try { isHttps = new URL(redirect_back).protocol === 'https:'; } catch { /* invalid URL */ }
                    if (isHttps) {
                        const isValidRedirect = await validateRedirectBack(redirect_back);
                        if (isValidRedirect) {
                            const sso_token      = crypto.randomUUID();
                            const sso_token_hash = crypto.createHash('sha256').update(sso_token).digest('hex');
                            try {
                                await pool.query(
                                    'INSERT INTO sso_tokens (token, user_id) VALUES ($1, $2)',
                                    [sso_token_hash, user.id]
                                );
                                const ssoUrl = new URL(redirect_back);
                                ssoUrl.searchParams.set('sso_token', sso_token);
                                redirectUrl = ssoUrl.toString();
                            } catch (ssoErr) {
                                console.error('[WARN] auth post SSO token insert failed:', ssoErr.message);
                            }
                        } else {
                            console.error('[WARN] auth post: redirect_back not registered:', redirect_back);
                        }
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
        console.error('[ERROR] auth post:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
}

