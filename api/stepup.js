import '../startup-check.js';
import crypto from 'crypto';
import { pool } from '../lib/db.js';
import { checkRateLimit } from '../lib/rate-limit.js';
import { getClientIp } from '../lib/ip-utils.js';
import { validateCsrfToken } from '../lib/csrf-utils.js';
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
const STEPUP_MAX_RESENDS_PER_SESSION = 3;
const STEPUP_TOKEN_TTL_MINUTES = 5;

function hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
}

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

async function ensureStepupTokensSchema() {
    try {
        await pool.query(
            `CREATE TABLE IF NOT EXISTS stepup_tokens (
                token_hash TEXT PRIMARY KEY,
                challenge_id UUID NOT NULL,
                username TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                used_at TIMESTAMPTZ,
                FOREIGN KEY (challenge_id) REFERENCES stepup_challenges(id) ON DELETE CASCADE
            )`
        );
    } catch { }
    try {
        await pool.query(
            `CREATE INDEX IF NOT EXISTS stepup_tokens_username_idx ON stepup_tokens (username, created_at DESC)`
        );
    } catch { }
    try {
        await pool.query(
            `CREATE INDEX IF NOT EXISTS stepup_tokens_challenge_id_idx ON stepup_tokens (challenge_id)`
        );
    } catch { }
}

async function ensureStepupChallengesHasReturnUrl() {
    try {
        await pool.query(
            `ALTER TABLE stepup_challenges ADD COLUMN IF NOT EXISTS return_url TEXT`
        );
    } catch { }
}

export default async function handler(req, res) {
    setSecurityHeaders(res);

    const ip = getClientIp(req);

    if (req.method === 'GET') {
        const action = req.query?.action;
        if (action === 'validate-token') return handleValidateToken(req, res, ip);
        return res.status(400).json({ error: 'Invalid action' });
    }

    if (req.method !== 'POST') return res.status(405).send();

    if (!isJsonContentType(req)) {
        return res.status(415).json({ error: 'Content-Type must be application/json' });
    }
    if (!isValidBody(req.body)) {
        return res.status(400).json({ error: 'Invalid request data' });
    }

    const action = req.body.action;

    if (action === 'send')           return handleSend(req, res, ip);
    if (action === 'verify')         return handleVerify(req, res, ip);
    if (action === 'validate-token') return handleValidateToken(req, res, ip);

    if (action === 'redirect-verify') return handleRedirectVerify(req, res, ip);
    if (action === 'redirect-resend') return handleRedirectResend(req, res, ip);

    return res.status(400).json({ error: 'Invalid action' });
}

async function handleSend(req, res, ip) {
    try {
        if (await checkRateLimit(`ip:${ip}:stepup`, 30, 60_000)) {
            auditLog('STEPUP_IP_RATE_LIMIT', { ip });
            return res.status(429).json({ error: 'Too many requests. Please try again later.' });
        }
    } catch (rlErr) {
        console.error('[WARN] stepup.js rate-limit DB error, failing open:', rlErr.message);
    }

    let bearer;
    try { bearer = await requireBearerUser(req); }
    catch (err) { console.error('[WARN] stepup.js bearer lookup failed:', err.message); bearer = null; }
    if (!bearer?.username) {
        res.setHeader('WWW-Authenticate', 'Bearer realm="oauth", error="invalid_token"');
        return res.status(401).json({ error: 'Unauthorized' });
    }
    const { username, tokenHash, sessionJti } = bearer;

    await ensureStepupChallengesSchema();

    try {
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
                from:    `"B-SSO" <${process.env.EMAIL_FROM}>`,
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

async function handleVerify(req, res, ip) {
    try {
        if (await checkRateLimit(`ip:${ip}:stepup`, 30, 60_000)) {
            auditLog('STEPUP_IP_RATE_LIMIT', { ip });
            return res.status(429).json({ error: 'Too many requests. Please try again later.' });
        }
    } catch (rlErr) {
        console.error('[WARN] stepup.js rate-limit DB error, failing open:', rlErr.message);
    }

    let bearer;
    try { bearer = await requireBearerUser(req); }
    catch (err) { console.error('[WARN] stepup.js bearer lookup failed:', err.message); bearer = null; }
    if (!bearer?.username) {
        res.setHeader('WWW-Authenticate', 'Bearer realm="oauth", error="invalid_token"');
        return res.status(401).json({ error: 'Unauthorized' });
    }
    const { username } = bearer;

    await ensureStepupChallengesSchema();

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
                auditLog('STEPUP_MAX_ATTEMPTS_EXCEEDED', { username, ip, stepupId: id, attempts });
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
            try { await client.query('ROLLBACK'); } catch {  }
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

async function handleRedirectVerify(req, res, ip) {
    try {
        if (await checkRateLimit(`ip:${ip}:stepup-redirect-verify`, 30, 60_000)) {
            auditLog('STEPUP_REDIRECT_IP_RATE_LIMIT', { ip });
            return res.status(429).json({ error: 'Too many requests. Please try again later.' });
        }
    } catch (rlErr) {
        console.error('[WARN] stepup.js redirect-verify rate-limit DB error, failing open:', rlErr.message);
    }

    if (!validateCsrfToken(req)) {
        auditLog('STEPUP_REDIRECT_VERIFY_CSRF_FAIL', { ip });
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }

    const { challenge_id, code } = req.body;
    if (typeof challenge_id !== 'string' || !challenge_id) {
        return res.status(400).json({ error: 'Invalid challenge_id' });
    }
    if (typeof code !== 'string' || !OTP_REGEX.test(code)) {
        return res.status(400).json({ error: 'Invalid code' });
    }

    try {
        await ensureStepupChallengesSchema();
        await ensureStepupTokensSchema();
        await ensureStepupChallengesHasReturnUrl();

        const client = await pool.connect();
        try {
            await client.query('BEGIN');

            const challengeRes = await client.query(
                `SELECT id, username, code_hash, expires_at, attempts, verified_at, return_url
                 FROM stepup_challenges
                 WHERE id = $1
                 FOR UPDATE`,
                [challenge_id]
            );

            const challenge = challengeRes.rows[0];
            if (!challenge) {
                await client.query('ROLLBACK');
                auditLog('STEPUP_REDIRECT_INVALID_CHALLENGE', { ip, challengeId: challenge_id });
                return res.status(400).json({ error: 'Invalid challenge' });
            }

            if (challenge.verified_at) {
                await client.query('ROLLBACK');
                auditLog('STEPUP_REDIRECT_ALREADY_VERIFIED', { ip, challengeId: challenge_id, username: challenge.username });
                return res.status(400).json({ error: 'Challenge already verified' });
            }

            if (new Date() > new Date(challenge.expires_at)) {
                await client.query('ROLLBACK');
                auditLog('STEPUP_REDIRECT_EXPIRED', { ip, challengeId: challenge_id, username: challenge.username });
                return res.status(400).json({ error: 'Code expired' });
            }

            const attempts = Number(challenge.attempts || 0);
            if (attempts >= STEPUP_MAX_ATTEMPTS) {
                await client.query('ROLLBACK');
                auditLog('STEPUP_REDIRECT_MAX_ATTEMPTS', { ip, challengeId: challenge_id, username: challenge.username, attempts });
                return res.status(429).json({ error: 'Too many attempts' });
            }

            const newAttempts = attempts + 1;
            await client.query(
                'UPDATE stepup_challenges SET attempts = $2 WHERE id = $1',
                [challenge_id, newAttempts]
            );

            const inputHash = hashStepupCode(challenge_id, code);
            const ok = (challenge.code_hash && challenge.code_hash.length === inputHash.length)
                ? crypto.timingSafeEqual(Buffer.from(challenge.code_hash, 'hex'), Buffer.from(inputHash, 'hex'))
                : false;

            if (!ok) {
                await client.query('COMMIT');
                auditLog('STEPUP_REDIRECT_WRONG_CODE', { ip, challengeId: challenge_id, username: challenge.username });
                return res.status(401).json({ error: 'Wrong code' });
            }

            await client.query('UPDATE stepup_challenges SET verified_at = NOW() WHERE id = $1', [challenge_id]);

            const stepupToken = crypto.randomUUID();
            const tokenHash = hashToken(stepupToken);

            await client.query(
                `INSERT INTO stepup_tokens (token_hash, challenge_id, username, created_at)
                 VALUES ($1, $2, $3, NOW())`,
                [tokenHash, challenge_id, challenge.username]
            );

            await client.query('COMMIT');

            auditLog('STEPUP_REDIRECT_VERIFIED', { ip, challengeId: challenge_id, username: challenge.username });
            return res.status(200).json({
                success: true,
                stepup_token: stepupToken,
                return_url: challenge.return_url || null,
            });

        } catch (err) {
            try { await client.query('ROLLBACK'); } catch { }
            throw err;
        } finally {
            client.release();
        }

    } catch (err) {
        console.error('[ERROR] stepup.js redirect-verify:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
}

async function handleRedirectResend(req, res, ip) {
    try {
        if (await checkRateLimit(`ip:${ip}:stepup-redirect-resend`, 20, 60_000)) {
            auditLog('STEPUP_REDIRECT_IP_RATE_LIMIT_RESEND', { ip });
            return res.status(429).json({ error: 'Too many requests. Please try again later.' });
        }
    } catch (rlErr) {
        console.error('[WARN] stepup.js redirect-resend rate-limit DB error, failing open:', rlErr.message);
    }

    if (!validateCsrfToken(req)) {
        auditLog('STEPUP_REDIRECT_RESEND_CSRF_FAIL', { ip });
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }

    const { challenge_id } = req.body;
    if (typeof challenge_id !== 'string' || !challenge_id) {
        return res.status(400).json({ error: 'Invalid challenge_id' });
    }

    try {
        await ensureStepupChallengesSchema();
        await ensureStepupTokensSchema();
        await ensureStepupChallengesHasReturnUrl();

        const client = await pool.connect();
        try {
            await client.query('BEGIN');

            const challengeRes = await client.query(
                `SELECT id, username, return_url
                 FROM stepup_challenges
                 WHERE id = $1
                 FOR UPDATE`,
                [challenge_id]
            );

            const challenge = challengeRes.rows[0];
            if (!challenge) {
                await client.query('ROLLBACK');
                auditLog('STEPUP_REDIRECT_RESEND_INVALID_CHALLENGE', { ip, challengeId: challenge_id });
                return res.status(400).json({ error: 'Invalid challenge' });
            }

            const { username } = challenge;

            try {
                const countRes = await client.query(
                    `SELECT COUNT(*)::int AS cnt
                     FROM stepup_challenges
                     WHERE username = $1 AND created_at > NOW() - INTERVAL '8 hours'`,
                    [username]
                );
                const cnt = Number(countRes.rows[0]?.cnt || 0);
                if (cnt >= STEPUP_MAX_RESENDS_PER_SESSION) {
                    await client.query('ROLLBACK');
                    auditLog('STEPUP_REDIRECT_RESEND_LIMIT', { ip, username, cnt });
                    return res.status(429).json({ error: 'Too many resend attempts. Please try again later.' });
                }
            } catch (limitErr) {
                console.error('[WARN] stepup.js redirect-resend limit check failed:', limitErr.message);
            }

            const userRes = await client.query('SELECT email FROM users WHERE username = $1', [username]);
            const email = userRes.rows[0]?.email;
            if (!email) {
                await client.query('ROLLBACK');
                console.error('[WARN] stepup.js redirect-resend: email not found for', username);
                return res.status(500).json({ error: 'User email not found' });
            }

            const newChallengeId = crypto.randomUUID();
            const newCode = crypto.randomInt(100000, 1000000).toString();
            const newCodeHash = hashStepupCode(newChallengeId, newCode);

            await client.query(
                `INSERT INTO stepup_challenges (id, username, code_hash, expires_at, return_url)
                 VALUES ($1, $2, $3, NOW() + INTERVAL '5 minutes', $4)`,
                [newChallengeId, username, newCodeHash, challenge.return_url || null]
            );

            await client.query('COMMIT');

            let emailSent = false;
            try {
                await mailTransporter.sendMail({
                    from:    `"B-SSO" <${process.env.EMAIL_FROM}>`,
                    to:      email,
                    subject: 'New step-up verification code (B-SSO)',
                    html:    `<p>Your new verification code is:</p>
                              <h2 style="letter-spacing:2px">${newCode}</h2>
                              <p>This code expires in 5 minutes.</p>`,
                });
                emailSent = true;
            } catch (mailErr) {
                console.error('[ERROR] stepup.js redirect-resend sendMail:', mailErr.message);
            }

            auditLog('STEPUP_REDIRECT_RESEND_SUCCESS', { ip, username, oldChallengeId: challenge_id, newChallengeId, emailSent });
            return res.status(200).json({
                success: true,
                new_challenge_id: newChallengeId,
                expires_in: STEPUP_TTL_MINUTES * 60,
            });

        } catch (err) {
            try { await client.query('ROLLBACK'); } catch { }
            throw err;
        } finally {
            client.release();
        }

    } catch (err) {
        console.error('[ERROR] stepup.js redirect-resend:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
}

async function handleValidateToken(req, res, ip) {
    try {
        if (await checkRateLimit(`ip:${ip}:stepup-validate-token`, 50, 60_000)) {
            auditLog('STEPUP_REDIRECT_IP_RATE_LIMIT_VALIDATE', { ip });
            return res.status(429).json({ error: 'Too many requests. Please try again later.' });
        }
    } catch (rlErr) {
        console.error('[WARN] stepup.js validate-token rate-limit DB error, failing open:', rlErr.message);
    }

    let bearer;
    try { bearer = await requireBearerUser(req); }
    catch (err) { console.error('[WARN] stepup.js validate-token bearer lookup failed:', err.message); bearer = null; }
    if (!bearer?.username) {
        res.setHeader('WWW-Authenticate', 'Bearer realm="oauth", error="invalid_token"');
        auditLog('STEPUP_REDIRECT_VALIDATE_NO_AUTH', { ip });
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const stepupToken = req.body?.stepup_token ?? req.query?.stepup_token;
    if (typeof stepupToken !== 'string' || !stepupToken) {
        return res.status(400).json({ error: 'Invalid stepup_token' });
    }

    try {
        await ensureStepupChallengesSchema();
        await ensureStepupTokensSchema();

        const tokenHash = hashToken(stepupToken);
        const tokenRes = await pool.query(
            `SELECT token_hash, challenge_id, username, created_at, used_at
             FROM stepup_tokens
             WHERE token_hash = $1`,
            [tokenHash]
        );

        const token = tokenRes.rows[0];
        if (!token) {
            auditLog('STEPUP_REDIRECT_VALIDATE_TOKEN_NOT_FOUND', { ip, username: bearer.username });
            return res.status(401).json({ error: 'Invalid stepup_token' });
        }

        if (token.username !== bearer.username) {
            auditLog('STEPUP_REDIRECT_VALIDATE_TOKEN_MISMATCH', { ip, username: bearer.username, tokenUsername: token.username });
            return res.status(401).json({ error: 'Invalid stepup_token' });
        }

        if (token.used_at) {
            auditLog('STEPUP_REDIRECT_VALIDATE_TOKEN_ALREADY_USED', { ip, username: bearer.username });
            return res.status(401).json({ error: 'Token already used' });
        }

        const createdAt = new Date(token.created_at);
        const expiresAt = new Date(createdAt.getTime() + STEPUP_TOKEN_TTL_MINUTES * 60 * 1000);
        if (new Date() > expiresAt) {
            auditLog('STEPUP_REDIRECT_VALIDATE_TOKEN_EXPIRED', { ip, username: bearer.username });
            return res.status(401).json({ error: 'Token expired' });
        }

        await pool.query(
            `UPDATE stepup_tokens SET used_at = NOW() WHERE token_hash = $1`,
            [tokenHash]
        );

        auditLog('STEPUP_REDIRECT_VALIDATE_TOKEN_SUCCESS', { ip, username: bearer.username });
        return res.status(200).json({ valid: true });

    } catch (err) {
        console.error('[ERROR] stepup.js validate-token:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
}
