// ============================================================
// 🪪 api/stepup.js — Step-up MFA for Customer Apps (Bearer)
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

const OTP_REGEX = /^\d{6}$/;
const STEPUP_TTL_MINUTES = 5;
const STEPUP_MAX_ATTEMPTS = 5;

function hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
}

function hashStepupCode(stepupId, code) {
    const pepper = process.env.MFA_PEPPER;
    return crypto
        .createHmac('sha256', pepper)
        .update(`${stepupId}:${code}`)
        .digest('hex');
}

let _schemaEnsured = false;
async function ensureStepupSchema() {
    if (_schemaEnsured) return;
    _schemaEnsured = true;
    try {
        await pool.query(
            `CREATE TABLE IF NOT EXISTS stepup_challenges (
                id UUID PRIMARY KEY,
                username TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                verified_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )`
        );
    } catch { /* ignore */ }
    try {
        await pool.query(
            `CREATE INDEX IF NOT EXISTS stepup_challenges_user_time_idx
             ON stepup_challenges (username, created_at DESC)`
        );
    } catch { /* ignore */ }
}

async function requireBearerUser(req) {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith?.('Bearer ')) return null;
    const token = authHeader.slice(7).trim();
    if (!token || token.length > 128) return null;

    const result = await pool.query(
        `SELECT ot.username, ot.expires_at, ot.revoked_at
         FROM oauth_tokens ot
         WHERE ot.token_hash = $1 AND ot.token_type = 'access'`,
        [hashToken(token)]
    );
    const row = result.rows[0];
    if (!row) return null;
    if (row.revoked_at) return null;
    if (new Date() > new Date(row.expires_at)) return null;
    return row.username;
}

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

    let username;
    try {
        username = await requireBearerUser(req);
    } catch (err) {
        console.error('[WARN] stepup.js bearer lookup failed:', err.message);
        username = null;
    }
    if (!username) {
        res.setHeader('WWW-Authenticate', 'Bearer realm="oauth", error="invalid_token"');
        return res.status(401).json({ error: 'Unauthorized' });
    }

    await ensureStepupSchema();

    const action = req.body.action;
    if (action === 'send') {
        try {
            const u = await pool.query('SELECT email FROM users WHERE username = $1', [username]);
            const email = u.rows[0]?.email;
            if (!email) return res.status(500).json({ error: 'User email not found' });

            const stepupId = crypto.randomUUID();
            const code = crypto.randomInt(100000, 1000000).toString();
            const codeHash = hashStepupCode(stepupId, code);

            await pool.query(
                `INSERT INTO stepup_challenges (id, username, code_hash, expires_at)
                 VALUES ($1, $2, $3, NOW() + INTERVAL '5 minutes')`,
                [stepupId, username, codeHash]
            );

            try {
                await mailTransporter.sendMail({
                    from:    `"CARS SSO" <${process.env.EMAIL_USER}>`,
                    to:      email,
                    subject: '🛡️ Step-up verification code (CARS)',
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
                    return res.status(400).json({ error: 'Invalid challenge' });
                }
                if (row.verified_at) {
                    await client.query('ROLLBACK');
                    return res.status(200).json({ success: true });
                }
                if (new Date() > new Date(row.expires_at)) {
                    await client.query('ROLLBACK');
                    return res.status(400).json({ error: 'Code expired' });
                }
                const attempts = Number(row.attempts || 0);
                if (attempts >= STEPUP_MAX_ATTEMPTS) {
                    await client.query('ROLLBACK');
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

