import '../startup-check.js';
import { pool }             from '../lib/db.js';
import { checkRateLimit }   from '../lib/rate-limit.js';
import { getClientIp }      from '../lib/ip-utils.js';
import { validateCsrfToken } from '../lib/csrf-utils.js';
import { ensureLoginRisksSchema, getCombinedConfig } from '../lib/risk-score.js';
import { LOGID_TTL_MINUTES } from '../lib/constants.js';
import crypto from 'crypto';
import {
    setSecurityHeaders, auditLog,
    USER_REGEX, SAFE_STRING_REGEX,
    isJsonContentType, isValidBody,
} from '../lib/response-utils.js';

function hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
}

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();

    setSecurityHeaders(res);

    if (!isJsonContentType(req)) {
        return res.status(415).json({ error: 'Content-Type must be application/json' });
    }

    const authHeader = req.headers.authorization;
    let bearerUsername = null;
    if (authHeader?.startsWith?.('Bearer ')) {
        const token = authHeader.slice(7).trim();
        if (token && token.length <= 128) {
            try {
                const result = await pool.query(
                    `SELECT ot.username, ot.expires_at, ot.revoked_at
                     FROM oauth_tokens ot
                     WHERE ot.token_hash = $1 AND ot.token_type = 'access'`,
                    [hashToken(token)]
                );
                const row = result.rows[0];
                if (row && !row.revoked_at && new Date() <= new Date(row.expires_at)) {
                    bearerUsername = row.username;
                }
            } catch (err) {
                console.error('[WARN] assess.js bearer lookup failed:', err.message);
            }
        }
    }

    if (!bearerUsername) {
        if (!validateCsrfToken(req)) {
            return res.status(403).json({ error: 'Invalid CSRF token' });
        }
    }

    try {
        const ip = getClientIp(req);

        try {
            if (await checkRateLimit(`ip:${ip}:assess`, 10, 60_000)) {
                auditLog('ASSESS_IP_RATE_LIMIT', { ip });
                return res.status(429).json({
                    risk_level: 'HIGH',
                    logId: null,
                    message: 'Unusual activity detected from your IP. Please try again later.'
                });
            }
        } catch (rlErr) {
            console.error('[WARN] rate-limit DB error (assess ip), failing open:', rlErr.message);
        }

        if (!isValidBody(req.body)) {
            return res.status(400).json({ error: 'Invalid request data' });
        }

        const { username, device, fingerprint, reuse_log_id } = req.body;
        
        // เพิ่ม user agent และข้อมูล device ที่ครบขึ้น (ลบ CPU ออก)
        const userAgent = req.headers['user-agent'] || 'unknown';
        const enhancedDevice = device ? `${device.replace(/ \| CPU:\d+/, '')} | UA:${userAgent.slice(0, 100)}` : 'unknown';

        if (typeof username !== 'string' || !username || username.length > 32) {
            return res.status(400).json({ error: 'Invalid request data' });
        }
        if (!USER_REGEX.test(username)) {
            return res.status(400).json({ error: 'Invalid request data' });
        }

        if (bearerUsername && bearerUsername !== username) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        if (typeof device !== 'string' || !device || device.length > 256) {
            return res.status(400).json({ error: 'Invalid request data' });
        }
        if (!SAFE_STRING_REGEX.test(device)) {
            return res.status(400).json({ error: 'Invalid request data' });
        }
        if (typeof fingerprint !== 'string' || !fingerprint || fingerprint.length > 256) {
            return res.status(400).json({ error: 'Invalid request data' });
        }
        if (!SAFE_STRING_REGEX.test(fingerprint)) {
            return res.status(400).json({ error: 'Invalid request data' });
        }
        
        // ตรวจสอบความยาวของ enhanced device ที่มี user agent
        if (enhancedDevice.length > 400) {
            return res.status(400).json({ error: 'Device info too long' });
        }

        if (reuse_log_id !== undefined) {
            if (typeof reuse_log_id !== 'string' || reuse_log_id.length > 32) {
                return res.status(400).json({ error: 'Invalid request data' });
            }
            if (!USER_REGEX.test(reuse_log_id)) {
                return res.status(400).json({ error: 'Invalid request data' });
            }
        }

        await ensureLoginRisksSchema();

        try {
            if (await checkRateLimit(`user:${username}:assess`, 20, 60_000)) {
                auditLog('ASSESS_USERNAME_RATE_LIMIT', { username, ip });
                return res.status(429).json({
                    risk_level: 'HIGH',
                    logId: null,
                    message: 'Unusual activity detected. Please try again later.'
                });
            }
        } catch (rlErr) {
            console.error('[WARN] rate-limit DB error (assess user), failing open:', rlErr.message);
        }

        const client = await pool.connect();
        try {
            await client.query('BEGIN');

            if (reuse_log_id) {
                const parsedReuseId = Number(reuse_log_id);
                if (Number.isInteger(parsedReuseId) && parsedReuseId > 0) {
                    const existingRes = await client.query(
                        `SELECT id, risk_level, pre_login_score
                         FROM login_risks
                         WHERE id = $1 AND username = $2
                           AND created_at > NOW() - INTERVAL '1 minute' * $3
                           AND is_success = FALSE
                         FOR UPDATE`,
                        [parsedReuseId, username, LOGID_TTL_MINUTES]
                    );

                    if (existingRes.rows[0]) {
                        const existing = existingRes.rows[0];
                        auditLog('ASSESS_REUSE_LOGID', { username, ip, reusedId: existing.id });
                        return res.status(200).json({ 
                            risk_level: existing.risk_level, 
                            logId: existing.id 
                        });
                    }
                }
            }

            await client.query(
                `SELECT pg_advisory_xact_lock(('x' || substr(md5($1), 1, 16))::bit(64)::bigint)`,
                [username]
            );

            const deviceRes = await client.query(
                'SELECT id FROM user_devices WHERE username = $1 AND fingerprint = $2',
                [username, fingerprint]
            );

            const countRes = await client.query(
                `SELECT COUNT(*) AS recent_fails
                 FROM login_risks
                 WHERE username = $1
                   AND is_success = FALSE
                   AND created_at > NOW() - INTERVAL '60 seconds'`,
                [username]
            );
            
            // ตรวจสอบ step-up attempts ใน 1 ชั่วโมง
            const stepupCountRes = await client.query(
                `SELECT COUNT(*) AS stepup_count
                 FROM stepup_challenges
                 WHERE username = $1
                   AND created_at > NOW() - INTERVAL '1 hour'`,
                [username]
            );

            const fp_match       = deviceRes.rows.length > 0;
            const currentAttempt = Number(countRes.rows[0].recent_fails) + 1;
            const stepupCount   = Number(stepupCountRes.rows[0]?.stepup_count || 0);

            const isOAuthFlow = req.body.next &&
                                typeof req.body.next === 'string' &&
                                req.body.next.includes('/oauth/authorize');

            let score = 0.1;

            if (!fp_match) score += 0.4; 
            if (currentAttempt > 3)  score += 0.3;
            if (currentAttempt >= 5) score  = 1.0;
            if (stepupCount >= 3) score = 1.0; // เกิน 3 step-up ใน 1 ชม ให้ revoke ทันที

            const { medium: MEDIUM_THRESHOLD } = getCombinedConfig();
            const level = score >= 1.0 ? 'HIGH' : (score >= MEDIUM_THRESHOLD ? 'MEDIUM' : 'LOW');

            let insertedId;
            try {
                const actionForHigh = level === 'HIGH' ? 'revoke' : null;
                const insertRes = await client.query(
                    `INSERT INTO login_risks (username, device, fingerprint, risk_level, pre_login_score, combined_action)
                     VALUES ($1, $2, $3, $4, $5, $6)
                     RETURNING id`,
                    [username, enhancedDevice, fingerprint, level, score, actionForHigh]
                );
                insertedId = insertRes.rows[0]?.id;
                await client.query('COMMIT');
            } catch (insertErr) {
                await client.query('ROLLBACK');

                if (insertErr.code === '23503') {
                    auditLog('ASSESS_FK_VIOLATION', { username, ip });
                    return res.status(200).json({ risk_level: 'MEDIUM', logId: null });
                }
                throw insertErr;
            }

            if (level === 'HIGH') {
                auditLog('ASSESS_HIGH_RISK', { 
                    username, 
                    ip, 
                    score, 
                    stepupCount,
                    reason: stepupCount >= 3 ? 'stepup_limit_exceeded_1h' : 'high_risk_score'
                });
                return res.status(200).json({ risk_level: 'HIGH', logId: null });
            }

            auditLog('ASSESS_COMPLETE', { username, ip, risk_level: level, logId: insertedId });
            return res.status(200).json({ risk_level: level, logId: insertedId });

        } catch (err) {
            try { await client.query('ROLLBACK'); } catch {  }
            throw err;
        } finally {
            client.release();
        }

    } catch (err) {
        console.error('[ERROR] assess.js:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
}
