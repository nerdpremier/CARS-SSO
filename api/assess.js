// ============================================================
// api/assess.js — Risk Assessment
// ทำหน้าที่ประเมินความเสี่ยงของ login attempt ก่อนที่ auth.js จะตรวจ password
// คืน risk_level (LOW/MEDIUM/HIGH) และ logId สำหรับ session นั้น
//
// Flow:
//   1. ตรวจ Content-Type + CSRF + IP rate limit
//   2. Validate input fields
//   3. ตรวจ per-username rate limit
//   4. เปิด DB transaction พร้อม advisory lock ต่อ username
//   5. คำนวณ risk score จาก fingerprint match + recent fail count
//   6. INSERT บันทึกลง login_risks + COMMIT (ทุก level รวม HIGH)
//   7. คืน risk_level + logId (HIGH จะ return logId: null เสมอ)
// ============================================================

import '../startup-check.js';
import { pool }             from '../lib/db.js';
import { checkRateLimit }   from '../lib/rate-limit.js';
import { getClientIp }      from '../lib/ip-utils.js';
import { validateCsrfToken } from '../lib/csrf-utils.js';
import { ensureLoginRisksSchema } from '../lib/risk-score.js';
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

    // Support both same-origin CSRF-protected calls AND OAuth Bearer calls from customer apps.
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

    // If no valid bearer session, require CSRF (same-origin SSO flow)
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

        if (typeof username !== 'string' || !username || username.length > 32) {
            return res.status(400).json({ error: 'Invalid request data' });
        }
        if (!USER_REGEX.test(username)) {
            return res.status(400).json({ error: 'Invalid request data' });
        }

        // Bearer flow must only assess its own subject (prevent probing other usernames)
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

        // Validate reuse_log_id if provided
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

            // Check if we should reuse an existing logId
            if (reuse_log_id) {
                const parsedReuseId = Number(reuse_log_id);
                if (Number.isInteger(parsedReuseId) && parsedReuseId > 0) {
                    const existingRes = await client.query(
                        `SELECT id, risk_level, pre_login_score
                         FROM login_risks
                         WHERE id = $1 AND username = $2
                           AND created_at > NOW() - make_interval(mins => $3)
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

            // Advisory lock ต่อ username ป้องกัน TOCTOU:
            //   ใช้ upper 64 bits ของ MD5 แทน hashtext() (int4, 32-bit)
            //   MD5 → collision space 2^64 — practical collision-free
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

            const fp_match       = deviceRes.rows.length > 0;
            const currentAttempt = Number(countRes.rows[0].recent_fails) + 1;

            // ── Scoring logic ─────────────────────────────────
            // baseline 0.1 → +0.4 (device ใหม่) → +0.3 (fail > 3) → 1.0 (fail >= 5)
            // [FIX-OAUTH-FLOW] ถ้าเป็น OAuth flow จากเว็บลูกค้า → ลดความเสี่ยง
            console.log('[DEBUG] assess.js req.body:', req.body);
            console.log('[DEBUG] assess.js req.body.next:', req.body.next);
            
            const isOAuthFlow = req.body.next && 
                                typeof req.body.next === 'string' && 
                                req.body.next.includes('/oauth/authorize');
            
            console.log('[DEBUG] assess.js isOAuthFlow:', isOAuthFlow);
            
            let score = 0.1;
            if (!fp_match && !isOAuthFlow) score += 0.4; // device ใหม่ แต่ไม่ใช่ OAuth → +0.4
            if (isOAuthFlow) {
                // OAuth flow จากเว็บลูกค้า → ถือว่า trusted
                console.log('[DEBUG] assess.js OAuth flow detected, reducing risk score');
                score = 0.1; // ต่ำกว่า threshold MEDIUM (0.4) เพื่อให้เป็น LOW
            }
            if (currentAttempt > 3)  score += 0.3;
            if (currentAttempt >= 5) score  = 1.0;

            const level = score >= 0.7 ? 'HIGH' : (score >= 0.4 ? 'MEDIUM' : 'LOW');

            // COMMIT ทุก level รวม HIGH — เพื่อ audit trail และ forensics
            let insertedId;
            try {
                const insertRes = await client.query(
                    `INSERT INTO login_risks (username, device, fingerprint, risk_level, pre_login_score)
                     VALUES ($1, $2, $3, $4, $5)
                     RETURNING id`,
                    [username, device, fingerprint, level, score]
                );
                insertedId = insertRes.rows[0]?.id;
                await client.query('COMMIT');
            } catch (insertErr) {
                await client.query('ROLLBACK');
                // 23503 = FK violation (username ไม่มีใน users table)
                // คืน MEDIUM เหมือน non-existent user → ป้องกัน enumeration
                if (insertErr.code === '23503') {
                    auditLog('ASSESS_FK_VIOLATION', { username, ip });
                    return res.status(200).json({ risk_level: 'MEDIUM', logId: null });
                }
                throw insertErr;
            }

            if (level === 'HIGH') {
                auditLog('ASSESS_HIGH_RISK', { username, ip, score });
                return res.status(200).json({ risk_level: 'HIGH', logId: null });
            }

            auditLog('ASSESS_COMPLETE', { username, ip, risk_level: level, logId: insertedId });
            return res.status(200).json({ risk_level: level, logId: insertedId });

        } catch (err) {
            try { await client.query('ROLLBACK'); } catch { /* ignore */ }
            throw err;
        } finally {
            client.release();
        }

    } catch (err) {
        console.error('[ERROR] assess.js:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
}
