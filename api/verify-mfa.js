// ============================================================
// 🛡️ api/verify-mfa.js — MFA Code Verification
// ทำหน้าที่ตรวจสอบ OTP ที่ user กรอก → ออก JWT เมื่อถูกต้อง พร้อมจัดการ SSO Redirect
//
// Security design:
//   - ผูก logId กับ username ป้องกัน session enumeration / slot burning
//   - กรอง risk_level = 'MEDIUM' เท่านั้น (HIGH records ไม่สามารถ verify ได้)
//   - FOR UPDATE ป้องกัน concurrent requests race กันบน attempt counters
//   - WHERE mfa_attempts < $2 AND total < $3 ใน UPDATE: atomic guard ป้องกัน TOCTOU
//   - JWT sign ก่อน COMMIT: ถ้า sign fail → ROLLBACK → user retry ได้
//   - timingSafeHashEqual: ป้องกัน timing oracle แม้ rate limit ป้องกันอยู่แล้ว
// ============================================================
import '../startup-check.js';
import { pool }                from '../lib/db.js';
import { validateCsrfToken }   from '../lib/csrf-utils.js';
import { checkRateLimit }      from '../lib/rate-limit.js';
import { getClientIp }         from '../lib/ip-utils.js';
import { LOGID_TTL_MINUTES, MFA_MAX_ATTEMPTS, TOTAL_MFA_MAX, SESSION_DURATION_SECONDS } from '../lib/constants.js';
import { hashMfaCode }         from '../lib/mfa-utils.js';
import { validateRedirectBack } from '../lib/redirect-utils.js';
import {
    setSecurityHeaders, auditLog,
    USER_REGEX, LOGID_STRING_REGEX,
    isJsonContentType, isValidBody,
} from '../lib/response-utils.js';
import jwt         from 'jsonwebtoken';
import { serialize } from 'cookie';
import crypto      from 'crypto';

const OTP_REGEX = /^\d{6}$/;

/**
 * Timing-safe comparison สำหรับ MFA hash
 * ป้องกัน timing oracle: string === คืนเร็วเมื่อ prefix ต่างกัน
 */
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
        return res.status(403).json({ error: 'CSRF token ไม่ถูกต้อง' });
    }

    const ip = getClientIp(req);
    try {
        if (await checkRateLimit(`ip:${ip}:verify-mfa`, 30, 60_000)) {
            auditLog('VERIFY_MFA_IP_RATE_LIMIT', { ip });
            return res.status(429).json({ error: 'ส่งคำขอบ่อยเกินไป กรุณารอสักครู่' });
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit DB error (verify-mfa), failing open:', rlErr.message);
    }

    if (!isValidBody(req.body)) {
        return res.status(400).json({ error: 'ข้อมูลไม่ครบถ้วน' });
    }

    const { logId, code, remember, username, redirect_back } = req.body;

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

    if (typeof code !== 'string' || !OTP_REGEX.test(code)) {
        return res.status(400).json({ error: 'รหัส OTP ไม่ถูกต้อง' });
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
                return res.status(400).json({ error: 'Session หมดอายุ กรุณาเริ่มต้นใหม่' });
            }

            const row = riskRes.rows[0];
            const currentAttempts = Number(row.mfa_attempts || 0);
            const currentTotal    = Number(row.total_mfa_attempts || 0);

            // ── Attempt limits ────────────────────────────────
            if (currentAttempts >= MFA_MAX_ATTEMPTS || currentTotal >= TOTAL_MFA_MAX) {
                await client.query('ROLLBACK');
                auditLog('MFA_ATTEMPT_LIMIT', { username, ip, currentAttempts, currentTotal });
                return res.status(429).json({ error: 'ยืนยันรหัสผิดเกินจำนวนที่อนุญาต กรุณาเริ่มต้นใหม่' });
            }

            // ── OTP expiry ────────────────────────────────────
            if (!row.mfa_expires_at || new Date() > new Date(row.mfa_expires_at)) {
                await client.query('ROLLBACK');
                return res.status(400).json({ error: 'รหัส OTP หมดอายุ กรุณาขอรหัสใหม่' });
            }

            // ── Atomic increment + TOCTOU guard ──────────────
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
                return res.status(429).json({ error: 'ยืนยันรหัสผิดเกินจำนวนที่อนุญาต กรุณาเริ่มต้นใหม่' });
            }

            // ── Timing-safe OTP comparison ────────────────────
            const inputHash = hashMfaCode(code, parsedLogId);
            if (!timingSafeHashEqual(row.mfa_code, inputHash)) {
                await client.query('COMMIT'); // commit attempt counter
                auditLog('MFA_WRONG_CODE', { username, ip });
                return res.status(401).json({ error: 'รหัส OTP ไม่ถูกต้อง' });
            }

            // ── MFA passed — mark logId as used ──────────────
            await client.query(
                'UPDATE login_risks SET is_success = TRUE WHERE id = $1',
                [parsedLogId]
            );

            // remember me
            if ((remember === true || remember === 'true') && req.body.fingerprint) {
                await client.query(
                    'INSERT INTO user_devices (username, fingerprint) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                    [username, req.body.fingerprint]
                );
            }

            // JWT sign ก่อน COMMIT
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
                console.error('[ERROR] verify-mfa.js JWT sign failed:', jwtErr.message);
                return res.status(500).json({ error: 'เซิร์ฟเวอร์ขัดข้อง' });
            }

            await client.query('COMMIT');

            // [BUG-005 FIX] SSO Redirect
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
                        console.error('[WARN] verify-mfa.js SSO token insert failed:', ssoErr.message);
                    }
                } else {
                    console.error('[WARN] verify-mfa.js: redirect_back ไม่ได้ลงทะเบียน:', redirect_back);
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
        console.error('[ERROR] verify-mfa.js:', err);
        return res.status(500).json({ error: 'เซิร์ฟเวอร์ขัดข้อง' });
    }
}
