// ============================================================
// Reusable DB Cleanup Utility
//
// ส่งออกเฉพาะ runCleanup() function
// HTTP handler อยู่ที่ api/cleanup.js
// ============================================================

import { pool } from './db.js';

/**
 * ลบ rows เก่าที่ไม่จำเป็นออกจาก DB
 *
 * Tables:
 *   rate_limit_events    — events เก่ากว่า 2 ชั่วโมง
 *   revoked_tokens       — JWT ที่ expires_at < NOW()
 *   sso_tokens           — one-time token ที่ expires_at < NOW()
 *   oauth_codes          — codes ที่หมดอายุและถูกใช้แล้ว
 *   oauth_tokens         — access/refresh tokens ที่หมดอายุ
 *   email_verifications  — verification tokens ที่หมดอายุ
 *   login_risks (partial) — successful attempts เก่ากว่า 24 ชั่วโมง
 *   user_devices         — trusted devices เก่ากว่า 7 วัน
 *
 * @returns {Promise<object>} จำนวน rows ที่ลบแต่ละ table
 */
export async function runCleanup() {
    const client = await pool.connect();
    try {
        const [rl, rt, sso, oc, ot, ev, lr, ud] = await Promise.all([
            client.query(`
                DELETE FROM rate_limit_events
                WHERE created_at < NOW() - INTERVAL '2 hours'
            `),
            client.query(`
                DELETE FROM revoked_tokens
                WHERE expires_at < NOW()
            `),
            client.query(`
                DELETE FROM sso_tokens
                WHERE expires_at < NOW()
            `),
            client.query(`
                DELETE FROM oauth_codes
                WHERE expires_at < NOW() AND used = TRUE
            `),
            client.query(`
                DELETE FROM oauth_tokens
                WHERE expires_at < NOW()
            `),
            client.query(`
                DELETE FROM email_verifications
                WHERE expires_at < NOW()
            `),
            client.query(`
                DELETE FROM login_risks
                WHERE created_at < NOW() - INTERVAL '24 hours'
                  AND is_success = TRUE
            `),
            client.query(`
                DELETE FROM user_devices
                WHERE created_at < NOW() - INTERVAL '7 days'
            `),
        ]);

        return {
            rateLimit:          rl.rowCount,
            revokedTokens:      rt.rowCount,
            ssoTokens:          sso.rowCount,
            oauthCodes:         oc.rowCount,
            oauthTokens:        ot.rowCount,
            emailVerifications: ev.rowCount,
            loginRisks:         lr.rowCount,
            userDevices:        ud.rowCount,
        };
    } finally {
        client.release();
    }
}

