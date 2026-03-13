// ============================================================
// 🧹 cleanup.js (lib) — Reusable DB Cleanup Utility
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
 *   oauth_codes          — codes ที่หมดอายุ (ทั้งที่ใช้แล้วและยังไม่ได้ใช้)
 *   oauth_tokens         — access/refresh tokens ที่หมดอายุ
 *   email_verifications  — verification tokens ที่หมดอายุ
 *   login_risks (partial) — successful attempts เก่ากว่า 24 ชั่วโมง, failed attempts เก่ากว่า 7 วัน
 *
 * Batch limit (CLEANUP_BATCH_SIZE = 5000 rows ต่อ table ต่อครั้ง):
 *   DELETE ไม่มี LIMIT → ถ้า backlog สะสมนานหลายวัน cleanup ครั้งแรกจะลบแสน/ล้าน rows
 *   → exclusive lock บน table นาน → query อื่น (auth, rate-limit) ถูก block → latency spike
 *   batch limit ลด blast radius: cleanup หลายรอบแทน 1 รอบใหญ่
 *   rowCount < CLEANUP_BATCH_SIZE ใน return หมายความว่าไม่มี backlog เหลือ
 *
 * @returns {Promise<object>} จำนวน rows ที่ลบแต่ละ table
 */

// ลบสูงสุด N rows ต่อ table ต่อครั้ง — ป้องกัน table lock spike จาก backlog ใหญ่
// ปรับค่านี้ขึ้นได้ถ้าใช้ pg_cron (predictable load) หรือลงถ้า table มี write contention สูง
const CLEANUP_BATCH_SIZE = 5000;

export async function runCleanup() {
    // ใช้ Promise.allSettled (ไม่ใช่ Promise.all) เพื่อ error isolation จริง:
    //   Promise.all reject ทันทีที่ query แรก fail → queries อื่นที่สำเร็จไม่มีใครรับ rowCount
    //   Promise.allSettled รอทุก query ครบ → แต่ละ table fail-safe ต่อกัน
    //   pool.query() แต่ละตัวใช้ connection แยก → parallel จริง
    const settled = await Promise.allSettled([
        pool.query(`
            DELETE FROM rate_limit_events
            WHERE id IN (
                SELECT id FROM rate_limit_events
                WHERE created_at < NOW() - INTERVAL '2 hours'
                LIMIT $1
            )
        `, [CLEANUP_BATCH_SIZE]),
        pool.query(`
            DELETE FROM revoked_tokens
            WHERE id IN (
                SELECT id FROM revoked_tokens
                WHERE expires_at < NOW()
                LIMIT $1
            )
        `, [CLEANUP_BATCH_SIZE]),
        pool.query(`
            DELETE FROM sso_tokens
            WHERE id IN (
                SELECT id FROM sso_tokens
                WHERE expires_at < NOW()
                LIMIT $1
            )
        `, [CLEANUP_BATCH_SIZE]),
        pool.query(`
            DELETE FROM oauth_codes
            WHERE id IN (
                SELECT id FROM oauth_codes
                WHERE expires_at < NOW()
                LIMIT $1
            )
        `, [CLEANUP_BATCH_SIZE]),
        pool.query(`
            DELETE FROM oauth_tokens
            WHERE id IN (
                SELECT id FROM oauth_tokens
                WHERE expires_at < NOW()
                LIMIT $1
            )
        `, [CLEANUP_BATCH_SIZE]),
        pool.query(`
            DELETE FROM email_verifications
            WHERE id IN (
                SELECT id FROM email_verifications
                WHERE expires_at < NOW()
                LIMIT $1
            )
        `, [CLEANUP_BATCH_SIZE]),
        pool.query(`
            DELETE FROM login_risks
            WHERE id IN (
                SELECT id FROM login_risks
                WHERE (created_at < NOW() - INTERVAL '24 hours' AND is_success = TRUE)
                   OR (created_at < NOW() - INTERVAL '7 days')
                LIMIT $1
            )
        `, [CLEANUP_BATCH_SIZE]),
        pool.query(`
            DELETE FROM session_risks
            WHERE id IN (
                SELECT id FROM session_risks
                WHERE created_at < NOW() - INTERVAL '30 days'
                LIMIT $1
            )
        `, [CLEANUP_BATCH_SIZE]),
    ]);

    const TABLES = ['rateLimit', 'revokedTokens', 'ssoTokens', 'oauthCodes', 'oauthTokens', 'emailVerifications', 'loginRisks', 'sessionRisks'];
    const out    = {};
    for (let i = 0; i < settled.length; i++) {
        const r = settled[i];
        if (r.status === 'fulfilled') {
            out[TABLES[i]] = r.value.rowCount;
        } else {
            // log แต่ไม่ throw: table อื่นที่สำเร็จยังได้รายงาน rowCount ปกติ
            console.error(JSON.stringify({
                event: 'CLEANUP_ERROR',
                ts:    new Date().toISOString(),
                table: TABLES[i],
                error: r.reason?.message,
                code:  r.reason?.code,
            }));
            out[TABLES[i]] = null; // null = error, 0 = ลบ 0 rows (ต่างกัน)
        }
    }
    return out;
}

