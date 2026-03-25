// ============================================================
// Risk Scoring & Database Schema Management
//
// ทำหน้าที่:
//   1. จัดการ database schema สำหรับ login_risks และ behavior_risks tables
//   2. คำนวณ combined risk score จาก pre-login และ post-login behavior
//   3. แปลง combined score เป็น action (low/medium/revoke)
//
// Schema evolution:
//   - ใช้ ALTER TABLE ... ADD COLUMN IF NOT EXISTS
//   - ป้องกัน migration error ใน production ที่มีข้อมูลอยู่แล้ว
//   - สร้าง index สำหรับ performance การ lookup
//
// Scoring algorithm:
//   - pre_login_score: คะแนนจาก assess.js (0.1-1.0)
//   - behavior_score: คะแนนจาก risk engine (0.0-1.0) 
//   - combined_score: ถ่วงน้ำหนัก w1=0.4 (pre) + w2=0.6 (behavior)
//   - action: low (<0.65), medium (0.65-0.8), revoke (>=0.8)
// ============================================================

import { pool } from './db.js';

let _ensurePromise = null;

/**
 * จัดการ schema สำหรับ login_risks table
 * เพิ่ม columns ใหม่ที่จำเป็นสำหรับ risk scoring system
 * ใช้ IF NOT EXISTS ป้องกัน error ใน production
 */
export async function ensureLoginRisksSchema() {
    if (_ensurePromise) return _ensurePromise;
    _ensurePromise = (async () => {
        // พยายามดีที่สุด, schema evolution ที่ทำซ้ำได้สำหรับการ deploy ที่มีอยู่แล้ว
        // หลีกเลี่ยง migration pipeline แยกใน Vercel serverless
        const statements = [
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS pre_login_score DOUBLE PRECISION`,
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS combined_score DOUBLE PRECISION`,
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS combined_action TEXT`,
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS session_jti TEXT`,
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS last_behavior_at TIMESTAMPTZ`,
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS behavior_samples INTEGER DEFAULT 0`,
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS is_success BOOLEAN DEFAULT FALSE`,
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS mfa_code TEXT`,
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS mfa_expires_at TIMESTAMPTZ`,
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS mfa_attempts INTEGER DEFAULT 0`,
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS total_mfa_attempts INTEGER DEFAULT 0`,
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS mfa_resent_at TIMESTAMPTZ`,
        ];
        for (const sql of statements) {
            try { await pool.query(sql); } catch { /* ignore */ }
        }
        // helpful index for fast lookup by session
        try {
            await pool.query(
                `CREATE INDEX IF NOT EXISTS login_risks_session_jti_idx
                 ON login_risks (username, session_jti)`
            );
        } catch { /* ignore */ }

        // index for is_success column used in frequent queries
        try {
            await pool.query(
                `CREATE INDEX IF NOT EXISTS login_risks_is_success_idx
                 ON login_risks (username, is_success, created_at DESC)`
            );
        } catch { /* ignore */ }
    })();
    return _ensurePromise;
}

/**
 * จัดการ schema สำหรับ behavior_risks table
 * เก็บข้อมูล post-login behavior samples แยกต่างหากจาก login_risks
 */
export async function ensureBehaviorRisksSchema() {
    await ensureLoginRisksSchema();

    // สร้าง table สำหรับเก็บ post-login behavior risk samples
    try {
        await pool.query(
            `CREATE TABLE IF NOT EXISTS behavior_risks (
                id BIGSERIAL PRIMARY KEY,
                request_id TEXT,
                username TEXT NOT NULL,
                session_jti TEXT NOT NULL,
                behavior_score DOUBLE PRECISION,
                combined_score DOUBLE PRECISION,
                combined_action TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )`
        );
    } catch { /* ignore */ }

    // ลบ deprecated column จากเวอร์ชันเก่า (ถ้ามี)
    try {
        await pool.query(
            `ALTER TABLE behavior_risks DROP COLUMN IF EXISTS engine_action`
        );
    } catch { /* ignore */ }

    try {
        await pool.query(
            `ALTER TABLE behavior_risks
             ADD COLUMN IF NOT EXISTS request_id TEXT`
        );
    } catch { /* ignore */ }

    try {
        await pool.query(
            `CREATE INDEX IF NOT EXISTS behavior_risks_session_idx
             ON behavior_risks (username, session_jti, created_at DESC)`
        );
    } catch { /* ignore */ }

    try {
        await pool.query(
            `CREATE INDEX IF NOT EXISTS behavior_risks_request_id_idx
             ON behavior_risks (request_id)`
        );
    } catch { /* ignore */ }

    // ── เพิ่ม pre_login_log_id ให้ oauth_codes และ oauth_tokens ──
    // เก็บ pre_login_log_id ไว้ใน token chain เพื่อให้ behavior.js
    // ดึงค่ามาใช้ได้โดยไม่ต้องพึ่ง cookie จากฝั่ง client
    try {
        await pool.query(
            `ALTER TABLE oauth_codes ADD COLUMN IF NOT EXISTS pre_login_log_id INTEGER`
        );
    } catch { /* ignore */ }

    try {
        await pool.query(
            `ALTER TABLE oauth_tokens ADD COLUMN IF NOT EXISTS pre_login_log_id INTEGER`
        );
    } catch { /* ignore */ }
}

/**
 * จัดการ schema สำหรับ stepup_challenges table
 * เก็บข้อมูล step-up authentication challenges
 */
export async function ensureStepupChallengesSchema() {
    try {
        await pool.query(
            `CREATE TABLE IF NOT EXISTS stepup_challenges (
                id UUID PRIMARY KEY,
                username TEXT NOT NULL,
                session_jti TEXT,
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
            `ALTER TABLE stepup_challenges
             ADD COLUMN IF NOT EXISTS session_jti TEXT`
        );
    } catch { /* ignore */ }

    try {
        await pool.query(
            `CREATE INDEX IF NOT EXISTS stepup_challenges_user_time_idx
             ON stepup_challenges (username, created_at DESC)`
        );
    } catch { /* ignore */ }

    try {
        await pool.query(
            `CREATE INDEX IF NOT EXISTS stepup_challenges_session_idx
             ON stepup_challenges (username, session_jti, created_at DESC)`
        );
    } catch { /* ignore */ }
}

/**
 * จำกัดค่าให้เป็นช่วง 0.0 - 1.0
 * ใช้สำหรับ clamp score ไม่ให้เกินขอบเขต
 */
function clamp01(x) {
    const n = Number(x);
    if (!Number.isFinite(n)) return 0;
    if (n < 0) return 0;
    if (n > 1) return 1;
    return n;
}

/**
 * คืนค่า configuration สำหรับ combined risk scoring
 * 
 * Returns:
 *   w1: น้ำหนักสำหรับ pre-login score (0.4)
 *   w2: น้ำหนักสำหรับ behavior score (0.6) 
 *   medium: threshold สำหรับ action = medium (0.65)
 *   revoke: threshold สำหรับ action = revoke (0.8)
 */
export function getCombinedConfig() {
    return {
        w1: 0.3,
        w2: 0.7,
        medium: 0.55,
        revoke: 0.85,
    };
}

/**
 * คำนวณ combined risk score จาก pre-login และ behavior scores
 * 
 * สูตร: combined = w1 * pre_login_score + w2 * behavior_score
 * โดยที่ w1 + w2 = 1.0 (normalized weights)
 * 
 * @param {number} preLoginScore - คะแนนจาก assess.js (0.1-1.0)
 * @param {number} behaviorScore - คะแนนจาก risk engine (0.0-1.0)
 * @returns {number} combined score (0.0-1.0)
 */
export function combineRisk(preLoginScore, behaviorScore) {
    const { w1, w2 } = getCombinedConfig();
    return clamp01(w1 * clamp01(preLoginScore) + w2 * clamp01(behaviorScore));
}

/**
 * แปลง combined risk score เป็น action ที่เหมาะสม
 * 
 * กฎการตัดสินใจ:
 *   - score >= 0.8  → revoke (บังคับ logout)
 *   - score >= 0.65 → medium (ต้อง MFA)
 *   - score < 0.65  → low (ผ่านปกติ)
 * 
 * @param {number} combinedScore - combined risk score (0.0-1.0)
 * @returns {string} action: 'low', 'medium', หรือ 'revoke'
 */
export function actionFromCombinedScore(combinedScore) {
    const { medium, revoke } = getCombinedConfig();
    const s = clamp01(combinedScore);
    if (s >= revoke) return 'revoke';
    if (s >= medium) return 'medium';
    return 'low';
}
