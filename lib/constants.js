// ============================================================
// 📐 constants.js — Shared Application Constants
// รวม constants ที่ใช้ร่วมกันระหว่าง auth.js, resend-mfa.js, verify-mfa.js
// ไว้ที่เดียวเพื่อป้องกัน drift เมื่อแก้ค่าในไฟล์เดียวแล้วลืมอีกไฟล์
//
// Relationships ที่สำคัญ:
//   TOTAL_MFA_MAX > MFA_MAX_ATTEMPTS:
//     เพราะ total นับทั้ง verify + resend
//     ถ้า TOTAL_MFA_MAX <= MFA_MAX_ATTEMPTS → total limit ถูก hit ก่อน per-code limit เสมอ
//     → MFA_MAX_ATTEMPTS ไม่มีผลจริง
//
//   "+1 guard" ใน auth.js และ resend-mfa.js:
//     block send/resend เมื่อ currentTotal + 1 >= TOTAL_MFA_MAX
//     สงวน 1 slot สำหรับ verify เสมอ
//     → effective verify slots = TOTAL_MFA_MAX - (จำนวนครั้งที่ส่ง code)
//     → ถ้าส่ง code 1 ครั้ง: verify ได้สูงสุด TOTAL_MFA_MAX - 1 = 14 ครั้ง
//        แต่ถูกจำกัดด้วย MFA_MAX_ATTEMPTS = 5 ก่อน
//
//   SESSION_DURATION_SECONDS ต้องตรงกับ JWT expiresIn ใน auth.js และ verify-mfa.js:
//     เดิม: กำหนดแยกในแต่ละไฟล์ → verify-mfa.js เคยมีค่า 29100 (8h5m) ผิดพลาด [BUG-010]
//     แก้: กำหนดที่นี่ที่เดียว → auth.js และ verify-mfa.js import ค่าเดียวกัน
// ============================================================

/** อายุของ logId นับจาก created_at (immutable) ไม่ใช่ updated_at
 *  resend ไม่ขยาย TTL เพราะใช้ created_at เป็น anchor */
export const LOGID_TTL_MINUTES   = 15;

/** จำนวนครั้ง verify สูงสุดต่อ code ปัจจุบัน
 *  reset เป็น 0 ทุกครั้งที่ส่ง code ใหม่ (resend หรือ initial send)
 *  ป้องกัน brute-force บน code ชุดเดียว */
export const MFA_MAX_ATTEMPTS    = 5;

/** จำนวนครั้ง MFA รวมสูงสุดตลอด session
 *  นับสะสม: ทุก verify attempt + ทุก resend + initial send
 *  ไม่ reset ตลอดอายุ session (logId TTL = LOGID_TTL_MINUTES)
 *  ป้องกัน brute-force ที่วนขอ code ใหม่แล้ว verify ซ้ำ */
export const TOTAL_MFA_MAX       = 15;

/** cooldown ระหว่าง resend MFA (วินาที)
 *  ป้องกัน email flooding: user ต้องรอก่อนขอ code ใหม่ */
export const RESEND_COOLDOWN_SEC = 60;

/**
 * อายุ session (วินาที) — ต้องตรงกับ JWT expiresIn ใน auth.js และ verify-mfa.js
 * 28800 = 8 ชั่วโมง = '8h' ใน jsonwebtoken
 *
 * [BUG-010 FIX] เดิม verify-mfa.js ใช้ 29100 (8h5m) ซึ่งไม่ตรงกับ auth.js (28800)
 * → session expiry ไม่ consistent ระหว่าง LOW path (auth.js) และ MEDIUM path (verify-mfa.js)
 * แก้: กำหนดที่ constants.js ที่เดียว ทั้งสองไฟล์ใช้ค่าเดียวกัน
 */
export const SESSION_DURATION_SECONDS = 28800; // 8 ชั่วโมง

// ── Runtime invariant validation ─────────────────────────────
// ตรวจตอน module load: ถ้าค่าผิดพลาด → throw ทันที (fail-fast)
// ดีกว่าปล่อยให้ระบบ block user ตลอดโดยไม่มี error ชัดเจน
// เช่น TOTAL_MFA_MAX = 0 → user ถูก block ทุก MFA request โดยไม่รู้สาเหตุ
const _checks = [
    [Number.isInteger(LOGID_TTL_MINUTES)      && LOGID_TTL_MINUTES      > 0, 'LOGID_TTL_MINUTES must be a positive integer'],
    [Number.isInteger(MFA_MAX_ATTEMPTS)        && MFA_MAX_ATTEMPTS        > 0, 'MFA_MAX_ATTEMPTS must be a positive integer'],
    [Number.isInteger(TOTAL_MFA_MAX)           && TOTAL_MFA_MAX           > 0, 'TOTAL_MFA_MAX must be a positive integer'],
    [Number.isInteger(RESEND_COOLDOWN_SEC)     && RESEND_COOLDOWN_SEC     > 0, 'RESEND_COOLDOWN_SEC must be a positive integer'],
    [Number.isInteger(SESSION_DURATION_SECONDS)&& SESSION_DURATION_SECONDS > 0, 'SESSION_DURATION_SECONDS must be a positive integer'],
    // TOTAL_MFA_MAX > MFA_MAX_ATTEMPTS: ถ้าไม่เป็นจริง → MFA_MAX_ATTEMPTS ไม่มีผลจริงเลย
    [TOTAL_MFA_MAX > MFA_MAX_ATTEMPTS, 'TOTAL_MFA_MAX must be greater than MFA_MAX_ATTEMPTS'],
    // SESSION_DURATION_SECONDS ต้องตรงกับ '8h' = 28800 (sanity check ป้องกัน typo)
    [SESSION_DURATION_SECONDS === 28800, 'SESSION_DURATION_SECONDS must equal 28800 (8h) to match JWT expiresIn'],
];

for (const [ok, msg] of _checks) {
    if (!ok) throw new Error(`[constants.js] Invalid constant: ${msg}`);
}
