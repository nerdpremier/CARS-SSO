// ============================================================
// 🔐 mfa-utils.js — Shared MFA Utilities
//
// ให้บริการ hashMfaCode() สำหรับสร้าง HMAC ของรหัส OTP
// ก่อนเก็บลง DB เพื่อป้องกัน rainbow table และ brute-force
// ============================================================
import crypto from 'crypto';

// Regex ตรวจว่า OTP เป็นตัวเลข 6 หลักพอดี (ไม่มี leading space, sign, หรือ decimal)
const OTP_PATTERN = /^\d{6}$/;

/**
 * สร้าง HMAC-SHA256 ของรหัส OTP ก่อนเก็บลง DB
 *
 * วิธีทำงาน:
 *   HMAC-SHA256(key = MFA_PEPPER, message = "<logId>:<code>")
 *
 *   - MFA_PEPPER  → secret key ใน HMAC (ไม่ใช่แค่ส่วนหนึ่งของ message)
 *                   ทำให้ attacker ที่ไม่รู้ pepper ไม่สามารถ precompute ได้
 *   - logId       → per-session salt ผูก hash กับ session นี้เท่านั้น
 *                   hash จาก session อื่นใช้ซ้ำไม่ได้ แม้ OTP จะตรงกัน
 *
 * เหตุที่ใช้ HMAC แทน SHA-256 ธรรมดา:
 *   SHA-256(logId:code:pepper) — pepper อยู่ท้าย message
 *     → เสี่ยงต่อ length-extension attack
 *     → pepper ทำหน้าที่เป็น data ไม่ใช่ key
 *   HMAC-SHA256(key=pepper, msg=logId:code) — pepper ถูก mix เข้า ipad/opad
 *     → resistant ต่อ length-extension โดย design ของ HMAC
 *     → semantically ถูกต้อง: pepper คือ secret key
 *
 * @param {string|number} code  - รหัส OTP ที่ต้องเป็นตัวเลข 6 หลักพอดี
 * @param {string|number} logId - login_risks.id ของ session ปัจจุบัน (ต้องไม่ว่าง)
 * @returns {string} HMAC-SHA256 hex digest
 * @throws {Error} ถ้า MFA_PEPPER ไม่ได้ตั้งค่า หรือ argument ไม่ถูกต้อง
 */
export function hashMfaCode(code, logId) {
    // ── 1. ตรวจ environment variable ────────────────────────────────────────
    // ใช้ throw แทน fallback เพื่อให้ fail loudly ทุก environment
    // ป้องกันกรณีที่ลบ startup-check.js ออกแล้ว security ลดลงอย่างเงียบๆ
    const pepper = process.env.MFA_PEPPER;
    if (!pepper) {
        throw new Error('[CONFIG] MFA_PEPPER environment variable is not set');
    }

    // ── 2. ตรวจ argument ────────────────────────────────────────────────────
    // ตรวจก่อน String() เพื่อจับ undefined/null ที่จะกลายเป็น
    // string "undefined" / "null" และผ่านเข้า hash โดยไม่ error
    if (code == null) {
        throw new Error('[INPUT] code must not be null or undefined');
    }
    if (logId == null) {
        throw new Error('[INPUT] logId must not be null or undefined');
    }

    const codeStr  = String(code);
    const logIdStr = String(logId);

    // ตรวจรูปแบบ OTP: ต้องเป็นตัวเลข 6 หลักพอดี
    if (!OTP_PATTERN.test(codeStr)) {
        throw new Error('[INPUT] code must be exactly 6 digits');
    }

    // ตรวจ logId ต้องไม่ว่างหลัง trim (ป้องกันค่า whitespace-only)
    if (!logIdStr.trim()) {
        throw new Error('[INPUT] logId must not be empty');
    }

    // ── 3. คำนวณ HMAC-SHA256 ────────────────────────────────────────────────
    // key     = pepper  (secret ที่ attacker ไม่รู้)
    // message = logId:code  (ผูก hash กับ session + OTP นี้เท่านั้น)
    return crypto
        .createHmac('sha256', pepper)
        .update(`${logIdStr}:${codeStr}`)
        .digest('hex');
}
