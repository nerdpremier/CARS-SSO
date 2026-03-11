// ============================================================
// 🔗 redirect-utils.js — OAuth Redirect URI Validation
//
// แยกออกมาจาก auth.js และ verify-mfa.js ที่มีฟังก์ชันเดียวกันซ้ำกัน
//
// ใช้สำหรับ SSO redirect flow:
//   1. auth.js (LOW path)     — login สำเร็จ → redirect ไป third-party app
//   2. verify-mfa.js          — MFA สำเร็จ  → redirect ไป third-party app
//
// Security:
//   ตรวจ redirect_back กับ oauth_clients.redirect_uris ใน DB
//   ป้องกัน Open Redirect: attacker ส่ง URL ที่ตัวเองควบคุม
//   → ได้ sso_token → account takeover บน third-party service
//
//   Fail closed: DB error → return false → ไม่ทำ SSO redirect
//   ดีกว่า fail open ที่อนุญาต redirect ไปยัง URL ที่ไม่ได้ตรวจ
// ============================================================
import { pool } from './db.js';

/**
 * ตรวจสอบว่า redirect URL ถูกลงทะเบียนใน oauth_clients.redirect_uris หรือไม่
 *
 * @param {unknown} redirectBack - URL ที่ต้องการ validate
 * @returns {Promise<boolean>} true ถ้า URL อยู่ใน DB และ valid
 */
export async function validateRedirectBack(redirectBack) {
    if (!redirectBack || typeof redirectBack !== 'string' || redirectBack.length > 512) {
        return false;
    }
    try {
        const result = await pool.query(
            'SELECT 1 FROM oauth_clients WHERE $1 = ANY(redirect_uris)',
            [redirectBack]
        );
        return result.rows.length > 0;
    } catch (dbErr) {
        console.error('[WARN] validateRedirectBack DB error:', dbErr.message);
        return false;
    }
}
