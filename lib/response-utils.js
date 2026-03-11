// ============================================================
// 🛠️ response-utils.js — Shared API Response Utilities
//
// รวม utilities ที่ใช้ซ้ำทุก API handler ไว้ที่เดียว
// ป้องกัน drift เมื่อแก้ security header ในไฟล์เดียวแล้วลืมอีก 10 ไฟล์
//
// Exports:
//   setSecurityHeaders(res)  — ตั้ง 6 security response headers
//   auditLog(event, fields)  — structured JSON logging
//   USER_REGEX               — username: alphanumeric only
//   SAFE_STRING_REGEX        — printable ASCII (fingerprint/device)
//   LOGID_STRING_REGEX       — digit-only string (ป้องกัน "1e5" bypass)
// ============================================================

/**
 * ตั้ง security response headers ที่จำเป็นทุก API endpoint
 * เรียกก่อนทุก return เพื่อให้ทุก response (รวม 4xx, 5xx) มี header ครบ
 *
 * @param {import('http').ServerResponse} res
 */
export function setSecurityHeaders(res) {
    res.setHeader('X-Content-Type-Options',   'nosniff');
    res.setHeader('X-Frame-Options',          'DENY');
    res.setHeader('Content-Security-Policy',  "default-src 'self'");
    res.setHeader('Strict-Transport-Security','max-age=63072000; includeSubDomains; preload');
    res.setHeader('Referrer-Policy',          'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy',       'camera=(), microphone=(), geolocation=()');
}

/**
 * บันทึก structured audit log เป็น JSON (ส่งออก stdout สำหรับ log aggregator)
 *
 * @param {string} event  - ชื่อ event เช่น 'LOGIN_SUCCESS'
 * @param {object} fields - ข้อมูลเพิ่มเติม เช่น { username, ip }
 */
export function auditLog(event, fields) {
    console.log(JSON.stringify({ event, ts: new Date().toISOString(), ...fields }));
}

// ── Shared Regex Patterns ────────────────────────────────────────────────────
// กำหนดไว้ที่เดียวเพื่อป้องกัน inconsistency ระหว่างไฟล์

/** username: ตัวอักษรและตัวเลขเท่านั้น ป้องกัน injection / log poisoning */
export const USER_REGEX = /^[a-zA-Z0-9]+$/;

/** fingerprint/device: printable ASCII เท่านั้น ป้องกัน control chars ใน log */
export const SAFE_STRING_REGEX = /^[\x20-\x7E]+$/;

/**
 * logId: digit ล้วน ป้องกัน "1e5" (scientific notation) ผ่าน Number() แล้วได้ integer
 * Number("1e5") = 100000, isInteger(100000) = true แต่ format ไม่ใช่ plain integer
 */
export const LOGID_STRING_REGEX = /^\d+$/;

/** password: ต้องมีตัวใหญ่ ตัวเล็ก ตัวเลข สัญลักษณ์ อย่างน้อย 8 ตัว */
export const PASS_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

/** email: basic format check ก่อน normalize */
export const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** reset token: hex string 64 ตัวอักษร */
export const TOKEN_REGEX = /^[0-9a-f]{64}$/i;

/**
 * Guard: ตรวจ Content-Type: application/json
 * คืน true ถ้า header ถูกต้อง (ให้ผ่าน), false ถ้าไม่ถูกต้อง (ควร return 415)
 *
 * @param {import('http').IncomingMessage} req
 * @returns {boolean}
 */
export function isJsonContentType(req) {
    return !!req.headers['content-type']?.includes('application/json');
}

/**
 * Guard: ตรวจ req.body ว่าเป็น plain object (ไม่ใช่ null หรือ array)
 * คืน true ถ้าถูกต้อง
 *
 * @param {unknown} body
 * @returns {boolean}
 */
export function isValidBody(body) {
    return !!body && typeof body === 'object' && !Array.isArray(body);
}
