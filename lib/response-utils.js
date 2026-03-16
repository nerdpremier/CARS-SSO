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
    return setSecurityHeadersWithOptions(res);
}

/**
 * ตั้ง security response headers แบบ configurable
 *
 * @param {import('http').ServerResponse} res
 * @param {{
 *  framePolicy?: 'DENY'|'SAMEORIGIN',
 *  csp?: string,
 *  cacheControl?: string,
 *  pragmaNoCache?: boolean,
 * }} [opts]
 */
export function setSecurityHeadersWithOptions(res, opts = {}) {
    const framePolicy = opts.framePolicy || 'DENY';
    const csp = opts.csp || "default-src 'self'";

    res.setHeader('X-Content-Type-Options',    'nosniff');
    res.setHeader('X-Frame-Options',           framePolicy);
    res.setHeader('Content-Security-Policy',   csp);
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
    res.setHeader('Referrer-Policy',           'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy',        'camera=(), microphone=(), geolocation=()');

    if (opts.cacheControl) res.setHeader('Cache-Control', opts.cacheControl);
    if (opts.pragmaNoCache) res.setHeader('Pragma', 'no-cache');
    return res;
}

/**
 * บันทึก structured audit log เป็น JSON (ส่งออก stdout สำหรับ log aggregator)
 *
 * สำคัญ: event และ ts ถูกวางก่อน ...fields เสมอ แต่ไม่เพียงพอ —
 *   { event, ts, ...fields } อนุญาตให้ caller ที่ส่ง fields = { event: 'LOGIN_SUCCESS' }
 *   override ค่า event จริงได้ → log aggregator อ่าน event ผิด → security audit miss
 *
 *   แก้: spread fields ก่อน แล้วทับด้วย event+ts ที่ถูกต้อง (fields ไม่สามารถ override ได้)
 *   ผลลัพธ์: { ...fields, event, ts } — event/ts มาจาก caller เสมอ
 *
 * @param {string} event  - ชื่อ event เช่น 'LOGIN_SUCCESS'
 * @param {object} [fields={}] - ข้อมูลเพิ่มเติม เช่น { username, ip }
 */
export function auditLog(event, fields = {}) {
    console.log(JSON.stringify({ ...fields, event, ts: new Date().toISOString() }));
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

/** password: ต้องมีตัวใหญ่ ตัวเล็ก ตัวเลข สัญลักษณ์ อย่างน้อย 8 ตัว สูงสุด 128 ตัว
 *  upper bound 128: ป้องกัน lookahead scan บน input ขนาดใหญ่ก่อน caller ตรวจ length
 *  (bcrypt ตัด input ที่ 72 bytes — ค่า > 128 ไม่เพิ่ม entropy จริงและเพิ่ม CPU waste)
 */
export const PASS_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#^_\-+=()])[A-Za-z\d@$!%*?&#^_\-+=()]{8,128}$/;

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

/**
 * Guard: require JSON request + plain object body.
 * Returns true if request is OK to process; otherwise writes response and returns false.
 *
 * @param {import('http').IncomingMessage & { body?: unknown }} req
 * @param {import('http').ServerResponse & { status?: (code:number)=>any, json?: (data:any)=>any }} res
 * @returns {boolean}
 */
export function requireJson(req, res) {
    if (!isJsonContentType(req)) {
        res.status?.(415);
        res.json?.({ error: 'Content-Type must be application/json' });
        return false;
    }
    if (!isValidBody(req.body)) {
        res.status?.(400);
        res.json?.({ error: 'Invalid request body' });
        return false;
    }
    return true;
}
