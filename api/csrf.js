// ============================================================
// 🔐 api/csrf.js — CSRF Token Endpoint (HMAC Double-Submit)
// ============================================================
import '../startup-check.js';
import { serialize }          from 'cookie';
import { generateCsrfToken }  from '../lib/csrf-utils.js';
import { checkRateLimit }     from '../lib/rate-limit.js';
import { getClientIp }        from '../lib/ip-utils.js';
import { setSecurityHeaders, auditLog } from '../lib/response-utils.js';

export default async function handler(req, res) {
    if (req.method !== 'GET') return res.status(405).send();

    setSecurityHeaders(res);
    res.setHeader('Cache-Control', 'no-store');

    const ip = getClientIp(req);
    try {
        if (await checkRateLimit(`ip:${ip}:csrf`, 60, 60_000)) {
            auditLog('CSRF_IP_RATE_LIMIT', { ip });
            return res.status(429).json({ error: 'ส่งคำขอบ่อยเกินไป กรุณารอสักครู่' });
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit DB error (csrf), failing open:', rlErr.message);
    }

    let token;
    try {
        token = generateCsrfToken();
    } catch (err) {
        auditLog('CSRF_TOKEN_GEN_ERROR', { error: err.message });
        return res.status(500).json({ error: 'ระบบขัดข้อง' });
    }

    // httpOnly: false — จำเป็น! JS ต้องอ่าน cookie เพื่อส่งใน X-CSRF-Token header
    res.setHeader('Set-Cookie', serialize('csrf_token', token, {
        httpOnly: false,
        secure:   process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge:   3600,
        path:     '/'
    }));

    return res.status(200).json({ token });
}
