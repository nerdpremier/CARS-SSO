// ============================================================
// 🔐 api/mfa.js — Combined MFA Handler
//
// รวม 2 MFA endpoints ไว้ในไฟล์เดียวเพื่อลด Vercel function count
// Route ด้วย action field ใน request body:
//   action: 'verify' → verify-mfa.js
//   action: 'resend' → resend-mfa.js
//
// vercel.json:
//   { "source": "/api/mfa", "destination": "/api/mfa.js" }
// ============================================================
import verifyHandler from '../lib/verify-mfa.js';
import resendHandler from '../lib/resend-mfa.js';
import { setSecurityHeaders } from '../lib/response-utils.js';

export default async function handler(req, res) {
    // ตรวจ Content-Type ก่อน dispatch: req.body?.action อาจเป็น undefined ถ้า body parser ไม่ทำงาน
    // เมื่อ Content-Type ไม่ใช่ application/json → body parser ข้าม → req.body = undefined
    // → action = undefined → fallthrough → 400 โดยไม่มี security headers
    // [FIX] setSecurityHeaders + Content-Type check ก่อน dispatch เสมอ
    if (req.method !== 'POST') {
        setSecurityHeaders(res);
        return res.status(405).send();
    }
    if (!req.headers['content-type']?.includes('application/json')) {
        setSecurityHeaders(res);
        return res.status(415).json({ error: 'Content-Type must be application/json' });
    }
    const action = req.body?.action;
    if (action === 'verify') return verifyHandler(req, res);
    if (action === 'resend') return resendHandler(req, res);
    setSecurityHeaders(res);
    return res.status(400).json({ error: 'Invalid request' });
}
