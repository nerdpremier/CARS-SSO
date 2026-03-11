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
import verifyHandler from './verify-mfa.js';
import resendHandler from './resend-mfa.js';

export default async function handler(req, res) {
    const action = req.body?.action ?? req.query?.action;
    if (action === 'verify') return verifyHandler(req, res);
    if (action === 'resend') return resendHandler(req, res);
    return res.status(400).json({ error: 'Invalid action. Use action: "verify" or "resend"' });
}
