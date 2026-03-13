// ============================================================
// 🔑 api/password.js — Combined Password Handler
//
// รวม 2 password endpoints ไว้ในไฟล์เดียวเพื่อลด Vercel function count
// Route ด้วย action field ใน request body:
//   action: 'forgot' → forgot-password.js
//   action: 'reset'  → reset-password.js
//
// vercel.json:
//   { "source": "/api/password", "destination": "/api/password.js" }
// ============================================================
import forgotHandler from './forgot-password.js';
import resetHandler  from './reset-password.js';
import { setSecurityHeaders } from '../lib/response-utils.js';

export default async function handler(req, res) {
    // ตรวจ Content-Type ก่อน dispatch: เหตุผลเดียวกับ mfa.js
    // body parser ข้ามเมื่อ Content-Type ไม่ตรง → req.body?.action = undefined → 400 ไม่มี headers
    if (req.method !== 'POST') {
        setSecurityHeaders(res);
        return res.status(405).send();
    }
    if (!req.headers['content-type']?.includes('application/json')) {
        setSecurityHeaders(res);
        return res.status(415).json({ error: 'Content-Type must be application/json' });
    }
    const action = req.body?.action;
    if (action === 'forgot') return forgotHandler(req, res);
    if (action === 'reset')  return resetHandler(req, res);
    setSecurityHeaders(res);
    return res.status(400).json({ error: 'Invalid request' });
}
