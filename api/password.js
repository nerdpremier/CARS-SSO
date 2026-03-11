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

export default async function handler(req, res) {
    const action = req.body?.action ?? req.query?.action;
    if (action === 'forgot') return forgotHandler(req, res);
    if (action === 'reset')  return resetHandler(req, res);
    return res.status(400).json({ error: 'Invalid action. Use action: "forgot" or "reset"' });
}
