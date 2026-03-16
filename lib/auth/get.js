import { pool } from '../db.js';
import { checkRateLimit } from '../rate-limit.js';
import { getClientIp } from '../ip-utils.js';
import crypto from 'crypto';
import { auditLog, USER_REGEX, TOKEN_REGEX } from '../response-utils.js';

export async function handleAuthGet(req, res) {
    const { action, username } = req.query;

    res.setHeader('Cache-Control', 'no-store');
    const ip = getClientIp(req);

    // ── verify-email: ยืนยัน email (?action=verify-email&token=xxx) ──
    if (action === 'verify-email') {
        const { token } = req.query;

        try {
            if (await checkRateLimit(`ip:${ip}:verify-email`, 10, 60_000)) {
                auditLog('VERIFY_EMAIL_RATE_LIMIT', { ip });
                return res.redirect('/login?error=rate_limit');
            }
        } catch (rlErr) {
            console.error('[WARN] rate-limit DB error (verify-email), failing open:', rlErr.message);
        }

        if (!token || typeof token !== 'string' || !TOKEN_REGEX.test(token)) {
            return res.redirect('/login?error=invalid_token');
        }

        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        const client    = await pool.connect();
        try {
            await client.query('BEGIN');

            const verifyRes = await client.query(
                `SELECT ev.id, ev.user_id, ev.expires_at, u.email_verified
                 FROM email_verifications ev
                 JOIN users u ON u.id = ev.user_id
                 WHERE ev.token_hash = $1 FOR UPDATE`,
                [tokenHash]
            );

            if (!verifyRes.rows[0]) {
                await client.query('ROLLBACK');
                return res.redirect('/login?error=invalid_token');
            }

            const row = verifyRes.rows[0];

            if (new Date() > new Date(row.expires_at)) {
                await client.query('DELETE FROM email_verifications WHERE id = $1', [row.id]);
                await client.query('COMMIT');
                auditLog('VERIFY_EMAIL_EXPIRED', { ip });
                return res.redirect('/login?error=token_expired');
            }

            if (row.email_verified) {
                await client.query('DELETE FROM email_verifications WHERE id = $1', [row.id]);
                await client.query('COMMIT');
                return res.redirect('/login?verified=1');
            }

            await client.query('UPDATE users SET email_verified = TRUE WHERE id = $1', [row.user_id]);
            await client.query('DELETE FROM email_verifications WHERE id = $1', [row.id]);
            await client.query('COMMIT');

            auditLog('VERIFY_EMAIL_SUCCESS', { userId: row.user_id, ip });
            return res.redirect('/login?verified=1');

        } catch (err) {
            try { await client.query('ROLLBACK'); } catch { /* ignore */ }
            console.error('[ERROR] auth get verify-email:', err);
            return res.redirect('/login?error=server_error');
        } finally {
            client.release();
        }
    }

    // ── poll-verified: PC polling ว่า user verify email แล้วหรือยัง ──
    if (action === 'poll-verified') {
        if (!username || typeof username !== 'string' || username.length > 32 || !USER_REGEX.test(username)) {
            return res.status(400).json({ error: 'Invalid username' });
        }

        try {
            if (await checkRateLimit(`ip:${ip}:poll-verified`, 30, 60_000)) {
                return res.status(429).json({ error: 'Too many requests' });
            }
        } catch (rlErr) {
            console.error('[WARN] rate-limit DB error (poll-verified), failing open:', rlErr.message);
        }

        try {
            const result = await pool.query(
                'SELECT email_verified FROM users WHERE username = $1',
                [username]
            );
            const verified = result.rows[0]?.email_verified === true;
            return res.status(200).json({ verified });
        } catch (err) {
            console.error('[ERROR] auth get poll-verified:', err);
            return res.status(500).json({ error: 'Server error' });
        }
    }

    return res.status(405).send();
}

