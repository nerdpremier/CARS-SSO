import { pool } from '../db.js';
import { checkRateLimit } from '../rate-limit.js';
import { auditLog } from '../response-utils.js';
import { hashToken } from './shared.js';

// One-time sso_token exchange
export async function handleSsoExchange(req, res, ip) {
    if (req.method !== 'GET') return res.status(405).send();

    try {
        if (await checkRateLimit(`ip:${ip}:sso-exchange`, 30, 60_000)) {
            auditLog('SSO_EXCHANGE_RATE_LIMIT', { ip });
            return res.status(429).json({ error: 'too_many_requests' });
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit error (sso-exchange), failing open:', rlErr.message);
    }

    const { token } = req.query;
    if (!token || typeof token !== 'string' || token.length > 36) {
        return res.status(400).json({ error: 'invalid_request: missing or invalid token' });
    }

    const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (!UUID_REGEX.test(token)) {
        return res.status(400).json({ error: 'invalid_request: invalid token format' });
    }

    const tokenHash = hashToken(token);

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const result = await client.query(
            `SELECT st.id, st.user_id, st.used, st.expires_at, u.username, u.email, u.email_verified
             FROM sso_tokens st
             JOIN users u ON u.id = st.user_id
             WHERE st.token = $1 FOR UPDATE`,
            [tokenHash]
        );

        if (result.rows.length === 0) {
            await client.query('ROLLBACK');
            auditLog('SSO_EXCHANGE_INVALID', { ip });
            return res.status(400).json({ error: 'invalid_token' });
        }

        const row = result.rows[0];

        if (row.used) {
            await client.query('ROLLBACK');
            auditLog('SSO_EXCHANGE_REUSE', { username: row.username, ip, note: 'possible token theft' });
            return res.status(400).json({ error: 'invalid_token: token already used' });
        }

        if (new Date() > new Date(row.expires_at)) {
            await client.query('ROLLBACK');
            auditLog('SSO_EXCHANGE_EXPIRED', { ip });
            return res.status(400).json({ error: 'invalid_token: token has expired' });
        }

        await client.query(
            'UPDATE sso_tokens SET used = TRUE WHERE id = $1',
            [row.id]
        );

        await client.query('COMMIT');
        auditLog('SSO_EXCHANGE_SUCCESS', { username: row.username, ip });

        return res.status(200).json({
            user_id:  row.user_id,
            username: row.username,
            ...(row.email_verified ? { email: row.email } : {}),
        });

    } catch (err) {
        try { await client.query('ROLLBACK'); } catch { /* ignore */ }
        console.error('[ERROR] oauth sso-exchange:', err);
        return res.status(500).json({ error: 'server_error' });
    } finally {
        client.release();
    }
}

