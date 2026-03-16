import { pool } from '../db.js';
import { checkRateLimit } from '../rate-limit.js';
import { auditLog, requireJson } from '../response-utils.js';
import { hashToken, hashClientSecret, safeHexEqual } from './shared.js';

// RFC 7009 token revoke
export async function handleRevoke(req, res, ip) {
    if (req.method !== 'POST') return res.status(405).send();
    if (!requireJson(req, res)) return;

    try {
        if (await checkRateLimit(`ip:${ip}:oauth-revoke`, 20, 60_000)) {
            return res.status(429).json({ error: 'too_many_requests' });
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit error (oauth-revoke), failing open:', rlErr.message);
    }

    const { token, client_id, client_secret } = req.body;

    if (!token         || typeof token         !== 'string' || token.length         > 128) return res.status(400).json({ error: 'invalid_request: token is required' });
    if (!client_id     || typeof client_id     !== 'string' || client_id.length     > 128) return res.status(400).json({ error: 'invalid_request: client_id is required' });
    if (!client_secret || typeof client_secret !== 'string' || client_secret.length > 256) return res.status(400).json({ error: 'invalid_request: client_secret is required' });

    try {
        const clientResult = await pool.query(
            'SELECT client_secret_hash FROM oauth_clients WHERE client_id = $1', [client_id]
        );
        if (clientResult.rows.length === 0) {
            hashClientSecret(client_secret); // dummy
            return res.status(401).json({ error: 'invalid_client' });
        }
        if (!safeHexEqual(clientResult.rows[0].client_secret_hash, hashClientSecret(client_secret))) {
            auditLog('OAUTH_REVOKE_WRONG_SECRET', { clientId: client_id, ip });
            return res.status(401).json({ error: 'invalid_client' });
        }

        const targetHash = hashToken(token);
        const tokenRow = await pool.query(
            `SELECT username, token_type FROM oauth_tokens
             WHERE token_hash = $1 AND client_id = $2`,
            [targetHash, client_id]
        );

        if (tokenRow.rows.length > 0) {
            const { username: tokenUsername } = tokenRow.rows[0];
            const result = await pool.query(
                `UPDATE oauth_tokens SET revoked_at = NOW()
                 WHERE client_id = $1 AND username = $2 AND revoked_at IS NULL`,
                [client_id, tokenUsername]
            );
            if (result.rowCount > 0) auditLog('OAUTH_TOKEN_REVOKED', { clientId: client_id, username: tokenUsername, ip });
        }

        return res.status(200).json({ success: true });

    } catch (err) {
        console.error('[ERROR] oauth revoke:', err);
        return res.status(500).json({ error: 'server_error' });
    }
}

