import { pool } from '../db.js';
import { checkRateLimit } from '../rate-limit.js';
import crypto from 'crypto';
import { auditLog } from '../response-utils.js';
import { DEFAULT_SCOPE, hashToken } from './shared.js';

export async function handleUserinfo(req, res, ip) {
    if (req.method !== 'GET') return res.status(405).send();

    try {
        if (await checkRateLimit(`ip:${ip}:oauth-userinfo`, 120, 60_000)) {
            auditLog('OAUTH_USERINFO_RATE_LIMIT', { ip });
            return res.status(429).json({ error: 'too_many_requests' });
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit error (oauth-userinfo), failing open:', rlErr.message);
    }

    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
        res.setHeader('WWW-Authenticate', 'Bearer realm="oauth", error="invalid_token"');
        return res.status(401).json({ error: 'invalid_token' });
    }
    const token = authHeader.slice(7).trim();
    if (!token || token.length > 128) {
        res.setHeader('WWW-Authenticate', 'Bearer realm="oauth", error="invalid_token"');
        return res.status(401).json({ error: 'invalid_token' });
    }

    // Probabilistic cleanup: 2% ต่อ request
    if (crypto.randomInt(100) < 2) {
        pool.query(`DELETE FROM oauth_tokens WHERE expires_at < NOW()`)
            .catch(err => console.error('[WARN] oauth_tokens cleanup error:', err.message));
        pool.query(`DELETE FROM oauth_codes WHERE expires_at < NOW() AND used = TRUE`)
            .catch(err => console.error('[WARN] oauth_codes cleanup error:', err.message));
    }

    try {
        const result = await pool.query(
            `SELECT ot.username, ot.client_id, ot.expires_at, ot.revoked_at, ot.scope,
                    u.email, u.id AS user_id, u.email_verified
             FROM oauth_tokens ot
             JOIN users u ON u.username = ot.username
             WHERE ot.token_hash = $1 AND ot.token_type = 'access'`,
            [hashToken(token)]
        );

        if (result.rows.length === 0) {
            res.setHeader('WWW-Authenticate', 'Bearer realm="oauth", error="invalid_token"');
            return res.status(401).json({ error: 'invalid_token' });
        }

        const row = result.rows[0];

        if (row.revoked_at) {
            auditLog('OAUTH_USERINFO_REVOKED_TOKEN', { clientId: row.client_id, ip });
            res.setHeader('WWW-Authenticate', 'Bearer realm="oauth", error="invalid_token"');
            return res.status(401).json({ error: 'invalid_token' });
        }
        if (new Date() > new Date(row.expires_at)) {
            res.setHeader('WWW-Authenticate',
                'Bearer realm="oauth", error="invalid_token", error_description="token expired"');
            return res.status(401).json({ error: 'invalid_token' });
        }

        // ── Scope-aware response ───────────────────────────
        const scope    = row.scope || DEFAULT_SCOPE;
        const response = {};

        if (scope.includes('openid'))  response.sub      = String(row.user_id);
        if (scope.includes('profile')) response.username = row.username;
        if (scope.includes('email') && row.email_verified)
            response.email = row.email;

        return res.status(200).json(response);

    } catch (err) {
        console.error('[ERROR] oauth userinfo:', err);
        return res.status(500).json({ error: 'server_error' });
    }
}

