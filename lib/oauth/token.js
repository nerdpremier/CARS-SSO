import { pool } from '../db.js';
import { checkRateLimit } from '../rate-limit.js';
import crypto from 'crypto';
import { auditLog, requireJson } from '../response-utils.js';
import { DEFAULT_SCOPE, hashToken, hashClientSecret, safeHexEqual } from './shared.js';

const ACCESS_TOKEN_TTL_SECONDS = 3600;
const REFRESH_TOKEN_TTL_DAYS   = 30;

// แลก authorization_code → access_token + refresh_token หรือ refresh_token rotation
export async function handleToken(req, res, ip) {
    if (req.method !== 'POST') return res.status(405).send();
    if (!requireJson(req, res)) return;

    try {
        if (await checkRateLimit(`ip:${ip}:oauth-token`, 20, 60_000)) {
            auditLog('OAUTH_TOKEN_RATE_LIMIT', { ip });
            return res.status(429).json({ error: 'too_many_requests' });
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit error (oauth-token), failing open:', rlErr.message);
    }

    const { grant_type, code, redirect_uri, client_id, client_secret,
            code_verifier, refresh_token } = req.body;

    if (!grant_type || !['authorization_code', 'refresh_token'].includes(grant_type))
        return res.status(400).json({ error: 'unsupported_grant_type' });
    if (!client_id     || typeof client_id     !== 'string' || client_id.length     > 128) return res.status(400).json({ error: 'invalid_request: client_id is required' });
    if (!client_secret || typeof client_secret !== 'string' || client_secret.length > 256) return res.status(400).json({ error: 'invalid_request: client_secret is required' });

    const tokenClient = await pool.connect();
    try {
        await tokenClient.query('BEGIN');

        // ── ตรวจ client credentials ─────────────────────────
        const clientResult = await tokenClient.query(
            'SELECT client_secret_hash FROM oauth_clients WHERE client_id = $1',
            [client_id]
        );
        if (clientResult.rows.length === 0) {
            await tokenClient.query('ROLLBACK');
            auditLog('OAUTH_TOKEN_INVALID_CLIENT', { clientId: client_id, ip });
            hashClientSecret(client_secret); // dummy ป้องกัน timing attack
            return res.status(401).json({ error: 'invalid_client' });
        }
        if (!safeHexEqual(clientResult.rows[0].client_secret_hash, hashClientSecret(client_secret))) {
            await tokenClient.query('ROLLBACK');
            auditLog('OAUTH_TOKEN_WRONG_SECRET', { clientId: client_id, ip });
            return res.status(401).json({ error: 'invalid_client' });
        }

        // ══════════════════════════════════════════════════════
        // GRANT: authorization_code
        // ══════════════════════════════════════════════════════
        if (grant_type === 'authorization_code') {
            if (!code         || typeof code         !== 'string' || code.length         > 128) return res.status(400).json({ error: 'invalid_request: code is required' });
            if (!redirect_uri || typeof redirect_uri !== 'string' || redirect_uri.length > 512) return res.status(400).json({ error: 'invalid_request: redirect_uri is required' });

            // FOR UPDATE: lock row ป้องกัน concurrent redemption race condition
            const codeHash   = hashToken(code);
            const codeResult = await tokenClient.query(
                `SELECT id, username, redirect_uri, scope, expires_at, used,
                        code_challenge, code_challenge_method
                 FROM oauth_codes WHERE code_hash = $1 AND client_id = $2 FOR UPDATE`,
                [codeHash, client_id]
            );

            if (codeResult.rows.length === 0) {
                await tokenClient.query('ROLLBACK');
                auditLog('OAUTH_TOKEN_INVALID_CODE', { clientId: client_id, ip });
                return res.status(400).json({ error: 'invalid_grant' });
            }

            const codeRow = codeResult.rows[0];

            if (codeRow.used) {
                await tokenClient.query('ROLLBACK');
                auditLog('OAUTH_TOKEN_CODE_REUSE', {
                    clientId: client_id, username: codeRow.username, ip, note: 'possible code interception'
                });
                return res.status(400).json({ error: 'invalid_grant: code already used' });
            }
            if (new Date() > new Date(codeRow.expires_at)) {
                await tokenClient.query('ROLLBACK');
                return res.status(400).json({ error: 'invalid_grant: code has expired' });
            }
            if (codeRow.redirect_uri !== redirect_uri) {
                await tokenClient.query('ROLLBACK');
                auditLog('OAUTH_TOKEN_URI_MISMATCH', { clientId: client_id, ip });
                return res.status(400).json({ error: 'invalid_grant: redirect_uri mismatch' });
            }

            // ── PKCE verification (RFC 7636 S256) ─────────────
            if (codeRow.code_challenge) {
                if (!code_verifier || typeof code_verifier !== 'string' ||
                    code_verifier.length < 43 || code_verifier.length > 128) {
                    await tokenClient.query('ROLLBACK');
                    auditLog('OAUTH_TOKEN_PKCE_MISSING', { clientId: client_id, ip });
                    return res.status(400).json({ error: 'invalid_grant: code_verifier missing or invalid' });
                }
                const verifierHash = crypto
                    .createHash('sha256')
                    .update(code_verifier)
                    .digest('base64url');
                let pkceMatch = false;
                try {
                    const verifierBuf  = Buffer.from(verifierHash,           'utf8');
                    const challengeBuf = Buffer.from(codeRow.code_challenge, 'utf8');
                    pkceMatch = verifierBuf.length === challengeBuf.length &&
                        crypto.timingSafeEqual(verifierBuf, challengeBuf);
                } catch {
                    pkceMatch = false;
                }
                if (!pkceMatch) {
                    await tokenClient.query('ROLLBACK');
                    auditLog('OAUTH_TOKEN_PKCE_FAIL', { clientId: client_id, ip });
                    return res.status(400).json({ error: 'invalid_grant: code_verifier mismatch' });
                }
            }

            await tokenClient.query('UPDATE oauth_codes SET used = TRUE WHERE id = $1', [codeRow.id]);

            const scope       = codeRow.scope || DEFAULT_SCOPE;
            const accessToken = crypto.randomBytes(32).toString('hex');
            const accessHash  = hashToken(accessToken);
            const accessExp   = new Date(Date.now() + ACCESS_TOKEN_TTL_SECONDS * 1000);

            await tokenClient.query(
                `INSERT INTO oauth_tokens (token_hash, token_type, client_id, username, scope, expires_at)
                 VALUES ($1, 'access', $2, $3, $4, $5)`,
                [accessHash, client_id, codeRow.username, scope, accessExp]
            );

            const refreshToken = crypto.randomBytes(32).toString('hex');
            const refreshHash  = hashToken(refreshToken);
            const refreshExp   = new Date(Date.now() + REFRESH_TOKEN_TTL_DAYS * 86400 * 1000);

            await tokenClient.query(
                `INSERT INTO oauth_tokens (token_hash, token_type, client_id, username, scope, expires_at)
                 VALUES ($1, 'refresh', $2, $3, $4, $5)`,
                [refreshHash, client_id, codeRow.username, scope, refreshExp]
            );

            await tokenClient.query('COMMIT');
            auditLog('OAUTH_TOKEN_ISSUED', { clientId: client_id, username: codeRow.username, scope, ip });

            return res.status(200).json({
                access_token:  accessToken,
                token_type:    'Bearer',
                expires_in:    ACCESS_TOKEN_TTL_SECONDS,
                refresh_token: refreshToken,
                scope:         scope.join(' '),
            });
        }

        // ══════════════════════════════════════════════════════
        // GRANT: refresh_token (single-use rotation)
        // ══════════════════════════════════════════════════════
        if (grant_type === 'refresh_token') {
            if (!refresh_token || typeof refresh_token !== 'string' || refresh_token.length > 128) {
                await tokenClient.query('ROLLBACK');
                return res.status(400).json({ error: 'invalid_request: refresh_token is required' });
            }

            const rtHash  = hashToken(refresh_token);
            const rtResult = await tokenClient.query(
                `SELECT id, username, scope, expires_at, revoked_at, client_id
                 FROM oauth_tokens
                 WHERE token_hash = $1 AND token_type = 'refresh' AND client_id = $2 FOR UPDATE`,
                [rtHash, client_id]
            );

            if (rtResult.rows.length === 0) {
                await tokenClient.query('ROLLBACK');
                auditLog('OAUTH_REFRESH_INVALID', { clientId: client_id, ip });
                return res.status(400).json({ error: 'invalid_grant' });
            }

            const rt = rtResult.rows[0];

            if (rt.revoked_at) {
                await tokenClient.query('ROLLBACK');
                try {
                    await pool.query(
                        `UPDATE oauth_tokens SET revoked_at = NOW()
                         WHERE client_id = $1 AND username = $2 AND revoked_at IS NULL`,
                        [client_id, rt.username]
                    );
                } catch (revokeErr) {
                    console.error('[ERROR] oauth refresh reuse revoke-all failed:', revokeErr.message);
                }
                auditLog('OAUTH_REFRESH_REUSE_REVOKE_ALL', {
                    clientId: client_id, username: rt.username, ip, note: 'possible token theft'
                });
                return res.status(400).json({ error: 'invalid_grant: refresh_token already used' });
            }
            if (new Date() > new Date(rt.expires_at)) {
                await tokenClient.query('ROLLBACK');
                return res.status(400).json({ error: 'invalid_grant: refresh_token has expired' });
            }

            await tokenClient.query(
                'UPDATE oauth_tokens SET revoked_at = NOW() WHERE id = $1',
                [rt.id]
            );

            const scope       = rt.scope || DEFAULT_SCOPE;
            const accessToken = crypto.randomBytes(32).toString('hex');
            const accessHash  = hashToken(accessToken);
            const accessExp   = new Date(Date.now() + ACCESS_TOKEN_TTL_SECONDS * 1000);

            await tokenClient.query(
                `INSERT INTO oauth_tokens (token_hash, token_type, client_id, username, scope, expires_at)
                 VALUES ($1, 'access', $2, $3, $4, $5)`,
                [accessHash, client_id, rt.username, scope, accessExp]
            );

            const newRefreshToken = crypto.randomBytes(32).toString('hex');
            const newRefreshHash  = hashToken(newRefreshToken);
            const newRefreshExp   = new Date(Date.now() + REFRESH_TOKEN_TTL_DAYS * 86400 * 1000);

            await tokenClient.query(
                `INSERT INTO oauth_tokens (token_hash, token_type, client_id, username, scope, expires_at)
                 VALUES ($1, 'refresh', $2, $3, $4, $5)`,
                [newRefreshHash, client_id, rt.username, scope, newRefreshExp]
            );

            await tokenClient.query('COMMIT');
            auditLog('OAUTH_TOKEN_REFRESHED', { clientId: client_id, username: rt.username, ip });

            return res.status(200).json({
                access_token:  accessToken,
                token_type:    'Bearer',
                expires_in:    ACCESS_TOKEN_TTL_SECONDS,
                refresh_token: newRefreshToken,
                scope:         scope.join(' '),
            });
        }

    } catch (err) {
        try { await tokenClient.query('ROLLBACK'); } catch { /* ignore */ }
        console.error('[ERROR] oauth token:', err);
        return res.status(500).json({ error: 'server_error' });
    } finally {
        tokenClient.release();
    }
}

