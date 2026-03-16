import { pool } from '../db.js';
import { checkRateLimit } from '../rate-limit.js';
import crypto from 'crypto';
import { auditLog, requireJson } from '../response-utils.js';
import { DEFAULT_SCOPE, VALID_SCOPES, hashClientSecret, verifySessionCookie } from './shared.js';

const MAX_CLIENTS_PER_USER = 10;

// Developer Portal API: ลงทะเบียน / ดู / ลบ client app
// Auth: session_token cookie (same-origin จาก developer-portal.html)
export async function handleClients(req, res, ip) {
    try {
        if (await checkRateLimit(`ip:${ip}:oauth-clients`, 20, 60_000)) {
            auditLog('OAUTH_CLIENTS_RATE_LIMIT', { ip });
            return res.status(429).json({ error: 'Too many requests. Please try again later.' });
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit error (oauth-clients), failing open:', rlErr.message);
    }

    const decoded = await verifySessionCookie(req);
    if (!decoded) {
        return res.status(401).json({ error: 'Unauthorized. Please sign in first.' });
    }
    const username = decoded.username;

    try {
        // ── POST: สร้าง client app ─────────────────────────
        if (req.method === 'POST') {
            if (!requireJson(req, res)) return;
            const { name, redirect_uris, allowed_scopes: reqScopes } = req.body;

            if (typeof name !== 'string' || !name.trim() || name.length > 128)
                return res.status(400).json({ error: 'App name must be a non-empty string (max 128 characters)' });

            if (!Array.isArray(redirect_uris) || redirect_uris.length === 0 || redirect_uris.length > 10)
                return res.status(400).json({ error: 'redirect_uris must be an array with 1-10 entries' });

            for (const uri of redirect_uris) {
                if (typeof uri !== 'string' || uri.length > 512)
                    return res.status(400).json({ error: 'Each redirect_uri must be a string (max 512 characters)' });
                let parsed;
                try { parsed = new URL(uri); } catch {
                    return res.status(400).json({ error: 'One or more redirect_uris has an invalid URL format' });
                }
                const isLocalhost = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';
                if (parsed.protocol !== 'https:' && !isLocalhost)
                    return res.status(400).json({ error: 'All redirect_uris must use HTTPS (or localhost for development)' });
            }

            // Validate allowed_scopes (optional — default ['profile'])
            let allowedScopes = DEFAULT_SCOPE;
            if (reqScopes !== undefined) {
                if (!Array.isArray(reqScopes) || reqScopes.some(s => !VALID_SCOPES.has(s)))
                    return res.status(400).json({ error: `allowed_scopes contains invalid values — supported: ${[...VALID_SCOPES].join(', ')}` });
                allowedScopes = reqScopes.length > 0 ? reqScopes : DEFAULT_SCOPE;
            }

            const countRow = await pool.query(
                'SELECT COUNT(*) FROM oauth_clients WHERE owner_username = $1', [username]
            );
            if (parseInt(countRow.rows[0].count, 10) >= MAX_CLIENTS_PER_USER)
                return res.status(400).json({ error: `Maximum ${MAX_CLIENTS_PER_USER} apps per account` });

            const clientId     = 'c_' + crypto.randomBytes(16).toString('hex');
            const clientSecret = crypto.randomBytes(32).toString('hex');
            const secretHash   = hashClientSecret(clientSecret);

            await pool.query(
                `INSERT INTO oauth_clients (client_id, client_secret_hash, name, redirect_uris, allowed_scopes, owner_username)
                 VALUES ($1, $2, $3, $4, $5, $6)`,
                [clientId, secretHash, name.trim(), redirect_uris, allowedScopes, username]
            );

            auditLog('OAUTH_CLIENT_CREATED', { username, clientId, ip });
            return res.status(201).json({
                client_id:      clientId,
                client_secret:  clientSecret,
                name:           name.trim(),
                redirect_uris,
                allowed_scopes: allowedScopes,
                notice:         '⚠️ Save your client_secret now — it cannot be retrieved again'
            });
        }

        // ── GET: ดูรายการ ──────────────────────────────────
        if (req.method === 'GET') {
            const result = await pool.query(
                `SELECT client_id, name, redirect_uris, allowed_scopes, created_at
                 FROM oauth_clients WHERE owner_username = $1 ORDER BY created_at DESC`,
                [username]
            );
            return res.status(200).json({ clients: result.rows });
        }

        // ── PATCH: Rotate client_secret ────────────────────
        if (req.method === 'PATCH') {
            if (!requireJson(req, res)) return;
            const { client_id } = req.body;
            if (!client_id || typeof client_id !== 'string' || client_id.length > 128)
                return res.status(400).json({ error: 'client_id is required' });

            const newSecret     = crypto.randomBytes(32).toString('hex');
            const newSecretHash = hashClientSecret(newSecret);

            const rotateClient = await pool.connect();
            try {
                await rotateClient.query('BEGIN');

                const result = await rotateClient.query(
                    `UPDATE oauth_clients SET client_secret_hash = $1
                     WHERE client_id = $2 AND owner_username = $3
                     RETURNING client_id`,
                    [newSecretHash, client_id, username]
                );
                if (result.rowCount === 0) {
                    await rotateClient.query('ROLLBACK');
                    return res.status(404).json({ error: 'App not found or does not belong to you' });
                }

                // Revoke token ทั้งหมดของ client นี้ — บังคับ re-auth
                await rotateClient.query(
                    `UPDATE oauth_tokens SET revoked_at = NOW()
                     WHERE client_id = $1 AND revoked_at IS NULL`,
                    [client_id]
                );

                await rotateClient.query('COMMIT');
                auditLog('OAUTH_CLIENT_SECRET_ROTATED', { username, clientId: client_id, ip });
                return res.status(200).json({
                    client_id,
                    client_secret: newSecret,
                    notice:        '⚠️ New secret issued — all previous tokens have been revoked'
                });
            } catch (err) {
                try { await rotateClient.query('ROLLBACK'); } catch { /* ignore */ }
                throw err;
            } finally {
                rotateClient.release();
            }
        }

        // ── DELETE: ลบ client app ──────────────────────────
        if (req.method === 'DELETE') {
            if (!requireJson(req, res)) return;
            const { client_id } = req.body;
            if (!client_id || typeof client_id !== 'string' || client_id.length > 128)
                return res.status(400).json({ error: 'client_id is required' });

            const deleteClient = await pool.connect();
            try {
                await deleteClient.query('BEGIN');

                const ownerCheck = await deleteClient.query(
                    'SELECT client_id FROM oauth_clients WHERE client_id = $1 AND owner_username = $2',
                    [client_id, username]
                );
                if (ownerCheck.rowCount === 0) {
                    await deleteClient.query('ROLLBACK');
                    return res.status(404).json({ error: 'App not found or does not belong to you' });
                }

                await deleteClient.query(
                    `UPDATE oauth_tokens SET revoked_at = NOW()
                     WHERE client_id = $1 AND revoked_at IS NULL`,
                    [client_id]
                );

                await deleteClient.query(
                    'DELETE FROM oauth_clients WHERE client_id = $1 AND owner_username = $2',
                    [client_id, username]
                );

                await deleteClient.query('COMMIT');
            } catch (err) {
                try { await deleteClient.query('ROLLBACK'); } catch { /* ignore */ }
                throw err;
            } finally {
                deleteClient.release();
            }

            auditLog('OAUTH_CLIENT_DELETED', { username, clientId: client_id, ip });
            return res.status(200).json({ success: true });
        }

        return res.status(405).json({ error: 'Method not allowed' });
    } catch (err) {
        console.error('[ERROR] oauth clients:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
}

