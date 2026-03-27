import '../startup-check.js';
import { pool }           from '../lib/db.js';
import { checkRateLimit } from '../lib/rate-limit.js';
import { getClientIp }    from '../lib/ip-utils.js';
import jwt    from 'jsonwebtoken';
import { parse } from 'cookie';
import { auditLog } from '../lib/response-utils.js';
import { ensureBehaviorRisksSchema, getCombinedConfig, ensureOAuthClientsSchema, ensureUserDevicesSchema } from '../lib/risk-score.js';
import crypto from 'crypto';

const USER_REGEX               = /^[a-zA-Z0-9]+$/;
const MAX_CLIENTS_PER_USER     = 10;
const CODE_TTL_MINUTES         = 10;
const ACCESS_TOKEN_TTL_SECONDS = 3600;
const REFRESH_TOKEN_TTL_DAYS   = 7;

const VALID_SCOPES = new Set(['profile', 'email', 'openid']);
const DEFAULT_SCOPE = ['profile'];

function parseScope(scopeStr, allowedScopes = [...VALID_SCOPES]) {
    if (!scopeStr || typeof scopeStr !== 'string') return DEFAULT_SCOPE;
    const requested = scopeStr.trim().split(/\s+/).filter(s => VALID_SCOPES.has(s));
    const allowed   = requested.filter(s => allowedScopes.includes(s));
    return allowed.length > 0 ? allowed : DEFAULT_SCOPE;
}

function hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
}

function hashClientSecret(secret) {
    return crypto
        .createHmac('sha256', process.env.OAUTH_SECRET_PEPPER)
        .update(secret)
        .digest('hex');
}

function safeHexEqual(a, b) {
    if (a.length !== b.length) return false;
    try {
        return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
    } catch {
        return false;
    }
}

function verifyBearerSession(req) {
    const auth = req.headers.authorization;
    if (!auth?.startsWith('Bearer ')) return null;
    const token = auth.slice(7);
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET, {
            issuer: process.env.BASE_URL, audience: 'b-sso-api'
        });
        if (!decoded.jti) return null;
        if (!decoded.username || typeof decoded.username !== 'string' ||
            decoded.username.length > 32 || !USER_REGEX.test(decoded.username)) return null;
        return decoded;
    } catch {
        return null;
    }
}

async function verifySessionCookie(req) {
    const cookies = parse(req.headers.cookie || '');
    const token   = cookies.session_token;
    if (!token) return null;

    let decoded;
    try {
        decoded = jwt.verify(token, process.env.JWT_SECRET, {
            issuer: process.env.BASE_URL, audience: 'b-sso-api'
        });
    } catch { return null; }

    if (!decoded.jti) return null;
    if (!decoded.username || typeof decoded.username !== 'string' ||
        decoded.username.length > 32 || !USER_REGEX.test(decoded.username)) return null;

    try {
        const result = await pool.query(
            `SELECT u.sessions_revoked_at, rt.jti AS revoked_jti
             FROM users u
             LEFT JOIN revoked_tokens rt ON rt.jti = $2 AND rt.expires_at > NOW()
             WHERE u.username = $1`,
            [decoded.username, decoded.jti]
        );
        if (result.rows.length === 0) return null;
        const { sessions_revoked_at, revoked_jti } = result.rows[0];
        if (revoked_jti) return null;
        if (sessions_revoked_at && typeof decoded.iat === 'number') {
            if (new Date(decoded.iat * 1000) < new Date(sessions_revoked_at)) return null;
        }
    } catch (dbErr) {
        console.error('[WARN] oauth.js verifySessionCookie DB error:', dbErr.message);
        return null;
    }

    return decoded;
}

function setSecurityHeaders(res, framePolicy = 'DENY') {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', framePolicy);
    res.setHeader('Content-Security-Policy', "default-src 'none'");
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
    res.setHeader('Cache-Control', 'no-store, no-cache');
    res.setHeader('Pragma', 'no-cache');
}

function requireJson(req, res) {
    if (!req.headers['content-type']?.includes('application/json')) {
        res.status(415).json({ error: 'Content-Type must be application/json' });
        return false;
    }
    if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
        res.status(400).json({ error: 'Invalid request body' });
        return false;
    }
    return true;
}

async function handleClients(req, res, ip) {
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
        if (req.method === 'POST') {
            if (!requireJson(req, res)) return;
            const { name, redirect_uris, allowed_scopes: reqScopes, client_type: reqClientType } = req.body;

            if (typeof name !== 'string' || !name.trim() || name.length > 128)
                return res.status(400).json({ error: 'App name must be a non-empty string (max 128 characters)' });

            if (!Array.isArray(redirect_uris) || redirect_uris.length === 0 || redirect_uris.length > 10)
                return res.status(400).json({ error: 'redirect_uris must be an array with 1-10 entries' });

            for (const uri of redirect_uris) {
                if (typeof uri !== 'string' || uri.length > 512)
                    return res.status(400).json({ error: `Invalid redirect_uri: ${uri}` });
                let parsed;
                try { parsed = new URL(uri); } catch {
                    return res.status(400).json({ error: `Invalid redirect_uri format: ${uri}` });
                }
                const isLocalhost = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';
                if (parsed.protocol !== 'https:' && !isLocalhost)
                    return res.status(400).json({ error: `redirect_uri must use HTTPS (or localhost for dev): ${uri}` });
            }

            let allowedScopes = DEFAULT_SCOPE;
            if (reqScopes !== undefined) {
                if (!Array.isArray(reqScopes) || reqScopes.some(s => !VALID_SCOPES.has(s)))
                    return res.status(400).json({ error: `allowed_scopes contains invalid values — supported: ${[...VALID_SCOPES].join(', ')}` });
                allowedScopes = reqScopes.length > 0 ? reqScopes : DEFAULT_SCOPE;
            }

            const clientType = (reqClientType === 'public') ? 'public' : 'confidential';

            const countRow = await pool.query(
                'SELECT COUNT(*) FROM oauth_clients WHERE owner_username = $1', [username]
            );
            if (parseInt(countRow.rows[0].count, 10) >= MAX_CLIENTS_PER_USER)
                return res.status(400).json({ error: `Maximum ${MAX_CLIENTS_PER_USER} apps per account` });

            const clientId = 'c_' + crypto.randomBytes(16).toString('hex');

            let clientSecret = null;
            let secretHash = '';
            if (clientType === 'confidential') {
                clientSecret = crypto.randomBytes(32).toString('hex');
                secretHash = hashClientSecret(clientSecret);
            }

            await pool.query(
                `INSERT INTO oauth_clients (client_id, client_secret_hash, name, redirect_uris, allowed_scopes, client_type, owner_username)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
                [clientId, secretHash, name.trim(), redirect_uris, allowedScopes, clientType, username]
            );

            auditLog('OAUTH_CLIENT_CREATED', { username, clientId, clientType, ip });
            const response = {
                client_id:      clientId,
                client_type:    clientType,
                name:           name.trim(),
                redirect_uris,
                allowed_scopes: allowedScopes,
            };
            if (clientSecret) {
                response.client_secret = clientSecret;
                response.notice = 'Save your client_secret now — it cannot be retrieved again';
            }
            return res.status(201).json(response);
        }

        if (req.method === 'GET') {
            const result = await pool.query(
                `SELECT client_id, name, redirect_uris, allowed_scopes, client_type, created_at
                 FROM oauth_clients WHERE owner_username = $1 ORDER BY created_at DESC`,
                [username]
            );
            return res.status(200).json({ clients: result.rows });
        }

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
                    notice:        ' New secret issued — all previous tokens have been revoked'
                });
            } catch (err) {
                try { await rotateClient.query('ROLLBACK'); } catch { }
                throw err;
            } finally {
                rotateClient.release();
            }
        }

        if (req.method === 'DELETE') {
            if (!requireJson(req, res)) return;
            const { client_id } = req.body;
            if (!client_id || typeof client_id !== 'string' || client_id.length > 128)
                return res.status(400).json({ error: 'client_id is required' });

            const result = await pool.query(
                'DELETE FROM oauth_clients WHERE client_id = $1 AND owner_username = $2',
                [client_id, username]
            );
            if (result.rowCount === 0)
                return res.status(404).json({ error: 'App not found or does not belong to you' });

            auditLog('OAUTH_CLIENT_DELETED', { username, clientId: client_id, ip });
            return res.status(200).json({ success: true });
        }

        return res.status(405).json({ error: 'Method not allowed' });
    } catch (err) {
        console.error('[ERROR] oauth.js handleClients:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
}

async function handleAuthorize(req, res, ip) {
    try {
        if (await checkRateLimit(`ip:${ip}:oauth-authorize`, 30, 60_000)) {
            auditLog('OAUTH_AUTHORIZE_RATE_LIMIT', { ip });
            return res.status(429).json({ error: 'Too many requests. Please try again later.' });
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit error (oauth-authorize), failing open:', rlErr.message);
    }
    await ensureBehaviorRisksSchema();
    await ensureOAuthClientsSchema();
    await ensureUserDevicesSchema();

    if (req.method === 'GET') {
        const { client_id, redirect_uri, response_type, state, scope,
                code_challenge, code_challenge_method, pre_login_log_id,
                device: deviceParam, fingerprint: fingerprintParam } = req.query;

        if (response_type !== 'code')
            return res.status(400).json({ error: 'unsupported_response_type' });
        if (!client_id || typeof client_id !== 'string' || client_id.length > 128)
            return res.status(400).json({ error: 'invalid_request: missing or invalid client_id' });
        if (!redirect_uri || typeof redirect_uri !== 'string' || redirect_uri.length > 512)
            return res.status(400).json({ error: 'invalid_request: missing or invalid redirect_uri' });
        if (!state || typeof state !== 'string' || state.length > 256)
            return res.status(400).json({ error: 'invalid_request: missing or invalid state' });

        if (code_challenge !== undefined) {
            if (code_challenge_method !== 'S256')
                return res.status(400).json({ error: 'invalid_request: code_challenge_method must be S256' });
            if (typeof code_challenge !== 'string' || code_challenge.length < 43 || code_challenge.length > 128)
                return res.status(400).json({ error: 'invalid_request: invalid code_challenge' });
        }

        let clientResult;
        try {
            clientResult = await pool.query(
                'SELECT name, redirect_uris, allowed_scopes, client_type FROM oauth_clients WHERE client_id = $1',
                [client_id]
            );
        } catch (dbErr) {
            console.error('[ERROR] oauth.js handleAuthorize GET DB:', dbErr.message);
            return res.status(500).json({ error: 'Internal server error' });
        }

        if (clientResult.rows.length === 0)
            return res.status(400).json({ error: 'invalid_client: unknown client_id' });

        const { name: appName, redirect_uris, allowed_scopes, client_type } = clientResult.rows[0];

        if (client_type === 'public' && !code_challenge) {
            auditLog('OAUTH_PKCE_REQUIRED', { clientId: client_id, ip });
            return res.status(400).json({ error: 'invalid_request: code_challenge required for public clients' });
        }

        if (!redirect_uris.includes(redirect_uri))
            return res.status(400).json({ error: 'invalid_redirect_uri: URI not registered' });

        const effectiveScope = parseScope(scope, allowed_scopes);

        const decoded = await verifySessionCookie(req);
        if (!decoded) {
            return res.status(401).json({ error: 'unauthenticated', app_name: appName });
        }

        let device = 'unknown';
        let fingerprint = 'unknown';

        console.log('[DEBUG] OAuth GET params device/fingerprint:', { deviceParam, fingerprintParam });

        if (deviceParam && typeof deviceParam === 'string') {
            device = deviceParam.slice(0, 256);
            console.log('[DEBUG] Using device from GET params:', device);
        }
        if (fingerprintParam && typeof fingerprintParam === 'string' && /^[a-f0-9-]{32,128}$/i.test(fingerprintParam)) {
            fingerprint = fingerprintParam.slice(0, 64);
            console.log('[DEBUG] Using fingerprint from GET params:', fingerprint);
        }

        if (device === 'unknown' || fingerprint === 'unknown') {
            try {
                const existingDeviceRes = await pool.query(
                    `SELECT COALESCE(device, 'unknown') as device, fingerprint FROM user_devices
                     WHERE username = $1
                       AND (device != 'unknown' OR device IS NULL)
                       AND fingerprint != 'unknown'
                     ORDER BY created_at DESC
                     LIMIT 1`,
                    [decoded.username]
                );
                if (existingDeviceRes.rows[0]) {
                    device = existingDeviceRes.rows[0].device;
                    fingerprint = existingDeviceRes.rows[0].fingerprint;
                    auditLog('OAUTH_REUSED_FROM_USER_DEVICES', {
                        username: decoded.username,
                        device,
                        fingerprint
                    });
                }
            } catch (e) {
            }
        }

        let preLoginLogId = null;
        const client = await pool.connect();

        try {
            await client.query('BEGIN');

            if (pre_login_log_id && /^\d+$/.test(pre_login_log_id)) {
                try {
                    const riskRes = await client.query(
                        `SELECT id, username FROM login_risks
                         WHERE id = $1 AND created_at > NOW() - INTERVAL '15 minutes'`,
                        [Number(pre_login_log_id)]
                    );
                    if (riskRes.rows[0] && riskRes.rows[0].username === decoded.username) {
                        preLoginLogId = riskRes.rows[0].id;
                    } else if (riskRes.rows[0] && riskRes.rows[0].username !== decoded.username) {
                        auditLog('OAUTH_PRELOGIN_USER_MISMATCH', {
                            expectedUser: decoded.username,
                            logIdOwner: riskRes.rows[0].username
                        });
                    }
                } catch (dbErr) {
            console.error('[ERROR] oauth.js handleAuthorize risk handling:', err);
            throw err;
        } finally {
            client.release();
        }

        auditLog('OAUTH_CONSENT_VIEW', { username: decoded.username, clientId: client_id, ip, preLoginLogId });
        return res.status(200).json({
            app_name: appName, client_id, redirect_uri, state,
            username: decoded.username,
            scope:    effectiveScope,
            pre_login_log_id: preLoginLogId,
        });
    }

    if (req.method === 'POST') {
        if (!requireJson(req, res)) return;
        const { client_id, redirect_uri, state, approved,
                scope, code_challenge, code_challenge_method, pre_login_log_id,
                device: deviceFromBody, fingerprint: fingerprintFromBody } = req.body;

        if (!client_id || typeof client_id !== 'string' || client_id.length > 128)
            return res.status(400).json({ error: 'invalid_request: missing or invalid client_id' });
        if (!redirect_uri || typeof redirect_uri !== 'string' || redirect_uri.length > 512)
            return res.status(400).json({ error: 'invalid_request: missing or invalid redirect_uri' });
        if (!state || typeof state !== 'string' || state.length > 256)
            return res.status(400).json({ error: 'invalid_request: missing or invalid state' });

        if (code_challenge !== undefined) {
            if (code_challenge_method !== 'S256')
                return res.status(400).json({ error: 'invalid_request: code_challenge_method must be S256' });
            if (typeof code_challenge !== 'string' || code_challenge.length < 43 || code_challenge.length > 128)
                return res.status(400).json({ error: 'invalid_request: invalid code_challenge' });
        }

        const decoded = await verifySessionCookie(req);
        if (!decoded) return res.status(401).json({ error: 'session_expired: please sign in again' });

        let device = 'unknown';
        let fingerprint = 'unknown';

        console.log('[DEBUG] OAuth POST body device/fingerprint:', { deviceFromBody, fingerprintFromBody });

        if (deviceFromBody && typeof deviceFromBody === 'string') {
            device = deviceFromBody.slice(0, 256);
            console.log('[DEBUG] Using device from body:', device);
        }
        if (fingerprintFromBody && typeof fingerprintFromBody === 'string' && /^[a-f0-9-]{32,128}$/i.test(fingerprintFromBody)) {
            fingerprint = fingerprintFromBody.slice(0, 64);
            console.log('[DEBUG] Using fingerprint from body:', fingerprint);
        }

        if (device === 'unknown' || fingerprint === 'unknown') {
            try {
                const existingDeviceRes = await pool.query(
                    `SELECT COALESCE(device, 'unknown') as device, fingerprint FROM user_devices
                     WHERE username = $1
                       AND (device != 'unknown' OR device IS NULL)
                       AND fingerprint != 'unknown'
                     ORDER BY created_at DESC
                     LIMIT 1`,
                    [decoded.username]
                );
                if (existingDeviceRes.rows[0]) {
                    device = existingDeviceRes.rows[0].device;
                    fingerprint = existingDeviceRes.rows[0].fingerprint;
                    auditLog('OAUTH_POST_REUSED_FROM_USER_DEVICES', {
                        username: decoded.username,
                        device,
                        fingerprint
                    });
                }
            } catch (reuseErr) {
                console.error('[WARN] oauth.js POST device reuse failed:', reuseErr.message);
            }
        }

        let clientRow;
        try {
            const uriResult = await pool.query(
                `SELECT allowed_scopes, client_type FROM oauth_clients
                 WHERE client_id = $1 AND $2 = ANY(redirect_uris)`,
                [client_id, redirect_uri]
            );
            if (uriResult.rows.length === 0)
                return res.status(400).json({ error: 'invalid_client or invalid_redirect_uri' });
            clientRow = uriResult.rows[0];
        } catch (dbErr) {
            console.error('[ERROR] oauth.js handleAuthorize POST DB:', dbErr.message);
            return res.status(500).json({ error: 'Internal server error' });
        }

        if (clientRow.client_type === 'public' && !code_challenge) {
            auditLog('OAUTH_PKCE_REQUIRED', { clientId: client_id, ip });
            return res.status(400).json({ error: 'invalid_request: code_challenge required for public clients' });
        }

        if (!approved) {
            auditLog('OAUTH_CONSENT_DENIED', { username: decoded.username, clientId: client_id, ip });
            const denyUrl = new URL(redirect_uri);
            denyUrl.searchParams.set('error', 'access_denied');
            denyUrl.searchParams.set('state', state);
            return res.status(200).json({ redirect_url: denyUrl.toString() });
        }

        const effectiveScope = parseScope(scope, clientRow.allowed_scopes);
        const code           = crypto.randomBytes(32).toString('hex');
        const codeHash       = hashToken(code);
        const expiresAt      = new Date(Date.now() + CODE_TTL_MINUTES * 60 * 1000);

        let finalPreLoginLogId = pre_login_log_id;
        
        // ไม่สร้าง login_risks ใหม่ ใช้แค่ค่าจาก pre-login phase
        if (!finalPreLoginLogId) {
            console.warn('[WARN] oauth.js: No pre_login_log_id provided, using null');
        }

        try {
            await pool.query(
                `INSERT INTO oauth_codes
                 (code_hash, client_id, username, redirect_uri, scope,
                  code_challenge, code_challenge_method, expires_at, pre_login_log_id)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
                [codeHash, client_id, decoded.username, redirect_uri,
                 effectiveScope,
                 code_challenge || null,
                 code_challenge ? 'S256' : null,
                 expiresAt,
                 finalPreLoginLogId || null]
            );

            if (finalPreLoginLogId) {
                try {
                    const cookies = parse(req.headers.cookie || '');
                    const sessionToken = cookies.session_token;
                    if (sessionToken) {
                        const sessionDecoded = jwt.verify(sessionToken, process.env.JWT_SECRET, {
                            issuer: process.env.BASE_URL, audience: 'b-sso-api'
                        });

                        if (sessionDecoded?.jti) {
                            await pool.query(
                                `UPDATE login_risks
                                 SET session_jti = $1, is_success = TRUE
                                 WHERE id = $2 AND username = $3`,
                                [sessionDecoded.jti, finalPreLoginLogId, decoded.username]
                            );
                            console.log(`[INFO] oauth.js: Linked session_jti=${sessionDecoded.jti} to login_risk_id=${finalPreLoginLogId}`);
                        }
                    }
                } catch (linkErr) {
                    console.error('[WARN] oauth.js session_jti link failed:', linkErr.message);
                }
            }
        } catch (dbErr) {
            console.error('[ERROR] oauth.js handleAuthorize insert code:', dbErr.message);
            return res.status(500).json({ error: 'Internal server error' });
        }

        auditLog('OAUTH_CODE_ISSUED', { username: decoded.username, clientId: client_id, scope: effectiveScope, ip, preLoginLogId: finalPreLoginLogId });

        const redirectUrl = new URL(redirect_uri);
        redirectUrl.searchParams.set('code', code);
        redirectUrl.searchParams.set('state', state);
        if (finalPreLoginLogId) {
            redirectUrl.searchParams.set('pre_login_log_id', finalPreLoginLogId);
        }
        return res.status(200).json({ redirect_url: redirectUrl.toString() });
    }

    return res.status(405).json({ error: 'Method not allowed' });
}

async function handleToken(req, res, ip) {
    if (req.method !== 'POST') return res.status(405).send();

    try {
        if (await checkRateLimit(`ip:${ip}:oauth-token`, 20, 60_000)) {
            auditLog('OAUTH_TOKEN_RATE_LIMIT', { ip });
            return res.status(429).json({ error: 'too_many_requests' });
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit error (oauth-token), failing open:', rlErr.message);
    }

    if (!requireJson(req, res)) return;
    const { grant_type, code, redirect_uri, client_id, client_secret,
            code_verifier, refresh_token, pre_login_log_id } = req.body;

    if (!grant_type || !['authorization_code', 'refresh_token'].includes(grant_type))
        return res.status(400).json({ error: 'unsupported_grant_type' });
    if (!client_id || typeof client_id !== 'string' || client_id.length > 128)
        return res.status(400).json({ error: 'invalid_request: client_id is required' });

    const tokenClient = await pool.connect();
    try {
        await tokenClient.query('BEGIN');

        const clientResult = await tokenClient.query(
            'SELECT client_secret_hash, client_type FROM oauth_clients WHERE client_id = $1',
            [client_id]
        );
        if (clientResult.rows.length === 0) {
            await tokenClient.query('ROLLBACK');
            auditLog('OAUTH_TOKEN_INVALID_CLIENT', { clientId: client_id, ip });
            if (client_secret) hashClientSecret(client_secret);
            return res.status(401).json({ error: 'invalid_client' });
        }

        const isPublicClient = clientResult.rows[0].client_type === 'public';

        if (!isPublicClient) {
            if (!client_secret || typeof client_secret !== 'string' || client_secret.length > 256) {
                await tokenClient.query('ROLLBACK');
                return res.status(400).json({ error: 'invalid_request: client_secret is required for confidential clients' });
            }
            if (!safeHexEqual(clientResult.rows[0].client_secret_hash, hashClientSecret(client_secret))) {
                await tokenClient.query('ROLLBACK');
                auditLog('OAUTH_TOKEN_WRONG_SECRET', { clientId: client_id, ip });
                return res.status(401).json({ error: 'invalid_client' });
            }
        }

        if (grant_type === 'authorization_code') {
            if (!code         || typeof code         !== 'string' || code.length         > 128) return res.status(400).json({ error: 'invalid_request: code is required' });
            if (!redirect_uri || typeof redirect_uri !== 'string' || redirect_uri.length > 512) return res.status(400).json({ error: 'invalid_request: redirect_uri is required' });

            const codeHash   = hashToken(code);
            const codeResult = await tokenClient.query(
                `SELECT id, username, redirect_uri, scope, expires_at, used,
                        code_challenge, code_challenge_method, pre_login_log_id
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
                if (verifierHash !== codeRow.code_challenge) {
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

            const codePreLoginLogId = codeRow.pre_login_log_id || null;

            let preLoginScore = null;
            if (codePreLoginLogId) {
                const scoreRes = await tokenClient.query(
                    `SELECT pre_login_score FROM login_risks WHERE id = $1`,
                    [codePreLoginLogId]
                );
                if (scoreRes.rows[0]) {
                    preLoginScore = scoreRes.rows[0].pre_login_score;
                }
            }

            const accessResult = await tokenClient.query(
                `INSERT INTO oauth_tokens (token_hash, token_type, client_id, username, scope, expires_at, pre_login_log_id, pre_login_score)
                 VALUES ($1, 'access', $2, $3, $4, $5, $6, $7)
                 RETURNING id`,
                [accessHash, client_id, codeRow.username, scope, accessExp, codePreLoginLogId, preLoginScore]
            );
            const accessTokenId = accessResult.rows[0].id;
            auditLog('OAUTH_TOKEN_PRE_LOGIN_LINKED', { accessTokenId, preLoginLogId: codePreLoginLogId });

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
                refresh_token_expires_in: REFRESH_TOKEN_TTL_DAYS * 86400,
                scope:         scope.join(' '),
            });
        }

        if (grant_type === 'refresh_token') {
            try {
                if (await checkRateLimit(`ip:${ip}:oauth-refresh`, 10, 60_000)) {
                    await tokenClient.query('ROLLBACK');
                    auditLog('OAUTH_REFRESH_RATE_LIMIT', { clientId: client_id, ip });
                    return res.status(429).json({ error: 'too_many_requests' });
                }
            } catch (rlErr) {
                console.error('[WARN] rate-limit error (oauth-refresh), failing open:', rlErr.message);
            }

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
                await pool.query(
                    `UPDATE oauth_tokens SET revoked_at = NOW()
                     WHERE client_id = $1 AND username = $2 AND revoked_at IS NULL`,
                    [client_id, rt.username]
                );
                auditLog('OAUTH_REFRESH_REUSE_REVOKE_ALL', {
                    clientId: client_id, username: rt.username, ip, note: 'possible token theft'
                });
                return res.status(400).json({ error: 'invalid_grant: refresh_token already used' });
            }
            if (new Date() > new Date(rt.expires_at)) {
                await tokenClient.query('ROLLBACK');
                auditLog('OAUTH_REFRESH_EXPIRED', { clientId: client_id, username: rt.username, ip });
                return res.status(400).json({ error: 'invalid_grant: refresh_token has expired' });
            }

            const refreshFingerprint = `oauth_refresh:${client_id}:${ip}:${hashToken(req.headers['user-agent'] || 'unknown').slice(0, 16)}`;
            const deviceRes = await tokenClient.query(
                'SELECT id FROM user_devices WHERE username = $1 AND fingerprint = $2',
                [rt.username, refreshFingerprint]
            );
            const fpMatch = deviceRes.rows.length > 0;

            let currentRiskScore = 0.1;
            if (!fpMatch) currentRiskScore += 0.4;

            const failRes = await tokenClient.query(
                `SELECT COUNT(*) AS cnt FROM login_risks
                 WHERE username = $1 AND is_success = FALSE
                 AND created_at > NOW() - INTERVAL '60 seconds'`,
                [rt.username]
            );
            const recentFails = Number(failRes.rows[0]?.cnt || 0);
            if (recentFails > 3) currentRiskScore += 0.3;
            if (recentFails >= 5) currentRiskScore = 1.0;

            const { medium: MEDIUM_THRESHOLD } = getCombinedConfig();
            const currentRiskLevel = currentRiskScore >= 1.0 ? 'HIGH' :
                                    (currentRiskScore >= MEDIUM_THRESHOLD ? 'MEDIUM' : 'LOW');

            const stepUpRequired = currentRiskLevel === 'MEDIUM' || currentRiskLevel === 'HIGH';

            auditLog('OAUTH_REFRESH_RISK_ASSESSMENT', {
                clientId: client_id,
                username: rt.username,
                ip,
                fpMatch,
                recentFails,
                riskScore: currentRiskScore,
                riskLevel: currentRiskLevel,
                stepUpRequired
            });

            if (currentRiskLevel === 'HIGH') {
                await tokenClient.query('ROLLBACK');
                auditLog('OAUTH_REFRESH_HIGH_RISK_BLOCKED', {
                    clientId: client_id,
                    username: rt.username,
                    ip,
                    riskScore: currentRiskScore
                });
                return res.status(403).json({
                    error: 'access_denied',
                    error_description: 'Authentication failed. Please re-authenticate.',
                    step_up_required: true
                });
            }

            await tokenClient.query(
                'UPDATE oauth_tokens SET revoked_at = NOW() WHERE id = $1',
                [rt.id]
            );

            const scope       = rt.scope || DEFAULT_SCOPE;
            const accessToken = crypto.randomBytes(32).toString('hex');
            const accessHash  = hashToken(accessToken);
            const accessExp   = new Date(Date.now() + ACCESS_TOKEN_TTL_SECONDS * 1000);

            let refreshPreLoginScore = 0.1;
            try {
                const preLoginRes = await tokenClient.query(
                    `SELECT id, pre_login_score
                     FROM login_risks
                     WHERE username = $1 AND is_success = TRUE
                       AND created_at > NOW() - INTERVAL '30 minutes'
                     ORDER BY created_at DESC
                     LIMIT 1`,
                    [rt.username]
                );
                refreshPreLoginScore = preLoginRes.rows[0]?.pre_login_score || 0.1;
            } catch { }

            const newAccessResult = await tokenClient.query(
                `INSERT INTO oauth_tokens (token_hash, token_type, client_id, username, scope, expires_at, risk_level, step_up_required, pre_login_score)
                 VALUES ($1, 'access', $2, $3, $4, $5, $6, $7, $8)
                 RETURNING id`,
                [accessHash, client_id, rt.username, scope, accessExp, currentRiskLevel, stepUpRequired, refreshPreLoginScore]
            );
            const newAccessTokenId = newAccessResult.rows[0].id;

            // ไม่สร้าง login_risks ใหม่ตอน refresh token - ใช้ค่าเดิมจาก pre-login
            console.log(`[INFO] oauth.js: Refreshed OAuth token ${newAccessTokenId}, reusing existing pre-login record, score=${currentRiskScore}, level=${currentRiskLevel}`);

            const newRefreshToken = crypto.randomBytes(32).toString('hex');
            const newRefreshHash  = hashToken(newRefreshToken);
            const newRefreshExp   = new Date(Date.now() + REFRESH_TOKEN_TTL_DAYS * 86400 * 1000);

            await tokenClient.query(
                `INSERT INTO oauth_tokens (token_hash, token_type, client_id, username, scope, expires_at, risk_level)
                 VALUES ($1, 'refresh', $2, $3, $4, $5, $6)`,
                [newRefreshHash, client_id, rt.username, scope, newRefreshExp, currentRiskLevel]
            );

            await tokenClient.query('COMMIT');
            auditLog('OAUTH_TOKEN_REFRESHED', {
                clientId: client_id,
                username: rt.username,
                ip,
                riskLevel: currentRiskLevel,
                stepUpRequired: stepUpRequired
            });

            const tokenResponse = {
                access_token:  accessToken,
                token_type:    'Bearer',
                expires_in:    ACCESS_TOKEN_TTL_SECONDS,
                refresh_token: newRefreshToken,
                refresh_token_expires_in: REFRESH_TOKEN_TTL_DAYS * 86400,
                scope:         scope.join(' '),
            };

            if (stepUpRequired) {
                tokenResponse.step_up_required = true;
                tokenResponse.step_up_reason = currentRiskLevel === 'HIGH'
                    ? 'high_risk_detected'
                    : 'medium_risk_detected';
            }

            return res.status(200).json(tokenResponse);
        }

    } catch (err) {
        try { await tokenClient.query('ROLLBACK'); } catch { }
        console.error('[ERROR] oauth.js handleToken:', err);
        return res.status(500).json({ error: 'server_error' });
    } finally {
        tokenClient.release();
    }
}

async function handleUserinfo(req, res, ip) {
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

    if (Math.random() < 0.02) {
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

        const scope    = row.scope || DEFAULT_SCOPE;
        const response = {};

        if (scope.includes('openid'))  response.sub      = String(row.user_id);
        if (scope.includes('profile')) response.username = row.username;
        if (scope.includes('email') && row.email_verified)
            response.email = row.email;

        return res.status(200).json(response);

    } catch (err) {
        console.error('[ERROR] oauth.js handleUserinfo:', err);
        return res.status(500).json({ error: 'server_error' });
    }
}

async function handleSsoExchange(req, res, ip) {
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

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const result = await client.query(
            `SELECT st.id, st.user_id, st.used, st.expires_at, u.username, u.email
             FROM sso_tokens st
             JOIN users u ON u.id = st.user_id
             WHERE st.token = $1 FOR UPDATE`,
            [token]
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
        });

    } catch (err) {
        try { await client.query('ROLLBACK'); } catch { }
        console.error('[ERROR] oauth.js handleSsoExchange:', err);
        return res.status(500).json({ error: 'server_error' });
    } finally {
        client.release();
    }
}

async function handleIntrospect(req, res, ip) {
    if (req.method !== 'POST') return res.status(405).send();

    try {
        if (await checkRateLimit(`ip:${ip}:oauth-introspect`, 60, 60_000)) {
            auditLog('OAUTH_INTROSPECT_RATE_LIMIT', { ip });
            return res.status(429).json({ error: 'too_many_requests' });
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit error (oauth-introspect), failing open:', rlErr.message);
    }

    if (!requireJson(req, res)) return;
    const { token, client_id, client_secret } = req.body;

    if (!token || typeof token !== 'string' || token.length > 128)
        return res.status(400).json({ error: 'invalid_request: token is required' });
    if (!client_id || typeof client_id !== 'string' || client_id.length > 128)
        return res.status(400).json({ error: 'invalid_request: client_id is required' });
    if (!client_secret || typeof client_secret !== 'string' || client_secret.length > 256)
        return res.status(400).json({ error: 'invalid_request: client_secret is required' });

    try {
        const clientResult = await pool.query(
            'SELECT client_secret_hash FROM oauth_clients WHERE client_id = $1',
            [client_id]
        );
        if (clientResult.rows.length === 0) {
            hashClientSecret(client_secret);
            return res.status(401).json({ error: 'invalid_client' });
        }
        if (!safeHexEqual(clientResult.rows[0].client_secret_hash, hashClientSecret(client_secret))) {
            auditLog('OAUTH_INTROSPECT_WRONG_SECRET', { clientId: client_id, ip });
            return res.status(401).json({ error: 'invalid_client' });
        }

        const tokenHash = hashToken(token);
        const result = await pool.query(
            `SELECT token_type, username, scope, expires_at, revoked_at, client_id as token_client
             FROM oauth_tokens
             WHERE token_hash = $1 AND client_id = $2`,
            [tokenHash, client_id]
        );

        if (result.rows.length === 0) {
            return res.status(200).json({ active: false });
        }

        const row = result.rows[0];
        const now = new Date();
        const expiresAt = new Date(row.expires_at);
        const isRevoked = !!row.revoked_at;
        const isExpired = now > expiresAt;

        if (isRevoked || isExpired) {
            auditLog('OAUTH_INTROSPECT_INACTIVE', {
                clientId: client_id,
                username: row.username,
                reason: isRevoked ? 'revoked' : 'expired'
            });
            return res.status(200).json({ active: false });
        }

        const response = {
            active: true,
            scope: row.scope?.join(' ') || '',
            client_id: row.token_client,
            username: row.username,
            token_type: row.token_type === 'access' ? 'Bearer' : row.token_type,
            exp: Math.floor(expiresAt.getTime() / 1000),
            iat: Math.floor((expiresAt.getTime() - ACCESS_TOKEN_TTL_SECONDS * 1000) / 1000)
        };

        auditLog('OAUTH_INTROSPECT_SUCCESS', { clientId: client_id, username: row.username });
        return res.status(200).json(response);

    } catch (err) {
        console.error('[ERROR] oauth.js handleIntrospect:', err);
        return res.status(500).json({ error: 'server_error' });
    }
}

async function handleRevoke(req, res, ip) {
    if (req.method !== 'POST') return res.status(405).send();

    try {
        if (await checkRateLimit(`ip:${ip}:oauth-revoke`, 20, 60_000)) {
            return res.status(429).json({ error: 'too_many_requests' });
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit error (oauth-revoke), failing open:', rlErr.message);
    }

    if (!requireJson(req, res)) return;
    const { token, client_id, client_secret } = req.body;

    if (!token         || typeof token         !== 'string' || token.length         > 128) return res.status(400).json({ error: 'invalid_request: token is required' });
    if (!client_id     || typeof client_id     !== 'string' || client_id.length     > 128) return res.status(400).json({ error: 'invalid_request: client_id is required' });
    if (!client_secret || typeof client_secret !== 'string' || client_secret.length > 256) return res.status(400).json({ error: 'invalid_request: client_secret is required' });

    try {
        const clientResult = await pool.query(
            'SELECT client_secret_hash FROM oauth_clients WHERE client_id = $1', [client_id]
        );
        if (clientResult.rows.length === 0) {
            hashClientSecret(client_secret);
            return res.status(401).json({ error: 'invalid_client' });
        }
        if (!safeHexEqual(clientResult.rows[0].client_secret_hash, hashClientSecret(client_secret))) {
            auditLog('OAUTH_REVOKE_WRONG_SECRET', { clientId: client_id, ip });
            return res.status(401).json({ error: 'invalid_client' });
        }

        const result = await pool.query(
            `UPDATE oauth_tokens SET revoked_at = NOW()
             WHERE token_hash = $1 AND client_id = $2 AND revoked_at IS NULL`,
            [hashToken(token), client_id]
        );
        if (result.rowCount > 0) auditLog('OAUTH_TOKEN_REVOKED', { clientId: client_id, ip });

        return res.status(200).json({ success: true });

    } catch (err) {
        console.error('[ERROR] oauth.js handleRevoke:', err);
        return res.status(500).json({ error: 'server_error' });
    }
}

async function handleDiscovery(req, res) {
    if (req.method !== 'GET') return res.status(405).send();

    const baseUrl = process.env.BASE_URL?.replace(/\/$/, '') || '';

    const discovery = {
        issuer: baseUrl,
        authorization_endpoint: `${baseUrl}/api/oauth/authorize`,
        token_endpoint: `${baseUrl}/api/oauth/token`,
        userinfo_endpoint: `${baseUrl}/api/oauth/userinfo`,
        revocation_endpoint: `${baseUrl}/api/oauth/revoke`,
        introspection_endpoint: `${baseUrl}/api/oauth/introspect`,
        jwks_uri: `${baseUrl}/.well-known/jwks.json`,
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256', 'HS256'],
        scopes_supported: ['profile', 'email', 'openid'],
        token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
        code_challenge_methods_supported: ['S256'],
        claims_supported: ['sub', 'username', 'email', 'email_verified'],
    };

    res.setHeader('Content-Type', 'application/json');
    return res.status(200).json(discovery);
}

export default async function handler(req, res) {
    setSecurityHeaders(res, 'SAMEORIGIN');

    if (req.method === 'OPTIONS') {
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
        res.setHeader('Access-Control-Max-Age', '86400');
        return res.status(204).end();
    }

    res.setHeader('Access-Control-Allow-Origin', '*');

    const ip = getClientIp(req);
    const url = req.url || '';

    if (url.includes('/.well-known/openid-configuration')) {
        return handleDiscovery(req, res);
    }

    const match = url.match(/\/api\/oauth\/([^/?]+)/);
    const sub   = match?.[1];

    switch (sub) {
        case 'clients':      return handleClients(req, res, ip);
        case 'authorize':    return handleAuthorize(req, res, ip);
        case 'token':        return handleToken(req, res, ip);
        case 'userinfo':     return handleUserinfo(req, res, ip);
        case 'introspect':   return handleIntrospect(req, res, ip);
        case 'revoke':       return handleRevoke(req, res, ip);
        case 'sso-exchange': return handleSsoExchange(req, res, ip);
        default:
            return res.status(404).json({ error: 'OAuth endpoint not found' });
    }
}
