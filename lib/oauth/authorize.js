import { pool } from '../db.js';
import { checkRateLimit } from '../rate-limit.js';
import { getClientIp } from '../ip-utils.js';
import { validateCsrfToken } from '../csrf-utils.js';
import crypto from 'crypto';
import { auditLog, requireJson } from '../response-utils.js';
import { parseScope, hashToken, verifySessionCookie } from './shared.js';

const CODE_TTL_MINUTES = 10;

// Consent flow: GET แสดงข้อมูล app, POST รับผลการตัดสินใจ
// Auth: session_token cookie
export async function handleAuthorize(req, res, ip) {
    try {
        if (await checkRateLimit(`ip:${ip}:oauth-authorize`, 30, 60_000)) {
            auditLog('OAUTH_AUTHORIZE_RATE_LIMIT', { ip });
            return res.status(429).json({ error: 'Too many requests. Please try again later.' });
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit error (oauth-authorize), failing open:', rlErr.message);
    }

    // ── GET: ตรวจ params + session → ส่งข้อมูลสำหรับ consent UI ──
    if (req.method === 'GET') {
        const { client_id, redirect_uri, response_type, state, scope,
                code_challenge, code_challenge_method } = req.query;

        if (response_type !== 'code')
            return res.status(400).json({ error: 'unsupported_response_type' });
        if (!client_id || typeof client_id !== 'string' || client_id.length > 128)
            return res.status(400).json({ error: 'invalid_request: missing or invalid client_id' });
        if (!redirect_uri || typeof redirect_uri !== 'string' || redirect_uri.length > 512)
            return res.status(400).json({ error: 'invalid_request: missing or invalid redirect_uri' });
        if (!state || typeof state !== 'string' || state.length > 256)
            return res.status(400).json({ error: 'invalid_request: missing or invalid state' });

        // PKCE validation (optional, but if present must be S256)
        if (code_challenge !== undefined) {
            if (code_challenge_method !== 'S256')
                return res.status(400).json({ error: 'invalid_request: code_challenge_method must be S256' });
            if (typeof code_challenge !== 'string' || code_challenge.length < 43 || code_challenge.length > 128)
                return res.status(400).json({ error: 'invalid_request: invalid code_challenge' });
        }

        let clientResult;
        try {
            clientResult = await pool.query(
                'SELECT name, redirect_uris, allowed_scopes FROM oauth_clients WHERE client_id = $1',
                [client_id]
            );
        } catch (dbErr) {
            console.error('[ERROR] oauth authorize GET DB:', dbErr.message);
            return res.status(500).json({ error: 'Internal server error' });
        }

        if (clientResult.rows.length === 0)
            return res.status(400).json({ error: 'invalid_client: unknown client_id' });

        const { name: appName, redirect_uris, allowed_scopes } = clientResult.rows[0];

        if (!redirect_uris.includes(redirect_uri))
            return res.status(400).json({ error: 'invalid_redirect_uri: URI not registered' });

        // คำนวณ effective scope = intersection of requested + allowed
        const effectiveScope = parseScope(scope, allowed_scopes);

        const decoded = await verifySessionCookie(req);
        if (!decoded) {
            return res.status(401).json({ error: 'unauthenticated', app_name: appName });
        }

        auditLog('OAUTH_CONSENT_VIEW', { username: decoded.username, clientId: client_id, ip });
        return res.status(200).json({
            app_name: appName, client_id, redirect_uri, state,
            username: decoded.username,
            scope:    effectiveScope,
        });
    }

    // ── POST: รับผลการตัดสินใจ Allow / Deny ───────────────
    if (req.method === 'POST') {
        if (!requireJson(req, res)) return;
        // CSRF: ป้องกัน cross-site form submission
        if (!validateCsrfToken(req)) {
            return res.status(403).json({ error: 'invalid_request: CSRF token invalid or missing' });
        }

        const { client_id, redirect_uri, state, approved,
                scope, code_challenge, code_challenge_method } = req.body;

        if (!client_id || typeof client_id !== 'string' || client_id.length > 128)
            return res.status(400).json({ error: 'invalid_request: missing or invalid client_id' });
        if (!redirect_uri || typeof redirect_uri !== 'string' || redirect_uri.length > 512)
            return res.status(400).json({ error: 'invalid_request: missing or invalid redirect_uri' });
        if (!state || typeof state !== 'string' || state.length > 256)
            return res.status(400).json({ error: 'invalid_request: missing or invalid state' });

        // PKCE validation
        if (code_challenge !== undefined) {
            if (code_challenge_method !== 'S256')
                return res.status(400).json({ error: 'invalid_request: code_challenge_method must be S256' });
            if (typeof code_challenge !== 'string' || code_challenge.length < 43 || code_challenge.length > 128)
                return res.status(400).json({ error: 'invalid_request: invalid code_challenge' });
        }

        const decoded = await verifySessionCookie(req);
        if (!decoded) return res.status(401).json({ error: 'session_expired: please sign in again' });

        let clientRow;
        try {
            const uriResult = await pool.query(
                `SELECT allowed_scopes FROM oauth_clients
                 WHERE client_id = $1 AND $2 = ANY(redirect_uris)`,
                [client_id, redirect_uri]
            );
            if (uriResult.rows.length === 0)
                return res.status(400).json({ error: 'invalid_client or invalid_redirect_uri' });
            clientRow = uriResult.rows[0];
        } catch (dbErr) {
            console.error('[ERROR] oauth authorize POST DB:', dbErr.message);
            return res.status(500).json({ error: 'Internal server error' });
        }

        // ── Deny ──────────────────────────────────────────
        if (!approved) {
            auditLog('OAUTH_CONSENT_DENIED', { username: decoded.username, clientId: client_id, ip });
            const denyUrl = new URL(redirect_uri);
            denyUrl.searchParams.set('error', 'access_denied');
            denyUrl.searchParams.set('state', state);
            return res.status(200).json({ redirect_url: denyUrl.toString() });
        }

        // ── Allow: ออก authorization_code ─────────────────
        const effectiveScope = parseScope(scope, clientRow.allowed_scopes);
        const code           = crypto.randomBytes(32).toString('hex');
        const codeHash       = hashToken(code);
        const expiresAt      = new Date(Date.now() + CODE_TTL_MINUTES * 60 * 1000);

        try {
            await pool.query(
                `INSERT INTO oauth_codes
                 (code_hash, client_id, username, redirect_uri, scope,
                  code_challenge, code_challenge_method, expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
                [codeHash, client_id, decoded.username, redirect_uri,
                 effectiveScope,
                 code_challenge || null,
                 code_challenge ? 'S256' : null,
                 expiresAt]
            );
        } catch (dbErr) {
            console.error('[ERROR] oauth authorize insert code:', dbErr.message);
            return res.status(500).json({ error: 'Internal server error' });
        }

        auditLog('OAUTH_CODE_ISSUED', { username: decoded.username, clientId: client_id, scope: effectiveScope, ip });

        const redirectUrl = new URL(redirect_uri);
        redirectUrl.searchParams.set('code', code);
        redirectUrl.searchParams.set('state', state);
        return res.status(200).json({ redirect_url: redirectUrl.toString() });
    }

    return res.status(405).json({ error: 'Method not allowed' });
}

