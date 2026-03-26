import '../startup-check.js';
import jwt                 from 'jsonwebtoken';
import crypto              from 'crypto';
import { parse }           from 'cookie';
import { getClientIp }     from '../lib/ip-utils.js';
import { checkRateLimit }  from '../lib/rate-limit.js';
import { LOGID_TTL_MINUTES } from '../lib/constants.js';
import {
    setSecurityHeaders,
    auditLog,
    isJsonContentType,
    isValidBody,
} from '../lib/response-utils.js';
import { pool }            from '../lib/db.js';
import { ensureBehaviorRisksSchema, combineRisk, actionFromCombinedScore, ensureStepupChallengesSchema } from '../lib/risk-score.js';

const ENGINE_URL        = process.env.RISK_ENGINE_URL;
const ENGINE_API_KEY    = process.env.RISK_ENGINE_API_KEY;
const RISK_SHARED_SECRET = process.env.RISK_ENGINE_SHARED_SECRET;

function hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
}

function signForRiskEngine(timestamp, nonce, body) {
    if (!RISK_SHARED_SECRET) return null;
    const bodyHash = crypto.createHash('sha256').update(body).digest('hex');
    const base = `${timestamp}\n${nonce}\n${bodyHash}`;
    return crypto.createHmac('sha256', RISK_SHARED_SECRET).update(base).digest('base64url');
}

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();

    setSecurityHeaders(res);

    if (!ENGINE_URL) {
        console.error('[ERROR] behavior.js: RISK_ENGINE_URL is not configured');
        return res.status(500).json({ error: 'Risk engine is not configured' });
    }

    if (!isJsonContentType(req)) {
        return res.status(415).json({ error: 'Content-Type must be application/json' });
    }

    if (!isValidBody(req.body)) {
        return res.status(400).json({ error: 'Invalid request data' });
    }

    const ip = getClientIp(req);
    const requestId = crypto.randomUUID();

    try {
        if (await checkRateLimit(`ip:${ip}:behavior`, 60, 60_000)) {
            auditLog('BEHAVIOR_RATE_LIMIT', { ip });

            return res.status(429).json({ action: 'low', message: 'Too many behavior events' });
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit DB error (behavior), failing open:', rlErr.message);
    }

    const cookies = parse(req.headers.cookie || '');
    const sessionCookieToken = cookies.session_token;
    const authHeader = req.headers.authorization;

    let username = null;
    let sessionJti = null;
    let authType = null; 
    let tokenPreLoginLogId = null; 

    if (sessionCookieToken) {
        let decoded;
        try {
            decoded = jwt.verify(sessionCookieToken, process.env.JWT_SECRET, {
                issuer:   process.env.BASE_URL,
                audience: 'b-sso-api'
            });
        } catch {
            return res.status(401).json({ action: 'revoke' });
        }
        if (!decoded || typeof decoded.username !== 'string' || !decoded.jti) {
            return res.status(401).json({ action: 'revoke' });
        }
        username = decoded.username;
        sessionJti = decoded.jti;
        authType = 'session_cookie';
    } else if (authHeader?.startsWith?.('Bearer ')) {

        const token = authHeader.slice(7).trim();
        if (!token || token.length > 128) {
            res.setHeader('WWW-Authenticate', 'Bearer realm="oauth", error="invalid_token"');
            return res.status(401).json({ action: 'revoke' });
        }

        try {
            const result = await pool.query(
                `SELECT ot.id, ot.username, ot.expires_at, ot.revoked_at, ot.pre_login_log_id
                 FROM oauth_tokens ot
                 WHERE ot.token_hash = $1 AND ot.token_type = 'access'`,
                [hashToken(token)]
            );

            if (result.rows.length === 0) {
                res.setHeader('WWW-Authenticate', 'Bearer realm="oauth", error="invalid_token"');
                return res.status(401).json({ action: 'revoke' });
            }

            const row = result.rows[0];
            if (row.revoked_at) {
                res.setHeader('WWW-Authenticate', 'Bearer realm="oauth", error="invalid_token"');
                return res.status(401).json({ action: 'revoke' });
            }
            if (new Date() > new Date(row.expires_at)) {
                res.setHeader('WWW-Authenticate',
                    'Bearer realm="oauth", error="invalid_token", error_description="token expired"');
                return res.status(401).json({ action: 'revoke' });
            }

            username = row.username;
            sessionJti = `oauth:${row.id}`;
            authType = 'oauth_bearer';
            tokenPreLoginLogId = row.pre_login_log_id || null;
            auditLog('BEHAVIOR_OAUTH_TOKEN_LOADED', { oauthTokenId: row.id, username, tokenPreLoginLogId });
        } catch (dbErr) {
            console.error('[ERROR] behavior.js oauth token lookup failed:', dbErr.message);
            return res.status(500).json({ error: 'Internal server error' });
        }
    } else {
        return res.status(401).json({ action: 'revoke' });
    }

    await ensureBehaviorRisksSchema();
    await ensureStepupChallengesSchema(); 

    const { events, page, meta, features } = req.body;

    if (!Array.isArray(events)) {
        return res.status(400).json({ error: 'events must be an array' });
    }

    const safeFeatures = features && typeof features === 'object' ? features : {};

    function clamp01(x) {
        if (!Number.isFinite(x)) return 0;
        if (x < 0) return 0;
        if (x > 1) return 1;
        return x;
    }

    const idleRatio           = clamp01(Number(safeFeatures.idle_ratio || 0));
    const interactionDensity  = Number(safeFeatures.interaction_density || 0);
    const normDensity         = clamp01(interactionDensity / 5); 

    const avgMouseSpeed       = Number(safeFeatures.avg_mouse_speed || 0);
    const mouseSpeedNorm      = clamp01(avgMouseSpeed / 2000);   
    const mouseDirChangeRate  = clamp01(Number(safeFeatures.mouse_dir_change_rate || 0));

    const avgClickIntervalMs  = Number(safeFeatures.avg_click_interval_ms || 0);
    const stdClickIntervalMs  = Number(safeFeatures.std_click_interval_ms || 0);
    const clickRateNorm       = clamp01(avgClickIntervalMs > 0 ? 1 / (1 + avgClickIntervalMs / 1000) : 0);
    const clickJitterNorm     = clamp01(stdClickIntervalMs / 1000);

    const avgKeyIntervalMs    = Number(safeFeatures.avg_key_interval_ms || 0);
    const stdKeyIntervalMs    = Number(safeFeatures.std_key_interval_ms || 0);
    const keyRateNorm         = clamp01(avgKeyIntervalMs > 0 ? 1 / (1 + avgKeyIntervalMs / 1000) : 0);
    const keyJitterNorm       = clamp01(stdKeyIntervalMs / 1000);

    const avgScrollAbsDy      = Number(safeFeatures.avg_scroll_abs_dy || 0);
    const scrollDirChangeRate = clamp01(Number(safeFeatures.scroll_dir_change_rate || 0));
    const scrollDistNorm      = clamp01(avgScrollAbsDy / 2000);

    const behaviorPayload = {
        mouse: {
            m: mouseSpeedNorm,
            s: mouseDirChangeRate,
        },
        click: {
            m: clickRateNorm,
            s: clickJitterNorm,
        },
        key: {
            m: keyRateNorm,
            s: keyJitterNorm,
        },
        idle: {
            m: idleRatio,
            s: 0,
        },
        features: {
            density:    normDensity,
            idle_ratio: idleRatio,
        },

        username,
        session_jti: sessionJti,
        ip,
        page: typeof page === 'string' ? page : undefined,
        ts:   new Date().toISOString(),
    };

    const bodyJson   = JSON.stringify(behaviorPayload);
    const riskTs     = new Date().toISOString();
    const riskNonce  = crypto.randomUUID();
    const riskSig    = signForRiskEngine(riskTs, riskNonce, bodyJson);

    try {
        const controller = new AbortController();
        const timeoutId  = setTimeout(() => controller.abort(), 8_000);

        let engineRes;
        try {
            engineRes = await fetch(ENGINE_URL, {
                method:  'POST',
                headers: {
                    'Content-Type':        'application/json',
                    ...(ENGINE_API_KEY ? { 'x-api-key': ENGINE_API_KEY } : {}),
                    ...(riskSig ? {
                        'X-Risk-Timestamp': riskTs,
                        'X-Risk-Nonce':     riskNonce,
                        'X-Risk-Signature': `v1=${riskSig}`,
                    } : {}),
                },
                body:    bodyJson,
                signal:  controller.signal,
            });
        } finally {
            clearTimeout(timeoutId);
        }

        if (!engineRes.ok) {
            console.error('[WARN] behavior.js: engine responded with', engineRes.status);
            auditLog('BEHAVIOR_ENGINE_ERROR', { status: engineRes.status, username, ip });

            return res.status(200).json({ action: 'low' });
        }

        let engineData;
        try {
            engineData = await engineRes.json();
        } catch {
            console.error('[WARN] behavior.js: failed to parse engine JSON');
            return res.status(200).json({ action: 'low' });
        }

        const behaviorScore = (engineData && typeof engineData.normalized === 'number')
            ? engineData.normalized
            : null;

        let preLoginScore = 0;
        let combinedScore = null;
        let combinedAction = 'low';

        const preLoginLogId = tokenPreLoginLogId || req.body?.pre_login_log_id;

        let loginRiskId = null;
        auditLog('TRACE_CORRELATION_START', { username, sessionJti, preLoginLogId });

        try {

            if (preLoginLogId) {
                const parsed = Number(preLoginLogId);
                auditLog('TRACE_CORRELATION_STEP', { step: '1B_ID', parsedId: parsed });
                if (Number.isInteger(parsed) && parsed > 0) {
                    const byId = await pool.query(
                        `SELECT id, pre_login_score, is_success
                         FROM login_risks
                         WHERE id = $1 AND username = $2
                         LIMIT 1`,
                        [parsed, username]
                    );
                    if (byId.rows[0]) {
                        loginRiskId = byId.rows[0].id;
                        preLoginScore = Number(byId.rows[0].pre_login_score || 0);
                        auditLog('TRACE_CORRELATION_MATCH', { step: '1B_ID', id: loginRiskId, preScore: preLoginScore, is_success: byId.rows[0].is_success });
                    } else {
                        auditLog('TRACE_CORRELATION_MISS', { step: '1B_ID', parsedId: parsed, username });
                    }
                } else {
                    auditLog('TRACE_CORRELATION_ERROR', { step: '1B_ID', message: 'Invalid ID format', value: preLoginLogId });
                }
            }

            if (!loginRiskId && sessionJti) {
                auditLog('TRACE_CORRELATION_STEP', { step: '2_JTI', sessionJti });
                const preRes = await pool.query(
                    `SELECT id, pre_login_score, is_success
                     FROM login_risks
                     WHERE username = $1 AND session_jti = $2
                     ORDER BY created_at DESC
                     LIMIT 1`,
                    [username, sessionJti]
                );
                if (preRes.rows[0]) {
                    loginRiskId = preRes.rows[0].id;
                    preLoginScore = Number(preRes.rows[0].pre_login_score || 0);
                    auditLog('TRACE_CORRELATION_MATCH', { step: '2_JTI', id: loginRiskId, preScore: preLoginScore, is_success: preRes.rows[0].is_success });
                } else {
                    auditLog('TRACE_CORRELATION_MISS', { step: '2_JTI', sessionJti });
                }
            }

            if (!loginRiskId) {
                auditLog('TRACE_CORRELATION_STEP', { step: '3_FALLBACK', username });
                const fallbackRes = await pool.query(
                    `SELECT id, pre_login_score
                     FROM login_risks
                     WHERE username = $1 AND is_success = TRUE
                     ORDER BY created_at DESC
                     LIMIT 1`,
                    [username]
                );
                if (fallbackRes.rows[0]) {
                    loginRiskId = fallbackRes.rows[0].id;
                    preLoginScore = Number(fallbackRes.rows[0].pre_login_score || 0);
                    auditLog('TRACE_CORRELATION_MATCH', { step: '3_FALLBACK', id: loginRiskId, preScore: preLoginScore });
                } else {
                    auditLog('TRACE_CORRELATION_MISS', { step: '3_FALLBACK', username });
                }
            }
        } catch (preErr) {
            auditLog('TRACE_CORRELATION_ERROR', { message: preErr.message });
        }

        auditLog('TRACE_CORRELATION_END', { loginRiskId, behaviorScore });

        if (behaviorScore != null && loginRiskId != null) {
            combinedScore = combineRisk(preLoginScore, behaviorScore);
            combinedAction = actionFromCombinedScore(combinedScore);

            if (combinedAction === 'medium' && sessionJti) {
                try {
                    const mediumCountRes = await pool.query(
                        `SELECT COUNT(*)::int AS cnt
                         FROM behavior_risks
                         WHERE username = $1 
                           AND session_jti = $2 
                           AND combined_action = 'medium'
                           AND created_at > NOW() - INTERVAL '8 hours'`,
                        [username, sessionJti]
                    );
                    const mediumCount = mediumCountRes.rows[0]?.cnt || 0;

                    if (mediumCount >= 3) {
                        combinedAction = 'revoke';
                    }
                } catch (cntErr) {
                    console.error('[WARN] behavior.js medium count failed:', cntErr.message);
                }
            }
        } else {

            combinedScore = null;
            combinedAction = 'low';
        }

        try {
            await pool.query(
                `INSERT INTO behavior_risks
                 (request_id, username, session_jti, behavior_score, combined_score, combined_action)
                 VALUES ($1, $2, $3, $4, $5, $6)`,
                [requestId, username, sessionJti || '', behaviorScore, combinedScore, combinedAction]
            );
        } catch (insErr) {
            console.error('[WARN] behavior.js behavior_risks insert failed:', insErr.message);
        }

        if (loginRiskId != null) {
            try {
                await pool.query(
                    `UPDATE login_risks
                     SET combined_score = $1,
                         combined_action = $2,
                         last_behavior_at = NOW(),
                         behavior_samples = COALESCE(behavior_samples, 0) + 1
                     WHERE id = $3`,
                    [combinedScore, combinedAction, loginRiskId]
                );
            } catch (updErr) {
                console.error('[WARN] behavior.js login_risks summary update failed:', updErr.message);
            }
        }

        auditLog('BEHAVIOR_ENGINE_DECISION', {
            requestId,
            username,
            ip,
            action: combinedAction,
            has_behavior_score: behaviorScore != null,
            has_combined_score: combinedScore != null,
        });

        if (combinedAction === 'revoke') {
            if (authType === 'session_cookie') {
                let exp = null;
                try {
                    const decodedUnsafe = jwt.decode(sessionCookieToken);
                    exp = decodedUnsafe && typeof decodedUnsafe.exp === 'number' ? decodedUnsafe.exp : null;
                } catch {  }
                if (sessionJti && exp) {
                    try {
                        const expiresAt = new Date(exp * 1000).toISOString();
                        await pool.query(
                            'INSERT INTO revoked_tokens (jti, expires_at) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                            [sessionJti, expiresAt]
                        );
                    } catch (dbErr) {
                        console.error('[WARN] behavior.js revoke insert failed:', dbErr.message);
                    }
                }
            } else if (authType === 'oauth_bearer' && sessionJti) {
                try {

                    const oauthTokenId = sessionJti.split(':')[1];
                    if (oauthTokenId) {
                        await pool.query(
                            'UPDATE oauth_tokens SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL',
                            [oauthTokenId]
                        );
                    }
                } catch (dbErr) {
                    console.error('[WARN] behavior.js oauth revoke update failed:', dbErr.message);
                }
            }
        }

        if (combinedAction === 'medium' && authType === 'oauth_bearer') {
            try {

                const stepupId = crypto.randomUUID();
                const stepupCode = crypto.randomInt(100000, 1000000).toString();

                const pepper = process.env.MFA_PEPPER;
                if (!pepper) {
                    console.error('[FATAL] MFA_PEPPER environment variable not set');

                    return res.status(500).json({
                        action: 'revoke',
                        reason: 'security_configuration_error'
                    });
                }
                const codeHash = crypto
                    .createHmac('sha256', pepper)
                    .update(`${stepupId}:${stepupCode}`)
                    .digest('hex');

                await pool.query(
                    `INSERT INTO stepup_challenges (id, username, session_jti, code_hash, expires_at)
                     VALUES ($1, $2, $3, $4, NOW() + INTERVAL '5 minutes')`,
                    [stepupId, username, sessionJti, codeHash]
                );

                if (sessionJti) {
                    const oauthTokenId = sessionJti.split(':')[1];
                    if (oauthTokenId) {
                        await pool.query(
                            'UPDATE oauth_tokens SET step_up_required = TRUE WHERE id = $1',
                            [oauthTokenId]
                        );
                    }
                }

                auditLog('OAUTH_STEP_UP_AUTO_CREATED', {
                    username,
                    ip,
                    stepupId,
                    sessionJti,
                    combinedScore
                });

                return res.status(200).json({
                    action: 'step_up_required',
                    request_id: requestId,
                    stepup_id: stepupId,
                    expires_in: 300, 
                    reason: 'medium_risk_behavior_detected'
                });
            } catch (stepupErr) {
                console.error('[WARN] behavior.js auto step-up creation failed:', stepupErr.message);

                auditLog('OAUTH_STEP_UP_CREATION_FAILED_SECURITY_ALERT', {
                    username,
                    ip,
                    sessionJti,
                    combinedScore,
                    error: stepupErr.message
                });

                return res.status(200).json({
                    action: 'medium',
                    request_id: requestId,
                    reason: 'step_up_creation_failed'
                });
            }
        }

        return res.status(200).json({ action: combinedAction, request_id: requestId });
    } catch (err) {
        console.error('[ERROR] behavior.js engine call failed:', err.message);

        return res.status(200).json({ action: 'low', request_id: requestId });
    }
}
