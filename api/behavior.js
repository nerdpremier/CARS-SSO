// ============================================================
// Post‑Login Behavior Proxy
//
// รับข้อมูล behavior จากเว็บลูกค้า (ผ่าน browser → SSO)
// แล้ว proxy ต่อไปยัง risk engine ที่ deploy บน Railway
//
// Contract ฝั่ง frontend (เว็บลูกค้า):
//   - เรียกทุก ๆ 15 วินาทีขณะ user ยังมี session อยู่
//   - ส่งข้อมูลเป็น JSON:
//       {
//         events: [ ... ],          // array ของ event objects (any structure)
//         page:   string,           // optional: path/URL ปัจจุบัน
//         meta:   { ... }           // optional: userAgent ฯลฯ
//       }
//
// Contract กับ Railway engine:
//   - POST ไปที่ process.env.RISK_ENGINE_URL (แนะนำให้ชี้ไปที่ /score)
//     ด้วย JSON ของ BehaviorPayload
//
//   - engine ต้องตอบเป็น JSON:
//       { normalized: number, raw_score?: number }
//
//   - การตัดสิน action (low/medium/revoke) ทำที่ SSO จาก combined score เท่านั้น
//
//   - ถ้า engine ล่ม / timeout: เรา fail‑open เป็น action: 'low'
//     เพื่อไม่ล็อก user ทั้งระบบเพราะปัญหาภายใน engine
// ============================================================

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
import { ensureBehaviorRisksSchema, combineRisk, actionFromCombinedScore } from '../lib/risk-score.js';

const ENGINE_URL        = process.env.RISK_ENGINE_URL;
const ENGINE_API_KEY    = process.env.RISK_ENGINE_API_KEY;
const RISK_SHARED_SECRET = process.env.RISK_ENGINE_SHARED_SECRET;

/**
 * คำนวณค่า hash ของ token ด้วยอัลกอริทึม SHA-256 เพื่อความปลอดภัยในการตรวจสอบ
 * @param {string} token - ข้อมูล token ที่ต้องการนำมา hash
 * @returns {string} ค่า hash ในรูปแบบเลขฐานสิบหก (hex string)
 */
function hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * สร้าง digital signature สำหรับยืนยันตัวตนกับระบบ Risk Engine ภายนอก
 * โดยใช้ HMAC-SHA256 กับ timestamp, nonce และ hash ของข้อมูล body
 * @param {string} timestamp - เวลาที่ส่ง request (ISO string)
 * @param {string} nonce - ตัวเลขสุ่มแบบ UUID ป้องกัน Replay Attack
 * @param {string} body - ข้อมูลพฤติกรรมในรูปแบบ JSON string
 * @returns {string|null} ค่า signature ในรูปแบบ base64url หรือ null หากไม่ได้ตั้งค่า Secret
 */
function signForRiskEngine(timestamp, nonce, body) {
    if (!RISK_SHARED_SECRET) return null;
    const bodyHash = crypto.createHash('sha256').update(body).digest('hex');
    const base = `${timestamp}\n${nonce}\n${bodyHash}`;
    return crypto.createHmac('sha256', RISK_SHARED_SECRET).update(base).digest('base64url');
}

/**
 * API Handler หลักสำหรับรับข้อมูลพฤติกรรมการใช้งาน (Behavioral Data) ของผู้ใช้
 * หน้าที่:
 * 1. ตรวจสอบการ Authentication ของผู้ใช้ (รองรับทั้ง Session Cookie และ OAuth Bearer)
 * 2. คัดกรองและปรับรูปแบบข้อมูลคุณลักษณะ (Feature Extraction) ให้อยู่ในช่วง 0-1
 * 3. ส่งต่อข้อมูลไปยังระบบ Risk Engine เพื่อประเมินคะแนนความเสี่ยง (Behavior Score)
 * 4. นำคะแนนมาประมวลผลร่วมกับความเสี่ยงเริ่มต้น (Pre-login Score) เพื่อตัดสินใจ Action
 * @param {import('http').IncomingMessage} req - HTTP Request object
 * @param {import('http').ServerResponse} res - HTTP Response object
 * @returns {Promise<void>}
 */
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
            // ให้ frontend ทราบว่า request นี้ถูก drop แต่ไม่บังคับ logout
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
    let authType = null; // 'session_cookie' | 'oauth_bearer'

    // ── Auth path A: same-origin SSO session cookie (legacy) ──
    if (sessionCookieToken) {
        let decoded;
        try {
            decoded = jwt.verify(sessionCookieToken, process.env.JWT_SECRET, {
                issuer:   'auth-service',
                audience: 'api'
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
        // ── Auth path B: OAuth access_token (opaque) from client app ──
        const token = authHeader.slice(7).trim();
        if (!token || token.length > 128) {
            res.setHeader('WWW-Authenticate', 'Bearer realm="oauth", error="invalid_token"');
            return res.status(401).json({ action: 'revoke' });
        }

        try {
            const result = await pool.query(
                `SELECT ot.id, ot.username, ot.expires_at, ot.revoked_at
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
        } catch (dbErr) {
            console.error('[ERROR] behavior.js oauth token lookup failed:', dbErr.message);
            return res.status(500).json({ error: 'Internal server error' });
        }
    } else {
        return res.status(401).json({ action: 'revoke' });
    }

    await ensureBehaviorRisksSchema();

    const { events, page, meta, features } = req.body;

    if (!Array.isArray(events) || events.length === 0) {
        return res.status(400).json({ error: 'events must be a non-empty array' });
    }

    const safeFeatures = features && typeof features === 'object' ? features : {};

    /**
     * ฟังก์ชันสำหรับจำกัดค่าตัวเลขให้อยู่ในช่วง 0 ถึง 1 เท่านั้น
     * ป้องกันไม่ให้ค่า feature มีขนาดเกินขอบเขตที่โมเดลของ Risk Engine คาดหวัง
     * @param {number} x - ค่าตัวเลขที่ต้องการจำกัดขอบเขต
     * @returns {number} ค่าตัวเลขที่ถูกจำกัดให้อยู่ระหว่าง 0 ถึง 1
     */
    function clamp01(x) {
        if (!Number.isFinite(x)) return 0;
        if (x < 0) return 0;
        if (x > 1) return 1;
        return x;
    }

    // map continuous features จาก collector → Isolation Forest feature vector
    const idleRatio           = clamp01(Number(safeFeatures.idle_ratio || 0));
    const interactionDensity  = Number(safeFeatures.interaction_density || 0);
    const normDensity         = clamp01(interactionDensity / 5); // สมมติมากกว่า 5 events/s ถือว่าสูงสุด

    const avgMouseSpeed       = Number(safeFeatures.avg_mouse_speed || 0);
    const mouseSpeedNorm      = clamp01(avgMouseSpeed / 2000);   // ปรับตามค่าที่พบจริง
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

    // แปลงเป็น BehaviorPayload ของ CARS-ENGINE (FastAPI)
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
        // metadata เพิ่มเติม (FastAPI จะเพิกเฉย field ที่ไม่ได้อยู่ใน model)
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
            // fail‑open
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

        const preLoginLogId = req.body?.pre_login_log_id;

        // พยายามดึง pre-login score ถ้ามี
        let loginRiskId = null;
        try {
            // (1B) ถ้ามี pre_login_log_id จากเว็บลูกค้า → ใช้อันนี้ก่อน
            const parsed = Number(preLoginLogId);
            if (Number.isInteger(parsed) && parsed > 0) {
                const byId = await pool.query(
                    `SELECT id, pre_login_score
                     FROM login_risks
                     WHERE id = $1 AND username = $2
                       AND created_at > NOW() - make_interval(mins => $3)
                     ORDER BY created_at DESC
                     LIMIT 1`,
                    [parsed, username, LOGID_TTL_MINUTES]
                );
                if (byId.rows[0]) {
                    loginRiskId = byId.rows[0].id;
                    preLoginScore = Number(byId.rows[0].pre_login_score || 0);
                }
            }
            
            // (2) ถ้าไม่เจอจาก ID ให้ลองหาด้วย session_jti
            if (!loginRiskId && sessionJti) {
                const preRes = await pool.query(
                    `SELECT id, pre_login_score
                     FROM login_risks
                     WHERE username = $1 AND session_jti = $2 AND is_success = TRUE
                     ORDER BY created_at DESC
                     LIMIT 1`,
                    [username, sessionJti]
                );
                if (preRes.rows[0]) {
                    loginRiskId = preRes.rows[0].id;
                    preLoginScore = Number(preRes.rows[0].pre_login_score || 0);
                }
            }
            
            // (3) FINAL FALLBACK: หา pre-login score ล่าสุดของ username ที่ success ภายใน 30 นาที
            if (!loginRiskId) {
                const fallbackRes = await pool.query(
                    `SELECT id, pre_login_score
                     FROM login_risks
                     WHERE username = $1 AND is_success = TRUE
                       AND created_at > NOW() - INTERVAL '30 minutes'
                     ORDER BY created_at DESC
                     LIMIT 1`,
                    [username]
                );
                if (fallbackRes.rows[0]) {
                    loginRiskId = fallbackRes.rows[0].id;
                    preLoginScore = Number(fallbackRes.rows[0].pre_login_score || 0);
                    console.log(`[INFO] behavior.js: Using fallback pre-login score for ${username}, login_risk_id=${loginRiskId}`);
                }
            }
        } catch (preErr) {
            console.error('[WARN] behavior.js pre-login lookup failed:', preErr.message);
        }

        // รวมคะแนนได้ก็ต่อเมื่อมี behaviorScore (จาก engine /score) และมี pre-login score
        if (behaviorScore != null && loginRiskId != null) {
            combinedScore = combineRisk(preLoginScore, behaviorScore);
            combinedAction = actionFromCombinedScore(combinedScore);
            
            // ── Escalation Logic: ถ้าโดน Medium ครบ 3 ครั้งใน session นี้ ให้ครั้งถัดไปเป็น Revoke ทันที ──
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
            // ถ้ายังรวมไม่ได้ ให้ fail-open เป็น low
            combinedScore = null;
            combinedAction = 'low';
        }

        // เก็บ post-login score แยกตาราง "เสมอ" (ทั้ง session_cookie และ oauth_bearer)
        // เพื่อให้เห็นว่า SSO ได้รับ behavior แล้ว แม้ไม่มี pre-login record ให้ combine
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

        // อัปเดตสรุปกลับไปที่ login_risks เฉพาะเมื่อหา record เจอ
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

        // ถ้า combined ตัดสินใจ REVOKE → บันทึกลง revoked_tokens (สำหรับ session) หรือ oauth_tokens (สำหรับ bearer)
        if (combinedAction === 'revoke') {
            if (authType === 'session_cookie') {
                let exp = null;
                try {
                    const decodedUnsafe = jwt.decode(sessionCookieToken);
                    exp = decodedUnsafe && typeof decodedUnsafe.exp === 'number' ? decodedUnsafe.exp : null;
                } catch { /* ignore */ }
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
                    // sessionJti is `oauth:${row.id}`
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

        return res.status(200).json({ action: combinedAction, request_id: requestId });
    } catch (err) {
        console.error('[ERROR] behavior.js engine call failed:', err.message);
        // fail‑open: ไม่ทำให้ user หลุดออกเพราะ engine down
        return res.status(200).json({ action: 'low', request_id: requestId });
    }
}
