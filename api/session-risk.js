// ============================================================
// 🔄 api/session-risk.js — Continuous Post-Login Risk Scoring
//
// ถูกเรียกจาก client web app ทุก 15 วินาที หลังจาก login สำเร็จแล้ว
// ทำหน้าที่:
//   1. Verify JWT (session_token cookie) — ต้อง login แล้วเท่านั้น
//   2. ตรวจสอบว่า session ถูก revoke ไปแล้วหรือยัง
//   3. เรียก Risk Engine (Isolation Forest) → post-login IF score
//   4. ดึง pre-login score จาก login_risks
//   5. คำนวณ combined score: pre×0.3 + post×0.7
//   6. บันทึกลง session_risks
//   7. คืน action กลับให้ client:
//        ok       → ปกติ (combined < 0.45)
//        warn     → แจ้งเตือน (0.45–0.65)
//        step_up  → บังคับ re-auth (0.65–0.85)
//        revoke   → ยกเลิก session ทันที (> 0.85)
//
// Security:
//   - CSRF required (same pattern กับ endpoint อื่น)
//   - Rate limit: 10 req/นาที ต่อ IP (ป้องกัน abuse แม้มี JWT)
//   - JWT verify ก่อนทุกอย่าง — ไม่มี JWT = 401 ทันที
//   - behavior payload เป็น optional — ถ้าไม่มีหรือ invalid
//     → ใช้ pre_score อย่างเดียว (fail open, ไม่ block user)
//   - revoke ทำผ่าน revoked_tokens (ใช้ pattern เดียวกับ logout.js)
// ============================================================

import '../startup-check.js';
import jwt          from 'jsonwebtoken';
import { parse }    from 'cookie';
import { pool }     from '../lib/db.js';
import { checkRateLimit }    from '../lib/rate-limit.js';
import { getClientIp }       from '../lib/ip-utils.js';
import { validateCsrfToken } from '../lib/csrf-utils.js';
import { fetchBehaviorScore, mergeScores } from '../lib/risk-utils.js';
import {
    setSecurityHeaders, auditLog,
    USER_REGEX,
    isJsonContentType, isValidBody,
} from '../lib/response-utils.js';

// ── Threshold ─────────────────────────────────────────────────
// combined_score = pre×0.3 + post×0.7
//
//  < WARN_THRESHOLD               → ok       (พฤติกรรมปกติ)
//  WARN_THRESHOLD  – STEP_UP      → warn     (น่าสังเกต, แจ้ง user)
//  STEP_UP         – REVOKE       → step_up  (ผิดปกติ, บังคับ re-auth)
//  ≥ REVOKE_THRESHOLD             → revoke   (ผิดมนุษย์, ตัด session ทันที)
const WARN_THRESHOLD    = 0.40;
const STEP_UP_THRESHOLD = 0.60;
const REVOKE_THRESHOLD  = 0.75;


export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).send();

    setSecurityHeaders(res);
    res.setHeader('Cache-Control', 'no-store');

    if (!isJsonContentType(req)) {
        return res.status(415).json({ error: 'Content-Type must be application/json' });
    }

    const ip = getClientIp(req);

    // ── ตรวจ mode การเรียก ──────────────────────────────────────
    // Mode 1: client proxy  → Authorization: Bearer <OAuth access_token>
    // Mode 2: aggregator    → Authorization: Bearer <AGGREGATOR_SECRET>
    // Mode 3: browser       → session_token cookie + CSRF header
    const authHeader  = req.headers['authorization'] || '';
    const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

    const isAggregator = !!( process.env.AGGREGATOR_SECRET &&
                             bearerToken &&
                             bearerToken === process.env.AGGREGATOR_SECRET );

    // ตรวจว่าเป็น OAuth access_token (proxy mode จาก client app)
    let oauthUsername = null;
    if (bearerToken && !isAggregator) {
        try {
            const { createHash } = await import('crypto');
            const tokenHash = createHash('sha256').update(bearerToken).digest('hex');
            const { pool: dbPool } = await import('../lib/db.js');
            const oauthRes = await dbPool.query(
                `SELECT username FROM oauth_tokens
                 WHERE token_hash = $1 AND expires_at > NOW()`,
                [tokenHash]
            );
            if (oauthRes.rows[0]) {
                oauthUsername = oauthRes.rows[0].username;
            }
        } catch { /* fail open */ }
    }

    const isOAuthProxy = !!oauthUsername;

    if (!isAggregator && !isOAuthProxy) {
        // browser mode: ต้องมี CSRF
        if (!validateCsrfToken(req)) {
            return res.status(403).json({ error: 'Invalid CSRF token' });
        }
    }

    try {
        const rlKey = isAggregator ? `aggregator:session-risk` : `ip:${ip}:session-risk`;
        const limit = isAggregator ? 500 : 10;   // aggregator ส่งได้มากกว่า
        if (await checkRateLimit(rlKey, limit, 60_000)) {
            auditLog('SESSION_RISK_RATE_LIMIT', { ip, isAggregator });
            return res.status(429).json({ error: 'Too many requests' });
        }
    } catch (rlErr) {
        console.error('[WARN] rate-limit DB error (session-risk), failing open:', rlErr.message);
    }

    // ── 1. Verify JWT ─────────────────────────────────────────
    // oauth proxy mode → username ได้จาก oauth_tokens แล้ว ข้าม JWT
    // aggregator mode  → อ่านจาก body.session_id
    // browser mode     → อ่านจาก cookie

    // OAuth proxy: ข้าม JWT verify ใช้ username จาก oauth_tokens แทน
    if (isOAuthProxy) {
        // ดึง jti จาก oauth_tokens เพื่อใช้ track session
        let oauthJti = null;
        let oauthPreScore = 0.1;
        try {
            const { pool: dbPool } = await import('../lib/db.js');
            const lr = await dbPool.query(
                `SELECT lr.risk_score_normalized, lr.jti
                 FROM oauth_tokens ot
                 LEFT JOIN login_risks lr ON lr.username = ot.username
                 WHERE ot.token_hash = $1
                 ORDER BY lr.created_at DESC LIMIT 1`,
                [createHash('sha256').update(bearerToken).digest('hex')]
            );
            if (lr.rows[0]) {
                oauthPreScore = lr.rows[0].risk_score_normalized ?? 0.1;
                oauthJti      = lr.rows[0].jti ?? `oauth_${oauthUsername}`;
            }
        } catch { /* fail open */ }

        const behavior    = req.body?.behavior ?? null;
        const rawPostScore = await fetchBehaviorScore(behavior);
        const postScore    = rawPostScore !== null ? rawPostScore : oauthPreScore;
        const combinedScore = mergeScores(oauthPreScore, postScore, { preWeight: 0.3, postWeight: 0.7 });

        let action = combinedScore >= REVOKE_THRESHOLD   ? 'revoke'   :
                     combinedScore >= STEP_UP_THRESHOLD  ? 'step_up'  :
                     combinedScore >= WARN_THRESHOLD     ? 'warn'     : 'ok';

        try {
            const { pool: dbPool } = await import('../lib/db.js');
            await dbPool.query(
                `INSERT INTO session_risks (jti, username, pre_score, post_score, combined_score, action, ip)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
                [oauthJti ?? oauthUsername, oauthUsername,
                 parseFloat(oauthPreScore.toFixed(4)), parseFloat(postScore.toFixed(4)),
                 parseFloat(combinedScore.toFixed(4)), action, ip]
            );
        } catch { /* log fail → ไม่ block */ }

        auditLog('SESSION_RISK_CHECKPOINT', {
            username: oauthUsername, mode: 'oauth_proxy',
            combinedScore: combinedScore.toFixed(4), action, ip,
        });

        return res.status(200).json({ action, combinedScore: parseFloat(combinedScore.toFixed(4)) });
    }

    let token;
    if (isAggregator) {
        if (!isValidBody(req.body) || typeof req.body.session_id !== 'string') {
            return res.status(400).json({ error: 'Missing session_id' });
        }
        token = req.body.session_id;
    } else {
        const cookies = parse(req.headers.cookie || '');
        token = cookies.session_token;
    }
    if (!token) return res.status(401).json({ error: 'Not authenticated' });

    let decoded;
    try {
        decoded = jwt.verify(token, process.env.JWT_SECRET, {
            issuer:   'auth-service',
            audience: 'api',
        });
    } catch {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    if (!decoded.jti) return res.status(401).json({ error: 'Not authenticated' });

    if (!decoded.username ||
        typeof decoded.username !== 'string' ||
        decoded.username.length > 32 ||
        !USER_REGEX.test(decoded.username)) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    // ── 2. ตรวจ revoked / session invalidation ────────────────
    // ใช้ single query เหมือน session.js เพื่อลด round-trips
    let sessionValid = false;
    let preScore     = null;

    try {
        const sessionRes = await pool.query(
            `SELECT
                u.sessions_revoked_at,
                rt.jti                AS revoked_jti,
                lr.risk_score_normalized AS pre_score
             FROM users u
             LEFT JOIN revoked_tokens rt
               ON rt.jti = $2 AND rt.expires_at > NOW()
             LEFT JOIN login_risks lr
               ON lr.jti = $2
             WHERE u.username = $1`,
            [decoded.username, decoded.jti]
        );

        if (!sessionRes.rows[0]) {
            return res.status(401).json({ error: 'Not authenticated' });
        }

        const { sessions_revoked_at, revoked_jti, pre_score: dbPreScore } = sessionRes.rows[0];

        if (revoked_jti) {
            auditLog('SESSION_RISK_REJECTED_REVOKED', { username: decoded.username, jti: decoded.jti, ip });
            return res.status(401).json({ error: 'Session revoked' });
        }

        if (sessions_revoked_at && typeof decoded.iat === 'number') {
            if (new Date(decoded.iat * 1000) < new Date(sessions_revoked_at)) {
                auditLog('SESSION_RISK_REJECTED_PASSWORD_RESET', { username: decoded.username, ip });
                return res.status(401).json({ error: 'Session revoked' });
            }
        }

        sessionValid = true;
        // pre_score ที่เก็บไว้ใน login_risks ตอน assess (normalize 0–1)
        // ถ้ายังไม่มีคอลัมน์นี้ใน DB เดิม → fallback เป็น 0.1 (baseline low risk)
        preScore = typeof dbPreScore === 'number' ? dbPreScore : 0.1;

    } catch (dbErr) {
        console.error('[ERROR] session-risk.js session check:', dbErr.message);
        return res.status(500).json({ error: 'Internal server error' });
    }

    if (!sessionValid) return res.status(401).json({ error: 'Not authenticated' });

    // ── 3. รับ behavior payload ───────────────────────────────
    if (!isValidBody(req.body)) {
        return res.status(400).json({ error: 'Invalid request data' });
    }
    const { behavior } = req.body;

    // ── 4. คำนวณ post-login score จาก Risk Engine ─────────────
    // fetchBehaviorScore คืน null ถ้า engine down หรือ payload ไม่ valid
    const rawPostScore = await fetchBehaviorScore(behavior ?? null);

    // ถ้า engine unavailable → ใช้ pre_score เป็น post_score ด้วย
    // (conservative: ไม่ลด risk โดยไม่มีข้อมูล)
    const postScore = rawPostScore !== null ? rawPostScore : preScore;

    // ── 5. Combined score ─────────────────────────────────────
    // น้ำหนัก: pre 30%, post 70%
    // post ได้น้ำหนักมากกว่าเพราะ:
    //   - เก็บระหว่างใช้งานจริง (บริบทมากกว่า)
    //   - pre เก็บแค่ช่วงสั้น ๆ ตอนกรอก form login
    const combinedScore = mergeScores(preScore, postScore, { preWeight: 0.3, postWeight: 0.7 });

    // ── 6. ตัดสินใจ action ────────────────────────────────────
    let action;
    if      (combinedScore >= REVOKE_THRESHOLD)   action = 'revoke';
    else if (combinedScore >= STEP_UP_THRESHOLD)  action = 'step_up';
    else if (combinedScore >= WARN_THRESHOLD)     action = 'warn';
    else                                          action = 'ok';

    // ── 7. Revoke session ถ้า action = revoke ─────────────────
    if (action === 'revoke') {
        try {
            const expiresAt = new Date(decoded.exp * 1000).toISOString();
            await pool.query(
                'INSERT INTO revoked_tokens (jti, expires_at) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                [decoded.jti, expiresAt]
            );
            auditLog('SESSION_RISK_REVOKED', {
                username: decoded.username,
                jti:      decoded.jti,
                combinedScore,
                preScore,
                postScore,
                ip,
            });
        } catch (revokeErr) {
            console.error('[ERROR] session-risk.js revoke:', revokeErr.message);
            // ถ้า revoke fail → คืน step_up แทน (ไม่ปล่อยให้ผ่านเงียบ ๆ)
            action = 'step_up';
        }
    }

    // ── 8. บันทึกลง session_risks ─────────────────────────────
    try {
        await pool.query(
            `INSERT INTO session_risks
                (jti, username, pre_score, post_score, combined_score, action, ip)
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [
                decoded.jti,
                decoded.username,
                parseFloat(preScore.toFixed(4)),
                parseFloat(postScore.toFixed(4)),
                parseFloat(combinedScore.toFixed(4)),
                action,
                ip,
            ]
        );
    } catch (logErr) {
        // log fail ไม่ควร block response — บันทึก error แล้วไปต่อ
        console.error('[WARN] session-risk.js insert log failed:', logErr.message);
    }

    auditLog('SESSION_RISK_CHECKPOINT', {
        username:      decoded.username,
        jti:           decoded.jti,
        preScore:      preScore.toFixed(4),
        postScore:     postScore.toFixed(4),
        combinedScore: combinedScore.toFixed(4),
        action,
        ip,
    });

    return res.status(200).json({ action, combinedScore: parseFloat(combinedScore.toFixed(4)) });
}
