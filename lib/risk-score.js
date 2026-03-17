import { pool } from './db.js';

let _ensurePromise = null;

export async function ensureLoginRisksSchema() {
    if (_ensurePromise) return _ensurePromise;
    _ensurePromise = (async () => {
        // Best-effort, idempotent schema evolution for existing deployments.
        // This avoids a separate migration pipeline in Vercel serverless.
        const statements = [
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS pre_login_score DOUBLE PRECISION`,
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS combined_score DOUBLE PRECISION`,
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS combined_action TEXT`,
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS session_jti TEXT`,
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS last_behavior_at TIMESTAMPTZ`,
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS behavior_samples INTEGER DEFAULT 0`,
        ];
        for (const sql of statements) {
            try { await pool.query(sql); } catch { /* ignore */ }
        }
        // helpful index for fast lookup by session
        try {
            await pool.query(
                `CREATE INDEX IF NOT EXISTS login_risks_session_jti_idx
                 ON login_risks (username, session_jti)`
            );
        } catch { /* ignore */ }
    })();
    return _ensurePromise;
}

export async function ensureBehaviorRisksSchema() {
    await ensureLoginRisksSchema();

    // Separate table for post-login behavior risk samples
    try {
        await pool.query(
            `CREATE TABLE IF NOT EXISTS behavior_risks (
                id BIGSERIAL PRIMARY KEY,
                request_id TEXT,
                username TEXT NOT NULL,
                session_jti TEXT NOT NULL,
                behavior_score DOUBLE PRECISION,
                combined_score DOUBLE PRECISION,
                combined_action TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )`
        );
    } catch { /* ignore */ }

    // Remove deprecated column (older deployments)
    try {
        await pool.query(
            `ALTER TABLE behavior_risks DROP COLUMN IF EXISTS engine_action`
        );
    } catch { /* ignore */ }

    try {
        await pool.query(
            `ALTER TABLE behavior_risks
             ADD COLUMN IF NOT EXISTS request_id TEXT`
        );
    } catch { /* ignore */ }

    try {
        await pool.query(
            `CREATE INDEX IF NOT EXISTS behavior_risks_session_idx
             ON behavior_risks (username, session_jti, created_at DESC)`
        );
    } catch { /* ignore */ }

    try {
        await pool.query(
            `CREATE INDEX IF NOT EXISTS behavior_risks_request_id_idx
             ON behavior_risks (request_id)`
        );
    } catch { /* ignore */ }
}

export async function ensureStepupChallengesSchema() {
    try {
        await pool.query(
            `CREATE TABLE IF NOT EXISTS stepup_challenges (
                id UUID PRIMARY KEY,
                username TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                verified_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )`
        );
    } catch { /* ignore */ }

    try {
        await pool.query(
            `CREATE INDEX IF NOT EXISTS stepup_challenges_user_time_idx
             ON stepup_challenges (username, created_at DESC)`
        );
    } catch { /* ignore */ }
}

function clamp01(x) {
    const n = Number(x);
    if (!Number.isFinite(n)) return 0;
    if (n < 0) return 0;
    if (n > 1) return 1;
    return n;
}

export function getCombinedConfig() {
    const w1 = Number(process.env.RISK_W1 ?? '0.5');
    const w2 = Number(process.env.RISK_W2 ?? '0.5');
    const medium = Number(process.env.RISK_COMBINED_MEDIUM_THRESHOLD ?? '0.5');
    const revoke = Number(process.env.RISK_COMBINED_REVOKE_THRESHOLD ?? '0.85');
    return {
        w1: Number.isFinite(w1) ? w1 : 0.5,
        w2: Number.isFinite(w2) ? w2 : 0.5,
        medium: Number.isFinite(medium) ? medium : 0.5,
        revoke: Number.isFinite(revoke) ? revoke : 0.85,
    };
}

export function combineRisk(preLoginScore, behaviorScore) {
    const { w1, w2 } = getCombinedConfig();
    return clamp01(w1 * clamp01(preLoginScore) + w2 * clamp01(behaviorScore));
}

export function actionFromCombinedScore(combinedScore) {
    const { medium, revoke } = getCombinedConfig();
    const s = clamp01(combinedScore);
    if (s >= revoke) return 'revoke';
    if (s >= medium) return 'medium';
    return 'low';
}

