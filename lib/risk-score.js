import { pool } from './db.js';

let _ensurePromise = null;

export async function ensureLoginRisksSchema() {
    if (_ensurePromise) return _ensurePromise;
    _ensurePromise = (async () => {
        const statements = [
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS pre_login_score DOUBLE PRECISION`,
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS combined_score DOUBLE PRECISION`,
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS combined_action TEXT`,
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS session_jti TEXT`,
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS last_behavior_at TIMESTAMPTZ`,
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS behavior_samples INTEGER DEFAULT 0`,
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS is_success BOOLEAN DEFAULT FALSE`,
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS mfa_code TEXT`,
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS mfa_expires_at TIMESTAMPTZ`,
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS mfa_attempts INTEGER DEFAULT 0`,
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS total_mfa_attempts INTEGER DEFAULT 0`,
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS mfa_resent_at TIMESTAMPTZ`,
            `ALTER TABLE login_risks ADD COLUMN IF NOT EXISTS login_ip TEXT`,
        ];
        for (const sql of statements) {
            try { await pool.query(sql); } catch { }
        }
        try {
            await pool.query(
                `CREATE INDEX IF NOT EXISTS login_risks_session_jti_idx ON login_risks (username, session_jti)`
            );
        } catch { }
        try {
            await pool.query(
                `CREATE INDEX IF NOT EXISTS login_risks_is_success_idx ON login_risks (username, is_success, created_at DESC)`
            );
        } catch { }
    })();
    return _ensurePromise;
}

export async function ensureBehaviorRisksSchema() {
    await ensureLoginRisksSchema();
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
    } catch { }
    try {
        await pool.query(`ALTER TABLE behavior_risks DROP COLUMN IF EXISTS engine_action`);
    } catch { }
    try {
        await pool.query(`ALTER TABLE behavior_risks ADD COLUMN IF NOT EXISTS request_id TEXT`);
    } catch { }
    try {
        await pool.query(`CREATE INDEX IF NOT EXISTS behavior_risks_session_idx ON behavior_risks (username, session_jti, created_at DESC)`);
    } catch { }
    try {
        await pool.query(`CREATE INDEX IF NOT EXISTS behavior_risks_request_id_idx ON behavior_risks (request_id)`);
    } catch { }
    try {
        await pool.query(`ALTER TABLE oauth_codes ADD COLUMN IF NOT EXISTS pre_login_log_id BIGINT REFERENCES login_risks(id) ON DELETE SET NULL`);
    } catch { }
    try {
        await pool.query(`ALTER TABLE oauth_tokens ADD COLUMN IF NOT EXISTS pre_login_log_id BIGINT REFERENCES login_risks(id) ON DELETE SET NULL`);
    } catch { }
    try {
        await pool.query(`ALTER TABLE oauth_tokens ADD COLUMN IF NOT EXISTS pre_login_score DOUBLE PRECISION`);
    } catch { }
    try {
        await pool.query(`ALTER TABLE oauth_tokens ADD COLUMN IF NOT EXISTS risk_level TEXT DEFAULT 'LOW'`);
    } catch { }
    try {
        await pool.query(`ALTER TABLE oauth_tokens ADD COLUMN IF NOT EXISTS step_up_required BOOLEAN DEFAULT FALSE`);
    } catch { }
}

export async function ensureUserDevicesSchema() {
    try {
        await pool.query(
            `CREATE TABLE IF NOT EXISTS user_devices (
                id BIGSERIAL PRIMARY KEY,
                username VARCHAR(32) NOT NULL,
                device TEXT,
                fingerprint TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE (username, fingerprint)
            )`
        );
    } catch { }
    try {
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_user_devices_username ON user_devices (username)`);
    } catch { }
    try {
        await pool.query(`ALTER TABLE user_devices ADD COLUMN IF NOT EXISTS device TEXT`);
    } catch { }
}

export async function ensureOAuthClientsSchema() {
    try {
        await pool.query(`ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS client_type TEXT DEFAULT 'confidential'`);
    } catch { }
    try {
        await pool.query(`ALTER TABLE oauth_clients ADD CONSTRAINT IF NOT EXISTS valid_client_type CHECK (client_type IN ('confidential', 'public'))`);
    } catch { }
}

export async function ensureStepupChallengesSchema() {
    try {
        await pool.query(
            `CREATE TABLE IF NOT EXISTS stepup_challenges (
                id UUID PRIMARY KEY,
                username TEXT NOT NULL,
                session_jti TEXT,
                code_hash TEXT NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                verified_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )`
        );
    } catch { }
    try {
        await pool.query(`ALTER TABLE stepup_challenges ADD COLUMN IF NOT EXISTS session_jti TEXT`);
    } catch { }
    try {
        await pool.query(`CREATE INDEX IF NOT EXISTS stepup_challenges_user_time_idx ON stepup_challenges (username, created_at DESC)`);
    } catch { }
    try {
        await pool.query(`CREATE INDEX IF NOT EXISTS stepup_challenges_session_idx ON stepup_challenges (username, session_jti, created_at DESC)`);
    } catch { }
}

function clamp01(x) {
    const n = Number(x);
    if (!Number.isFinite(n)) return 0;
    if (n < 0) return 0;
    if (n > 1) return 1;
    return n;
}

export function getCombinedConfig() {
    return {
        w1: 0.3,
        w2: 0.7,
        medium: 0.5,
        revoke: 0.85,
    };
}

export function combineRisk(preLoginScore, behaviorScore) {
    const { w1, w2 } = getCombinedConfig();
    const score = w1 * clamp01(preLoginScore) + w2 * clamp01(behaviorScore);
    return clamp01(score);
}

export function actionFromCombinedScore(combinedScore) {
    const { medium, revoke } = getCombinedConfig();
    const s = clamp01(combinedScore);
    if (s >= revoke) return 'revoke';
    if (s >= medium) return 'medium';
    return 'low';
}
