import { pool } from './db.js';

let _ensurePromise = null;

export async function ensureLoginRisksSchema() {
    if (_ensurePromise) return _ensurePromise;
    _ensurePromise = (async () => {
        // สร้างตารางก่อนถ้ายังไม่มี
        try {
            await pool.query(
                `CREATE TABLE IF NOT EXISTS login_risks (
                    id BIGSERIAL PRIMARY KEY,
                    username VARCHAR(32) NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    pre_login_score DOUBLE PRECISION,
                    combined_score DOUBLE PRECISION,
                    combined_action TEXT,
                    session_jti TEXT,
                    last_behavior_at TIMESTAMPTZ,
                    behavior_samples INTEGER DEFAULT 0,
                    is_success BOOLEAN DEFAULT FALSE,
                    mfa_code TEXT,
                    mfa_expires_at TIMESTAMPTZ,
                    mfa_attempts INTEGER DEFAULT 0,
                    total_mfa_attempts INTEGER DEFAULT 0,
                    mfa_resent_at TIMESTAMPTZ,
                    login_ip TEXT
                )`
            );
        } catch { }
        // ALTER TABLE สำหรับตารางที่มีอยู่แล้ว (backward compatibility)
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
    // สร้างตาราง oauth_codes และ oauth_tokens ก่อนถ้ายังไม่มี (เพื่อให้ foreign key ใช้งานได้)
    try {
        await pool.query(
            `CREATE TABLE IF NOT EXISTS oauth_codes (
                id BIGSERIAL PRIMARY KEY,
                code_hash TEXT NOT NULL UNIQUE,
                client_id TEXT NOT NULL,
                username VARCHAR(32) NOT NULL,
                redirect_uri TEXT NOT NULL,
                scope TEXT,
                expires_at TIMESTAMPTZ NOT NULL,
                used_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )`
        );
    } catch { }
    try {
        await pool.query(
            `CREATE TABLE IF NOT EXISTS oauth_tokens (
                id BIGSERIAL PRIMARY KEY,
                token_hash TEXT NOT NULL UNIQUE,
                token_type TEXT NOT NULL,
                client_id TEXT NOT NULL,
                username VARCHAR(32) NOT NULL,
                scope TEXT,
                expires_at TIMESTAMPTZ NOT NULL,
                revoked_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )`
        );
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
    // สร้างตาราง oauth_clients ก่อนถ้ายังไม่มี
    try {
        await pool.query(
            `CREATE TABLE IF NOT EXISTS oauth_clients (
                client_id TEXT PRIMARY KEY,
                client_secret_hash TEXT,
                name TEXT NOT NULL,
                redirect_uris TEXT[] NOT NULL,
                allowed_scopes TEXT[] NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                client_type TEXT DEFAULT 'confidential'
            )`
        );
    } catch { }
    try {
        await pool.query(`ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS client_type TEXT DEFAULT 'confidential'`);
    } catch { }
    try {
        await pool.query(`ALTER TABLE oauth_clients ADD CONSTRAINT IF NOT EXISTS valid_client_type CHECK (client_type IN ('confidential', 'public'))`);
    } catch { }
}

export async function ensureUsersSchema() {
    // สร้างตาราง users ถ้ายังไม่มี (พื้นฐานสำหรับ verifySessionCookie)
    try {
        await pool.query(
            `CREATE TABLE IF NOT EXISTS users (
                username VARCHAR(32) PRIMARY KEY,
                password_hash TEXT NOT NULL,
                email TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                sessions_revoked_at TIMESTAMPTZ
            )`
        );
    } catch { }
}

export async function ensureRevokedTokensSchema() {
    // สร้างตาราง revoked_tokens ถ้ายังไม่มี (สำหรับ verifySessionCookie)
    try {
        await pool.query(
            `CREATE TABLE IF NOT EXISTS revoked_tokens (
                jti TEXT PRIMARY KEY,
                expires_at TIMESTAMPTZ NOT NULL
            )`
        );
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
        ipChangeBoost: 0.25,
    };
}

export function combineRisk(preLoginScore, behaviorScore, { ipChanged = false } = {}) {
    const { w1, w2, ipChangeBoost } = getCombinedConfig();
    let score = w1 * clamp01(preLoginScore) + w2 * clamp01(behaviorScore);
    if (ipChanged) score += ipChangeBoost;
    return clamp01(score);
}

export function actionFromCombinedScore(combinedScore) {
    const { medium, revoke } = getCombinedConfig();
    const s = clamp01(combinedScore);
    if (s >= revoke) return 'revoke';
    if (s >= medium) return 'medium';
    return 'low';
}
