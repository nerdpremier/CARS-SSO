-- =====================================================================
-- SCHEMA สำหรับ B-SSO (Behavioral Risk-Based Single Sign-On) (PostgreSQL)
-- VERSION: 2.0.0 (Complete Schema)
-- DATE: 2026-03-22
--
-- รองรับ:
-- - users / auth / email verification
-- - risk-based login (login_risks + user_devices)
-- - MFA via login_risks
-- - session revocation (revoked_tokens)
-- - one-time SSO redirect tokens (sso_tokens)
-- - OAuth 2.0 / OIDC (clients, codes, tokens)
-- - rate limiting (rate_limit_events)
-- - behavioral risk analysis (behavior_risks)
-- - step-up authentication (stepup_challenges)
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================
-- 1) USERS
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id                  BIGSERIAL      PRIMARY KEY,
    username            VARCHAR(32)    NOT NULL UNIQUE,
    email               VARCHAR(254)   NOT NULL UNIQUE,
    password_hash       TEXT           NOT NULL,
    email_verified      BOOLEAN        NOT NULL DEFAULT FALSE,
    sessions_revoked_at TIMESTAMPTZ    NULL,
    created_at          TIMESTAMPTZ    NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);
CREATE INDEX IF NOT EXISTS idx_users_email_lower ON users ((LOWER(email)));

-- ============================================================
-- 2) EMAIL VERIFICATION
-- ============================================================
CREATE TABLE IF NOT EXISTS email_verifications (
    id         BIGSERIAL    PRIMARY KEY,
    user_id    BIGINT       NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash CHAR(64)     NOT NULL UNIQUE,  -- SHA-256 hex
    expires_at TIMESTAMPTZ  NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_email_verifications_user ON email_verifications (user_id);
CREATE INDEX IF NOT EXISTS idx_email_verifications_expires ON email_verifications (expires_at);

-- ============================================================
-- 3) LOGIN RISKS (Pre-login risk assessment + MFA state)
-- ============================================================
CREATE TYPE risk_level AS ENUM ('LOW', 'MEDIUM', 'HIGH');

CREATE TABLE IF NOT EXISTS login_risks (
    id              BIGSERIAL   PRIMARY KEY,
    username        VARCHAR(32) NOT NULL,
    device          TEXT        NOT NULL,        -- device description / UA fingerprint
    fingerprint     TEXT        NOT NULL,        -- stable device fingerprint
    risk_level      risk_level  NOT NULL,
    is_success      BOOLEAN     NOT NULL DEFAULT FALSE,
    total_mfa_attempts INTEGER  NOT NULL DEFAULT 0,

    -- MFA per-login fields
    mfa_code        TEXT        NULL,
    mfa_expires_at  TIMESTAMPTZ NULL,
    mfa_resent_at   TIMESTAMPTZ NULL,
    mfa_attempts    INTEGER     NOT NULL DEFAULT 0,

    -- Behavioral risk fields (v2.0.0)
    pre_login_score     DOUBLE PRECISION,
    combined_score      DOUBLE PRECISION,
    combined_action     TEXT,
    session_jti         TEXT,
    last_behavior_at    TIMESTAMPTZ,
    behavior_samples    INTEGER DEFAULT 0,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_login_risks_username_time
    ON login_risks (username, created_at DESC);

-- Index for session-based lookups (v2.0.0)
CREATE INDEX IF NOT EXISTS idx_login_risks_session_jti
    ON login_risks (username, session_jti);

-- Index for success lookups (v2.0.0)
CREATE INDEX IF NOT EXISTS idx_login_risks_is_success
    ON login_risks (username, is_success, created_at DESC);

-- Composite index for pre-login score lookups (v2.0.0)
CREATE INDEX IF NOT EXISTS idx_login_risks_prelogin_session
    ON login_risks (username, session_jti, is_success, created_at DESC);

-- ============================================================
-- 4) USER DEVICES (remember device)
-- ============================================================
CREATE TABLE IF NOT EXISTS user_devices (
    id          BIGSERIAL   PRIMARY KEY,
    username    VARCHAR(32) NOT NULL,
    fingerprint TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (username, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_user_devices_username ON user_devices (username);

-- ============================================================
-- 5) REVOKED TOKENS (session / oauth revocation)
-- ============================================================
CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti        TEXT        PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires
    ON revoked_tokens (expires_at);

-- Index for jti + expires lookup (v2.0.0)
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_jti_expires
    ON revoked_tokens (jti, expires_at);

-- ============================================================
-- 6) ONE-TIME SSO TOKENS (redirect-back)
-- ============================================================
CREATE TABLE IF NOT EXISTS sso_tokens (
    id         BIGSERIAL    PRIMARY KEY,
    token      UUID         NOT NULL UNIQUE,      -- randomUUID()
    user_id    BIGINT       NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    used       BOOLEAN      NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ  NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sso_tokens_user ON sso_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_sso_tokens_expires ON sso_tokens (expires_at);

-- ============================================================
-- 7) RATE LIMITING EVENTS
-- ============================================================
CREATE TABLE IF NOT EXISTS rate_limit_events (
    id         BIGSERIAL   PRIMARY KEY,
    key        TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rate_limit_events_key_time
    ON rate_limit_events (key, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_rate_limit_events_created
    ON rate_limit_events (created_at);

-- ============================================================
-- 8) OAUTH CLIENTS
-- ============================================================
CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id         TEXT          PRIMARY KEY,       -- e.g. "c_xxx"
    client_secret_hash TEXT         NOT NULL,          -- HMAC-SHA256 (empty for public clients)
    name              TEXT          NOT NULL,
    redirect_uris     TEXT[]        NOT NULL,
    allowed_scopes    TEXT[]        NOT NULL,          -- e.g. ['profile','email']
    client_type       TEXT          NOT NULL DEFAULT 'confidential', -- 'confidential' | 'public'
    owner_username    VARCHAR(32)   NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    created_at        TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CONSTRAINT valid_client_type CHECK (client_type IN ('confidential', 'public'))
);

CREATE INDEX IF NOT EXISTS idx_oauth_clients_owner ON oauth_clients (owner_username);

-- ============================================================
-- 9) OAUTH AUTHORIZATION CODES
-- ============================================================
CREATE TABLE IF NOT EXISTS oauth_codes (
    id                  BIGSERIAL    PRIMARY KEY,
    code_hash           CHAR(64)     NOT NULL UNIQUE,  -- SHA-256 hex
    client_id           TEXT         NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    username            VARCHAR(32)  NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    redirect_uri        TEXT         NOT NULL,
    scope               TEXT[]       NOT NULL,
    code_challenge      TEXT         NULL,
    code_challenge_method TEXT       NULL,
    expires_at          TIMESTAMPTZ  NOT NULL,
    used                BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_oauth_codes_client
    ON oauth_codes (client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_codes_expires
    ON oauth_codes (expires_at);

-- ============================================================
-- 10) OAUTH TOKENS (access / refresh)
-- ============================================================
CREATE TYPE oauth_token_type AS ENUM ('access', 'refresh');

CREATE TABLE IF NOT EXISTS oauth_tokens (
    id          BIGSERIAL        PRIMARY KEY,
    token_hash  CHAR(64)         NOT NULL UNIQUE,   -- SHA-256 hex
    token_type  oauth_token_type NOT NULL,
    client_id   TEXT             NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    username    VARCHAR(32)      NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    scope       TEXT[]           NOT NULL,
    expires_at  TIMESTAMPTZ      NOT NULL,
    revoked_at  TIMESTAMPTZ      NULL,
    created_at  TIMESTAMPTZ      NOT NULL DEFAULT NOW(),
    pre_login_score DOUBLE PRECISION  -- Pre-login risk score from login_risks
);

CREATE INDEX IF NOT EXISTS idx_oauth_tokens_client_user
    ON oauth_tokens (client_id, username);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_expires
    ON oauth_tokens (expires_at);

-- ============================================================
-- 11) BEHAVIOR RISKS (Post-login behavioral analysis)
-- NEW IN v2.0.0
-- ============================================================
CREATE TABLE IF NOT EXISTS behavior_risks (
    id              BIGSERIAL       PRIMARY KEY,
    request_id      TEXT,
    username        VARCHAR(32)     NOT NULL,
    session_jti     TEXT            NOT NULL,
    behavior_score  DOUBLE PRECISION,
    combined_score  DOUBLE PRECISION,
    combined_action TEXT,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_behavior_risks_username
    ON behavior_risks (username);

CREATE INDEX IF NOT EXISTS idx_behavior_risks_session
    ON behavior_risks (username, session_jti, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_behavior_risks_request_id
    ON behavior_risks (request_id);

-- Index for escalation logic (3 mediums = revoke)
CREATE INDEX IF NOT EXISTS idx_behavior_risks_escalation
    ON behavior_risks (username, session_jti, combined_action, created_at);

CREATE INDEX IF NOT EXISTS idx_behavior_risks_created
    ON behavior_risks (created_at);

-- ============================================================
-- 12) STEPUP CHALLENGES (Step-up MFA for OAuth)
-- NEW IN v2.0.0
-- ============================================================
CREATE TABLE IF NOT EXISTS stepup_challenges (
    id          UUID            PRIMARY KEY,
    username    VARCHAR(32)     NOT NULL,
    session_jti TEXT,
    code_hash   TEXT            NOT NULL,
    expires_at  TIMESTAMPTZ     NOT NULL,
    attempts    INTEGER         NOT NULL DEFAULT 0,
    verified_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_stepup_challenges_user_time
    ON stepup_challenges (username, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_stepup_challenges_session
    ON stepup_challenges (username, session_jti, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_stepup_challenges_expires
    ON stepup_challenges (expires_at);

-- ============================================================
-- END OF SCHEMA
-- =====================================================================
