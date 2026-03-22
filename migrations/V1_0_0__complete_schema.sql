-- =====================================================================
-- B-SSO Schema Completion Migration
-- Run this AFTER sso_schema.sql on new deployments
-- Or run on existing databases to add missing columns and tables
--
-- Version: 1.0.0
-- Date: 2026-03-22
-- =====================================================================

-- Migration tracking (optional - create this table first)
CREATE TABLE IF NOT EXISTS schema_migrations (
    id SERIAL PRIMARY KEY,
    version VARCHAR(20) NOT NULL UNIQUE,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    description TEXT
);

-- Record this migration
INSERT INTO schema_migrations (version, description)
VALUES ('1.0.0', 'Complete schema with behavior_risks, stepup_challenges, and missing columns')
ON CONFLICT DO NOTHING;

-- =====================================================================
-- 1. COMPLETE login_risks TABLE
-- Add columns that were previously added at runtime
-- =====================================================================

DO $$
BEGIN
    -- Add pre_login_score column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'login_risks' AND column_name = 'pre_login_score'
    ) THEN
        ALTER TABLE login_risks ADD COLUMN pre_login_score DOUBLE PRECISION;
        RAISE NOTICE 'Added column: login_risks.pre_login_score';
    END IF;

    -- Add combined_score column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'login_risks' AND column_name = 'combined_score'
    ) THEN
        ALTER TABLE login_risks ADD COLUMN combined_score DOUBLE PRECISION;
        RAISE NOTICE 'Added column: login_risks.combined_score';
    END IF;

    -- Add combined_action column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'login_risks' AND column_name = 'combined_action'
    ) THEN
        ALTER TABLE login_risks ADD COLUMN combined_action TEXT;
        RAISE NOTICE 'Added column: login_risks.combined_action';
    END IF;

    -- Add session_jti column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'login_risks' AND column_name = 'session_jti'
    ) THEN
        ALTER TABLE login_risks ADD COLUMN session_jti TEXT;
        RAISE NOTICE 'Added column: login_risks.session_jti';
    END IF;

    -- Add last_behavior_at column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'login_risks' AND column_name = 'last_behavior_at'
    ) THEN
        ALTER TABLE login_risks ADD COLUMN last_behavior_at TIMESTAMPTZ;
        RAISE NOTICE 'Added column: login_risks.last_behavior_at';
    END IF;

    -- Add behavior_samples column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'login_risks' AND column_name = 'behavior_samples'
    ) THEN
        ALTER TABLE login_risks ADD COLUMN behavior_samples INTEGER DEFAULT 0;
        RAISE NOTICE 'Added column: login_risks.behavior_samples';
    END IF;

    -- Ensure is_success column exists (may already exist from CREATE TABLE)
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'login_risks' AND column_name = 'is_success'
    ) THEN
        ALTER TABLE login_risks ADD COLUMN is_success BOOLEAN DEFAULT FALSE;
        RAISE NOTICE 'Added column: login_risks.is_success';
    END IF;

    -- Add MFA-related columns if missing
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'login_risks' AND column_name = 'mfa_code'
    ) THEN
        ALTER TABLE login_risks ADD COLUMN mfa_code TEXT;
        RAISE NOTICE 'Added column: login_risks.mfa_code';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'login_risks' AND column_name = 'mfa_expires_at'
    ) THEN
        ALTER TABLE login_risks ADD COLUMN mfa_expires_at TIMESTAMPTZ;
        RAISE NOTICE 'Added column: login_risks.mfa_expires_at';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'login_risks' AND column_name = 'mfa_attempts'
    ) THEN
        ALTER TABLE login_risks ADD COLUMN mfa_attempts INTEGER DEFAULT 0;
        RAISE NOTICE 'Added column: login_risks.mfa_attempts';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'login_risks' AND column_name = 'total_mfa_attempts'
    ) THEN
        ALTER TABLE login_risks ADD COLUMN total_mfa_attempts INTEGER DEFAULT 0;
        RAISE NOTICE 'Added column: login_risks.total_mfa_attempts';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'login_risks' AND column_name = 'mfa_resent_at'
    ) THEN
        ALTER TABLE login_risks ADD COLUMN mfa_resent_at TIMESTAMPTZ;
        RAISE NOTICE 'Added column: login_risks.mfa_resent_at';
    END IF;
END $$;

-- =====================================================================
-- 2. CREATE behavior_risks TABLE
-- Stores post-login behavioral risk assessments
-- =====================================================================

CREATE TABLE IF NOT EXISTS behavior_risks (
    id BIGSERIAL PRIMARY KEY,
    request_id TEXT,
    username VARCHAR(32) NOT NULL,
    session_jti TEXT NOT NULL,
    behavior_score DOUBLE PRECISION,
    combined_score DOUBLE PRECISION,
    combined_action TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for behavior_risks
CREATE INDEX IF NOT EXISTS idx_behavior_risks_username
ON behavior_risks (username);

CREATE INDEX IF NOT EXISTS idx_behavior_risks_session
ON behavior_risks (username, session_jti, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_behavior_risks_request_id
ON behavior_risks (request_id);

-- Index for escalation logic (3 mediums in session = revoke)
CREATE INDEX IF NOT EXISTS idx_behavior_risks_escalation
ON behavior_risks (username, session_jti, combined_action, created_at);

-- Index for time-based cleanup
CREATE INDEX IF NOT EXISTS idx_behavior_risks_created
ON behavior_risks (created_at);

-- =====================================================================
-- 3. CREATE stepup_challenges TABLE
-- Stores step-up authentication challenges
-- =====================================================================

CREATE TABLE IF NOT EXISTS stepup_challenges (
    id UUID PRIMARY KEY,
    username VARCHAR(32) NOT NULL,
    session_jti TEXT,
    code_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for stepup_challenges
CREATE INDEX IF NOT EXISTS idx_stepup_challenges_user_time
ON stepup_challenges (username, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_stepup_challenges_session
ON stepup_challenges (username, session_jti, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_stepup_challenges_expires
ON stepup_challenges (expires_at);

-- =====================================================================
-- 4. ADD MISSING INDEXES TO EXISTING TABLES
-- =====================================================================

-- Index for session_jti lookups in login_risks
CREATE INDEX IF NOT EXISTS idx_login_risks_session_jti
ON login_risks (username, session_jti);

-- Index for is_success lookups (used in many queries)
CREATE INDEX IF NOT EXISTS idx_login_risks_is_success
ON login_risks (username, is_success, created_at DESC);

-- Composite index for pre-login score lookups by session
CREATE INDEX IF NOT EXISTS idx_login_risks_prelogin_session
ON login_risks (username, session_jti, is_success, created_at DESC);

-- Index for revoked_tokens jti + expires (used in session verification)
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_jti_expires
ON revoked_tokens (jti, expires_at);

-- Index for rate_limit_events cleanup
CREATE INDEX IF NOT EXISTS idx_rate_limit_events_created
ON rate_limit_events (created_at);

-- =====================================================================
-- 5. ADD FOREIGN KEY CONSTRAINTS (OPTIONAL)
-- Uncomment if you want strict referential integrity
-- WARNING: May impact performance on high-volume inserts
-- =====================================================================

-- ALTER TABLE login_risks
-- ADD CONSTRAINT fk_login_risks_username
-- FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE;

-- ALTER TABLE behavior_risks
-- ADD CONSTRAINT fk_behavior_risks_username
-- FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE;

-- ALTER TABLE stepup_challenges
-- ADD CONSTRAINT fk_stepup_challenges_username
-- FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE;

-- =====================================================================
-- 6. VERIFY COMPLETION
-- =====================================================================

DO $$
DECLARE
    table_count INT;
    column_count INT;
    index_count INT;
BEGIN
    -- Count tables
    SELECT COUNT(*) INTO table_count
    FROM information_schema.tables
    WHERE table_schema = 'public'
    AND table_name IN ('users', 'email_verifications', 'login_risks', 'user_devices',
                       'revoked_tokens', 'sso_tokens', 'rate_limit_events',
                       'oauth_clients', 'oauth_codes', 'oauth_tokens',
                       'behavior_risks', 'stepup_challenges');

    -- Count new columns in login_risks
    SELECT COUNT(*) INTO column_count
    FROM information_schema.columns
    WHERE table_name = 'login_risks'
    AND column_name IN ('pre_login_score', 'combined_score', 'combined_action',
                        'session_jti', 'last_behavior_at', 'behavior_samples');

    -- Count indexes
    SELECT COUNT(*) INTO index_count
    FROM pg_indexes
    WHERE schemaname = 'public'
    AND indexname IN ('idx_behavior_risks_session', 'idx_stepup_challenges_user_time',
                      'idx_login_risks_session_jti', 'idx_revoked_tokens_jti_expires');

    RAISE NOTICE '========================================';
    RAISE NOTICE 'Migration Summary:';
    RAISE NOTICE '  - Tables present: %/12', table_count;
    RAISE NOTICE '  - New login_risks columns: %/6', column_count;
    RAISE NOTICE '  - New indexes: %/4', index_count;
    RAISE NOTICE '========================================';
END $$;

-- =====================================================================
-- END OF MIGRATION
-- =====================================================================
