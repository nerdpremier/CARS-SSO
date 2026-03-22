-- =====================================================================
-- B-SSO Schema Audit Fixes Migration
--
-- Version: 1.0.1
-- Date: 2026-03-22
-- =====================================================================

-- Record this migration
INSERT INTO schema_migrations (version, description)
VALUES ('1.0.1', 'Add missing indexes for fingerprint and email')
ON CONFLICT DO NOTHING;

-- 1. ADD MISSING FINGERPRINT INDEX FOR THREAT HUNTING
CREATE INDEX IF NOT EXISTS idx_user_devices_fingerprint ON user_devices (fingerprint);

-- 2. ENSURE STANDARD EMAIL QUERIES USE AN INDEX
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
