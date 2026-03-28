import '../startup-check.js';
import { pool } from './db.js';

export async function checkRateLimit(key, maxCount, windowMs) {
    if (!key || typeof key !== 'string') {
        throw new Error(`[rate-limit] key invalid: ${key}`);
    }
    const windowSec = Math.ceil(windowMs / 1000);
    if (!Number.isFinite(windowSec) || windowSec <= 0) {
        throw new Error(`[rate-limit] windowMs invalid: ${windowMs}`);
    }
    if (!Number.isFinite(maxCount) || !Number.isInteger(maxCount) || maxCount <= 0) {
        throw new Error(`[rate-limit] maxCount invalid: ${maxCount}`);
    }
    const result = await pool.query(
        `WITH current_count AS (
             SELECT COUNT(*) AS cnt
             FROM rate_limit_events
             WHERE key = $1
               AND created_at > NOW() - INTERVAL '1 second' * $2
         ),
         new_event AS (
             INSERT INTO rate_limit_events (key)
             SELECT $1
             WHERE (SELECT cnt FROM current_count) < $3
         )
         SELECT (SELECT cnt FROM current_count) AS count`,
        [key, windowSec, maxCount]
    );
    const currentCount = Number(result.rows[0].count);
    if (Math.random() < 0.01) {
        pool.query("DELETE FROM rate_limit_events WHERE created_at < NOW() - INTERVAL '2 hours'")
            .catch(err => console.error('[WARN] rate_limit_events cleanup error:', err.message));
    }
    return currentCount >= maxCount;
}

// Block user for 1 minute after revoke
export async function blockUser(username, ip) {
    if (!username || typeof username !== 'string') return;
    
    try {
        const key = `block:${username}`;
        await pool.query(
            `INSERT INTO rate_limit_events (key, created_at)
             VALUES ($1, NOW())
             ON CONFLICT (key) DO UPDATE
             SET created_at = NOW()`,
            [key]
        );
        // Also block by IP
        if (ip && typeof ip === 'string') {
            const ipKey = `block:ip:${ip}`;
            await pool.query(
                `INSERT INTO rate_limit_events (key, created_at)
                 VALUES ($1, NOW())
                 ON CONFLICT (key) DO UPDATE
                 SET created_at = NOW()`,
                [ipKey]
            );
        }
    } catch (err) {
        console.error('[WARN] blockUser failed:', err.message);
    }
}

// Check if user is blocked
export async function isUserBlocked(username, ip) {
    try {
        // Check username block
        const userKey = `block:${username}`;
        const userResult = await pool.query(
            `SELECT created_at FROM rate_limit_events
             WHERE key = $1 AND created_at > NOW() - INTERVAL '1 minute'`,
            [userKey]
        );
        if (userResult.rows.length > 0) {
            const blockedUntil = new Date(userResult.rows[0].created_at);
            blockedUntil.setMinutes(blockedUntil.getMinutes() + 1);
            const remainingSeconds = Math.ceil((blockedUntil - new Date()) / 1000);
            return { blocked: true, remainingSeconds };
        }
        
        // Check IP block
        if (ip && typeof ip === 'string') {
            const ipKey = `block:ip:${ip}`;
            const ipResult = await pool.query(
                `SELECT created_at FROM rate_limit_events
                 WHERE key = $1 AND created_at > NOW() - INTERVAL '1 minute'`,
                [ipKey]
            );
            if (ipResult.rows.length > 0) {
                const blockedUntil = new Date(ipResult.rows[0].created_at);
                blockedUntil.setMinutes(blockedUntil.getMinutes() + 1);
                const remainingSeconds = Math.ceil((blockedUntil - new Date()) / 1000);
                return { blocked: true, remainingSeconds };
            }
        }
        
        return { blocked: false };
    } catch (err) {
        console.error('[WARN] isUserBlocked failed:', err.message);
        return { blocked: false };
    }
}
