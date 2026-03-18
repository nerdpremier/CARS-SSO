// ============================================================
// จัดการการจำกัดอัตราการร้องขอด้วยฐานข้อมูล
// ใช้กรอบเวลาเลื่อนได้ (sliding window) เพื่อความแม่นยำ
// ป้องกันการโจมตีแบบ boundary exploit
//
// จุดเด่น:
//   - ใช้ฐานข้อมูลแทน memory เพื่อให้ทำงานบน serverless
//   - ใช้ Atomic CTE เพื่อความสมบูรณ์ของข้อมูล
// ============================================================
import '../startup-check.js';
import { pool } from './db.js';

// ตรวจสอบว่าผู้ใช้เกินอัตราการร้องขอที่กำหนดหรือไม่
/**
 * วิธีทำงาน (Atomic CTE — ทุกอย่างเกิดใน query เดียว):
 *   1. current_count — นับ event ของ key ใน window ปัจจุบัน
 *   2. new_event     — INSERT event ใหม่ เฉพาะเมื่อยังไม่เกิน limit
 *                      (ถ้าเกินแล้วไม่ INSERT → ป้องกัน DB write amplification)
 *   3. SELECT        — ส่งคืน count ที่นับได้
 *
 * PostgreSQL CTE snapshot semantics:
 *   ทุก sub-statement ใน WITH ใช้ snapshot เดียวกัน
 *   ดังนั้น INSERT ใน new_event จึงไม่ปรากฏใน COUNT ของ current_count
 *   → count ที่ได้คือจำนวน event ก่อน request นี้ (N-1)
 *   → block เมื่อ count >= maxCount (ไม่ใช่ >) เพื่อชดเชย off-by-one นี้
 *
 * ข้อจำกัด concurrency:
 *   เมื่อ request หลายตัวเข้าพร้อมกันที่ count = maxCount-1
 *   แต่ละตัวเห็น snapshot เดิม → อาจ INSERT พร้อมกันได้ → overrun ได้เล็กน้อย
 *   พฤติกรรมนี้ยอมรับได้สำหรับ rate limiter (strict enforcement ต้องใช้ advisory lock)
 *
 * @param {string} key       - unique key เช่น "ip:1.2.3.4:auth"
 * @param {number} maxCount  - จำนวนสูงสุดที่อนุญาตใน window (positive integer)
 * @param {number} windowMs  - ขนาด window เป็น milliseconds (ต้องมากกว่า 0)
 * @returns {Promise<boolean>} true = เกิน limit (ให้ block), false = ยังไม่เกิน (ให้ผ่าน)
 * @throws {Error} ถ้า argument ไม่ถูกต้องหรือ DB error
 */
export async function checkRateLimit(key, maxCount, windowMs) {
    // ── 1. ตรวจสอบ key ─────────────────────────────────────────────────────
    // null / undefined / "" ทำให้ทุก caller ใช้ key เดียวกัน
    // → rate limit ของ user A อาจ block user B ที่ไม่เกี่ยวข้องกัน
    if (!key || typeof key !== 'string') {
        throw new Error(`[rate-limit] key ไม่ถูกต้อง: ${key}`);
    }

    // ตรวจสอบความถูกต้องของช่วงเวลา
    // make_interval(secs => $2) รับ integer โดยตรง (type-safe กับ pg driver)
    // windowMs=0/NaN/undefined → windowSec ไม่ใช่ positive finite → throw
    const windowSec = Math.ceil(windowMs / 1000);
    if (!Number.isFinite(windowSec) || windowSec <= 0) {
        throw new Error(`[rate-limit] windowMs ไม่ถูกต้อง: ${windowMs}`);
    }

    // ตรวจสอบความถูกต้องของจำนวนสูงสุด
    // maxCount=0   → count(0) >= 0 → block ทุก request ทันที
    // maxCount=NaN → count >= NaN = false → rate limit ไม่ทำงานเลย
    if (!Number.isFinite(maxCount) || !Number.isInteger(maxCount) || maxCount <= 0) {
        throw new Error(`[rate-limit] maxCount ไม่ถูกต้อง: ${maxCount}`);
    }

    // ดำเนินการตรวจสอบแบบ Atomic CTE
    const result = await pool.query(
        `WITH current_count AS (
             SELECT COUNT(*) AS cnt
             FROM   rate_limit_events
             WHERE  key        = $1
               AND  created_at > NOW() - make_interval(secs => $2)
         ),
         new_event AS (
             INSERT INTO rate_limit_events (key)
             SELECT $1
             WHERE  (SELECT cnt FROM current_count) < $3
         )
         SELECT (SELECT cnt FROM current_count) AS count`,
        [key, windowSec, maxCount]
    );

    const currentCount = Number(result.rows[0].count);

    // ลบข้อมูลเก่าแบบสุ่มเพื่อป้องกันฐานข้อมูลโตเกินไป
    // ลบ event เก่ากว่า 2 ชั่วโมง (ซึ่งเกิน window ยาวสุดในระบบ = forgot-password 1h)
    // ป้องกัน table โตสะสมในระยะยาว
    //
    // ข้อจำกัด: cleanup เกิดเฉพาะเมื่อมี request เข้ามา และมีโอกาสแค่ 1%
    //   → สำหรับ production ที่ต้องการ predictable ควรใช้ pg_cron แทน
    if (Math.random() < 0.01) {
        pool
            .query("DELETE FROM rate_limit_events WHERE created_at < NOW() - INTERVAL '2 hours'")
            .catch(err => console.error('[WARN] rate_limit_events cleanup error:', err.message));
    }

    // count ที่ได้ = จำนวน event ก่อน request นี้ (snapshot isolation)
    // ใช้ >= (ไม่ใช่ >) เพื่อชดเชย off-by-one: block เมื่อ "ก่อน request นี้ = maxCount"
    // แปลว่า request นี้จะเป็นตัวที่ maxCount+1 → เกิน limit พอดี
    return currentCount >= maxCount;
}
