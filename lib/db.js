// ============================================================
// 🗄️ db.js — PostgreSQL Connection Pool
// ทำหน้าที่สร้างและ export connection pool ที่ใช้ร่วมกันทุก handler
//
// ทำไมต้อง module-level pool (ไม่สร้างใหม่ต่อ request):
//   serverless warm instance รัน handler หลาย request ต่อเนื่อง
//   pool สร้างครั้งเดียวตอน cold start → connections ถูก reuse
//   สร้างใหม่ต่อ request → connection overhead ทุกครั้ง + connection leak ได้
//
// Connection lifecycle:
//   handler เรียก pool.connect() → ได้ client → ใช้งาน → client.release()
//   pool จัดการ connection recycling, idle timeout, และ error recovery เอง
// ============================================================
import '../startup-check.js';
import pkg from 'pg';
const { Pool } = pkg;

export const pool = new Pool({
    // DATABASE_URL: ตรวจแล้วตอน cold start โดย startup-check.js
    connectionString: process.env.DATABASE_URL,

    // SSL: rejectUnauthorized: true ใน production — ตรวจ server certificate
    //   ป้องกัน MITM attack ระหว่าง app server และ DB server
    //   rejectUnauthorized: false ใน dev — รองรับ self-signed cert บน local DB
    ssl: process.env.NODE_ENV === 'production'
        ? { rejectUnauthorized: true }
        : { rejectUnauthorized: false },

    // max: จำนวน connections สูงสุดใน pool
    //   Vercel serverless: แต่ละ instance มีอิสระ → connections จริง = max × instances
    //   DB server ต้องรองรับ max × expected_concurrent_instances connections
    max: 10,

    // idleTimeoutMillis: ปิด connection ที่ไม่ได้ใช้นานกว่า 30 วินาที
    //   ลด idle connection ที่กิน resource บน DB server
    idleTimeoutMillis: 30_000,

    // connectionTimeoutMillis: timeout เมื่อรอ connection จาก pool นานกว่า 5 วินาที
    //   throw error แทนรอไม่จำกัด ป้องกัน handler แขวนค้างเมื่อ DB overload
    connectionTimeoutMillis: 5_000,
});

// ── Unexpected pool error handler ────────────────────────────
// pool.on('error') จับ error จาก idle client ที่ไม่ได้อยู่ใน handler
//   เช่น connection ถูกตัดโดย DB server (restart, network drop, idle timeout)
//   ถ้าไม่มี handler: Node.js throw uncaught error → process crash บน non-serverless
//
// ใช้ structured JSON เหมือน auditLog ทุกไฟล์ เพื่อให้ log aggregator parse ได้เหมือนกัน
// log err.code ด้วย: PostgreSQL/Node error codes ช่วย debug
//   เช่น ECONNRESET (network drop), 57P01 (admin shutdown), 53300 (too many connections)
pool.on('error', (err) => {
    console.error(JSON.stringify({
        event: 'DB_POOL_ERROR',
        ts:    new Date().toISOString(),
        error: err.message,
        code:  err.code,
    }));
});
