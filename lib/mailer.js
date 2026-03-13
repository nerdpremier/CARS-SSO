// ============================================================
// 📧 mailer.js — Shared Nodemailer Transporter
//
// สร้าง transporter ครั้งเดียวตอน module load (cold start)
// แทนการสร้างใหม่ใน auth.js, resend-mfa.js, forgot-password.js
//
// ทำไมต้อง module-level transporter:
//   serverless warm instance: connection reuse ลด SMTP handshake overhead
//   สร้างใหม่ต่อ request → TCP connect + TLS handshake ทุกครั้ง = latency สูง
//
// Module load order:
//   ไฟล์นี้ไม่ import startup-check.js โดยตรง
//   caller (auth.js, resend-mfa.js, forgot-password.js) import startup-check.js เป็นอันดับแรก
//   → EMAIL_USER / EMAIL_PASS ถูกตรวจแล้วก่อนที่ mailer.js จะถูก import
// ============================================================
import nodemailer from 'nodemailer';

/**
 * Module-level transporter — สร้างครั้งเดียว ใช้ร่วมกันทุก module ที่ import
 * EMAIL_USER และ EMAIL_PASS ถูกตรวจโดย startup-check.js แล้ว
 */
export const mailTransporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,        // STARTTLS (ไม่ใช่ SSL direct)
    // requireTLS: บังคับ STARTTLS upgrade เสมอ — ป้องกัน fallback ไป plaintext
    // ถ้า SMTP server ไม่ support STARTTLS → throw error แทนส่ง plaintext
    // สำคัญมาก: MFA code และ reset link ต้องเข้ารหัสระหว่างส่ง
    requireTLS: true,
    // tls.minVersion: ล็อก TLS version ขั้นต่ำเป็น 1.2
    //   requireTLS: true บังคับ STARTTLS แต่ไม่ล็อก TLS version
    //   → SMTP server ที่ negotiate TLSv1.0/1.1 ได้จะยังผ่าน (BEAST, POODLE)
    //   TLSv1.2: minimum ที่ NIST SP 800-52r2 แนะนำ, Gmail รองรับ TLSv1.2+ แน่นอน
    tls: { minVersion: 'TLSv1.2' },
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});
