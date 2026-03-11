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
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});
