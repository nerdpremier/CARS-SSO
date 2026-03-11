// ============================================================
// 🌐 ip-utils.js — Client IP Resolution for Rate Limiting
// ทำหน้าที่ resolve IP address ที่ใช้เป็น rate-limit key
//
// ปัญหาหลักที่ไฟล์นี้แก้:
//   1. Rate-limit bypass ผ่าน X-Forwarded-For:
//      เดิม: ใช้ leftmost XFF entry → attacker ส่ง "X-Forwarded-For: 1.2.3.4"
//            → fresh rate-limit bucket ทุกครั้ง → bypass ได้สมบูรณ์
//      แก้:  ใช้ rightmost XFF (proxy-appended) เมื่ออยู่หลัง proxy เท่านั้น
//
//   2. Unsanitized header inject rate-limit key:
//      เดิม: ไม่ validate format → "X-Forwarded-For: bypass_key_XXX"
//            → rate-limit key = "ip:bypass_key_XXX:..." → fresh bucket
//      แก้:  SAFE_IP_REGEX กรองเฉพาะ char ที่ valid ใน IP address
//
// Architecture decision (proxy vs direct):
//   Direct connection:
//     socket.remoteAddress = real client IP (unforgeable)
//     X-Forwarded-For = attacker-controlled ทั้งหมด → ไม่ใช้
//
//   Behind reverse proxy:
//     socket.remoteAddress = proxy IP (private/loopback เสมอ)
//     X-Forwarded-For = "<attacker-prefix>, <real-client>" (proxy append rightmost)
//     → ใช้ rightmost entry ที่ proxy เพิ่ม (unforgeable)
//
//   ตัวอย่าง (behind proxy):
//     attacker ส่ง "X-Forwarded-For: 1.1.1.1, 2.2.2.2"
//     proxy append → "X-Forwarded-For: 1.1.1.1, 2.2.2.2, <real-client>"
//     split(',').at(-1) = <real-client> ✓
// ============================================================

// อนุญาตเฉพาะ character ที่ valid ใน IPv4/IPv6 address:
//   IPv4:  digits + dots                     (192.168.1.1)
//   IPv6:  hex + colons + brackets           ([::1], fe80::1)
//   zone:  %                                 (::1%2 — numeric zone ID)
// หมายเหตุ: zone ID ที่มี interface name เช่น %eth0 จะ fallback เป็น '0.0.0.0'
//   เพราะ 't','h' ไม่ผ่าน regex นี้ — acceptable tradeoff สำหรับ rate-limit
const SAFE_IP_REGEX = /^[\d.:a-fA-F\[\]%]+$/;

// บ่งชี้ว่า socket IP เป็น private/loopback → request ผ่าน reverse proxy
//
// ครอบคลุม:
//   IPv4 (RFC 1918 + loopback + link-local):
//     10.0.0.0/8:       10\.
//     172.16.0.0/12:    172\.(1[6-9]|2\d|3[01])\.
//     192.168.0.0/16:   192\.168\.
//     127.0.0.0/8:      127\.
//     169.254.0.0/16:   169\.254\.
//
//   IPv6 (loopback + ULA + link-local):
//     ::1               loopback
//     fc00::/7          ULA: [fF][cCdD]xx:
//     fe80::/10         link-local: [fF][eE][89aAbB]x:
//
//   IPv4-mapped IPv6 (::ffff:A.B.C.D):
//     Node.js IPv6 socket แปลง IPv4 connection เป็น ::ffff:A.B.C.D เสมอ
//     ต้อง cover ทุก private range ในรูป mapped ด้วย:
//       ::ffff:127.x.x.x    (loopback mapped)
//       ::ffff:10.x.x.x     (RFC 1918 /8 mapped)
//       ::ffff:192.168.x.x  (RFC 1918 /16 mapped)
//       ::ffff:172.1x.x.x   (RFC 1918 /12 mapped)
//     ถ้าขาด: proxy ที่ socket IP เป็น ::ffff:10.x.x.x จะถูก classify
//     ผิดเป็น "direct connection" → ใช้ socket IP (proxy IP) แทน rightmost XFF
//     → ทุก client ผ่าน proxy นั้น share rate-limit bucket เดียว → collateral DoS
const PRIVATE_IP_REGEX = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|::1$|::ffff:127\.|::ffff:10\.|::ffff:192\.168\.|::ffff:172\.(1[6-9]|2\d|3[01])\.|[fF][cCdD][0-9a-fA-F]{2}:|[fF][eE][89aAbB][0-9a-fA-F]:)/;

/**
 * Resolve client IP address จาก request สำหรับใช้เป็น rate-limit key
 *
 * Logic:
 *   socket IP เป็น private/loopback → behind proxy → rightmost XFF (unforgeable)
 *   socket IP เป็น public           → direct       → socket IP (unforgeable)
 *   fallback: '0.0.0.0' (shared bucket — fail-safe แทน bypass)
 *
 * @param {import('http').IncomingMessage} req
 * @returns {string} validated IP หรือ '0.0.0.0' ถ้า invalid/unknown
 */
export function getClientIp(req) {
    // socketIp เป็น string เสมอ (|| '' ป้องกัน undefined/null จาก req.socket)
    const socketIp = req.socket?.remoteAddress || '';

    if (PRIVATE_IP_REGEX.test(socketIp)) {
        // ── Behind reverse proxy ──────────────────────────────
        // socket IP เป็น private/loopback → proxy ส่ง request มา
        // ใช้ rightmost XFF ที่ proxy เพิ่มให้ (attacker แก้ได้แค่ entries ก่อนหน้า)
        const xff = req.headers['x-forwarded-for'];
        if (xff && typeof xff === 'string') {
            const parts = xff.split(',');
            const raw   = parts[parts.length - 1]?.trim() || '';
            // length ≤ 45: IPv6 max = 39 chars, IPv4-mapped IPv6 max = 45 chars
            if (raw.length > 0 && raw.length <= 45 && SAFE_IP_REGEX.test(raw)) {
                return raw;
            }
        }
        // อยู่หลัง proxy แต่ไม่มี XFF header ที่ valid
        // (เช่น internal health check โดยตรง หรือ proxy misconfigured)
        // fallback เป็น socket IP (proxy IP) ดีกว่า '0.0.0.0' เพราะ
        //   '0.0.0.0' ทำให้ทุก request จาก proxy ต่าง ๆ share bucket เดียวกัน
        //   socket IP ทำให้แค่ proxy เดียวกันที่ share → blast radius เล็กกว่า
        if (socketIp.length > 0 && socketIp.length <= 45 && SAFE_IP_REGEX.test(socketIp)) {
            return socketIp;
        }
        return '0.0.0.0';
    }

    // ── Direct connection ─────────────────────────────────────
    // socket IP เป็น public → ใช้โดยตรง ไม่ดู X-Forwarded-For
    // (XFF จาก direct client = attacker-controlled ทั้งหมด)
    // socketIp เป็น string เสมอ → ไม่ต้อง check !socketIp ซ้ำ
    if (socketIp.length === 0 || socketIp.length > 45) {
        return '0.0.0.0';
    }
    if (!SAFE_IP_REGEX.test(socketIp)) {
        return '0.0.0.0';
    }
    return socketIp;
}
