import { secureFetch } from "./csrf.js";

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function validateEmail(email) {
  const e = (email || "").trim();
  return !e || !EMAIL_REGEX.test(e) ? "กรุณากรอกอีเมลให้ถูกต้อง" : null;
}

export function validateUsername(username) {
  const u = (username || "").trim();
  if (!u) return "กรุณากรอกชื่อผู้ใช้";
  if (u.length > 32) return "ชื่อผู้ใช้ต้องไม่เกิน 32 ตัวอักษร";
  if (!/^[a-zA-Z0-9]+$/.test(u)) return "ชื่อผู้ใช้ใช้ได้เฉพาะตัวอักษรและตัวเลข";
  return null;
}

export function validatePassword(password) {
  const p = password || "";
  const r =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#^_\-+=()])[A-Za-z\d@$!%*?&#^_\-+=()]{8,128}$/;
  if (!p) return "กรุณากรอกรหัสผ่าน";
  if (p.length > 128) return "รหัสผ่านต้องไม่เกิน 128 ตัวอักษร";
  if (!r.test(p)) return "รหัสผ่านต้องมี 8–128 ตัวอักษร และมีตัวพิมพ์ใหญ่/เล็ก ตัวเลข และสัญลักษณ์";
  return null;
}

export function getSecureFp() {
  try {
    let id = localStorage.getItem("_device_fp");
    if (!id) {
      id = crypto.randomUUID();
      localStorage.setItem("_device_fp", id);
    }
    return id;
  } catch {
    try {
      const h = [
        `${screen.width}x${screen.height}`,
        String(navigator.hardwareConcurrency || 0),
        String(navigator.language || ""),
      ].join("|");
      return btoa(encodeURIComponent(h)).slice(0, 128);
    } catch {
      return crypto.randomUUID();
    }
  }
}

export function readRedirectContext() {
  // same-origin next (route inside this app)
  const sp = new URLSearchParams(window.location.search);
  const rawNext = sp.get("next");
  let nextUrl = null;
  if (rawNext) {
    try {
      const u = new URL(rawNext, window.location.origin);
      if (u.origin === window.location.origin) nextUrl = u.pathname + u.search + u.hash;
    } catch {}
  }
  const redirectBack = sp.get("redirect_back");
  return { nextUrl, redirectBack };
}

export async function assessRisk({ username, fingerprint }) {
  const device = `Screen:${screen.width}x${screen.height} | CPU:${navigator.hardwareConcurrency || 0}`;
  const res = await secureFetch("/api/assess", {
    method: "POST",
    body: JSON.stringify({ username, device, fingerprint }),
  });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, data };
}

export async function login({ username, password, remember, fingerprint, logId, redirectBack }) {
  const body = { action: "login", username, password, fingerprint, logId, remember: Boolean(remember) };
  if (redirectBack) body.redirect_back = redirectBack;
  const res = await secureFetch("/api/auth", { method: "POST", body: JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

export async function register({ username, email, password }) {
  const res = await secureFetch("/api/auth", {
    method: "POST",
    body: JSON.stringify({ action: "register", username, email, password }),
  });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

export async function verifyMfa({ username, logId, code, remember, fingerprint, redirectBack }) {
  const body = { action: "verify", username, logId, code, remember: Boolean(remember), fingerprint };
  if (redirectBack) body.redirect_back = redirectBack;
  const res = await secureFetch("/api/mfa", { method: "POST", body: JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

export async function resendMfa({ username, logId }) {
  const res = await secureFetch("/api/mfa", { method: "POST", body: JSON.stringify({ action: "resend", username, logId }) });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

