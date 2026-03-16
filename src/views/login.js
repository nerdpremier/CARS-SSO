import { navigate } from "../router.js";
import { toast } from "../ui/toast.js";
import {
  assessRisk,
  getSecureFp,
  login,
  readRedirectContext,
  validatePassword,
  validateUsername,
} from "../core/auth.js";
import { authScaffold, escapeHtml } from "./_layout.js";

function setStatus(outlet, { tone, title, message }) {
  const s = outlet.querySelector("#status");
  if (!s) return;
  s.hidden = false;
  s.className = `status status--${tone}`;
  s.innerHTML = `<div class="status__title">${escapeHtml(title)}</div><div>${escapeHtml(message)}</div>`;
}

function clearStatus(outlet) {
  const s = outlet.querySelector("#status");
  if (!s) return;
  s.hidden = true;
  s.className = "";
  s.textContent = "";
}

export async function renderLogin({ outlet } = {}) {
  if (!outlet) return;
  outlet.innerHTML = authScaffold({
    title: "เข้าสู่ระบบ",
    subtitle: "เข้าสู่บัญชี CARS ของคุณเพื่อดำเนินการต่อ",
    formHtml: `
      <form id="form" class="stack" novalidate>
        <div class="field">
          <label class="label" for="username">ชื่อผู้ใช้</label>
          <input class="input" id="username" name="username" autocomplete="username" maxlength="32" placeholder="เช่น touch" required />
          <p class="hint">ใช้เฉพาะตัวอักษรและตัวเลข</p>
        </div>

        <div class="field">
          <label class="label" for="password">รหัสผ่าน</label>
          <input class="input" id="password" name="password" type="password" autocomplete="current-password" maxlength="128" placeholder="รหัสผ่านของคุณ" required />
        </div>

        <label class="row" style="gap: var(--s-2); color: var(--muted); font-size: 13px;">
          <input type="checkbox" id="remember" />
          <span>จดจำอุปกรณ์นี้ 30 วัน</span>
        </label>

        <div class="auth-actions">
          <button class="btn btn--full" id="submit" type="submit">
            <svg class="icon" aria-hidden="true"><use href="/assets/icons.svg#i-user"></use></svg>
            <span>เข้าสู่ระบบ</span>
          </button>
        </div>
      </form>
    `,
    footerHtml: `
      <div class="auth-links">
        <a href="/forgot-password" data-link>ลืมรหัสผ่าน</a>
        <a href="/register" data-link>สร้างบัญชี</a>
      </div>
    `,
  });

  clearStatus(outlet);
  const form = outlet.querySelector("#form");
  const btn = outlet.querySelector("#submit");

  const { nextUrl, redirectBack } = readRedirectContext();

  form?.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!btn) return;

    const username = outlet.querySelector("#username")?.value?.trim() || "";
    const password = outlet.querySelector("#password")?.value || "";
    const remember = Boolean(outlet.querySelector("#remember")?.checked);

    const uErr = validateUsername(username);
    if (uErr) return setStatus(outlet, { tone: "err", title: "ตรวจสอบข้อมูล", message: uErr });
    const pErr = validatePassword(password);
    if (pErr) return setStatus(outlet, { tone: "err", title: "ตรวจสอบข้อมูล", message: pErr });

    btn.setAttribute("disabled", "true");
    setStatus(outlet, { tone: "warn", title: "กำลังตรวจสอบ", message: "กำลังยืนยันตัวตนและประเมินความเสี่ยง…" });

    try {
      const fingerprint = getSecureFp();
      const risk = await assessRisk({ username, fingerprint });
      if (!risk.ok) throw new Error("ไม่สามารถประเมินความเสี่ยงได้");
      if (risk.data?.risk_level === "HIGH") {
        setStatus(outlet, { tone: "err", title: "ถูกปฏิเสธชั่วคราว", message: "ระบบตรวจพบความเสี่ยงสูง กรุณาลองใหม่ภายหลัง" });
        return;
      }
      const logIdNum = Number(risk.data?.logId);
      if (!Number.isInteger(logIdNum) || logIdNum <= 0) {
        setStatus(outlet, { tone: "err", title: "เข้าสู่ระบบไม่สำเร็จ", message: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง" });
        return;
      }

      const res = await login({
        username,
        password,
        remember,
        fingerprint,
        logId: String(logIdNum),
        redirectBack,
      });

      if (res.ok) {
        if (res.data?.mfa_required) {
          sessionStorage.setItem("mfa_logId", String(logIdNum));
          sessionStorage.setItem("mfa_username", username);
          sessionStorage.setItem("mfa_remember", String(remember));
          sessionStorage.setItem("mfa_fingerprint", fingerprint);
          if (redirectBack) sessionStorage.setItem("mfa_redirect_back", redirectBack);
          if (nextUrl) sessionStorage.setItem("mfa_next_url", nextUrl);
          toast({ tone: "ok", title: "ต้องยืนยันเพิ่มเติม", message: "กรุณากรอกรหัสยืนยันที่ส่งไปทางอีเมล" });
          navigate("/mfa");
          return;
        }

        // Priority: SSO redirect URL (server-validated) -> next -> welcome
        const serverUrl = typeof res.data?.redirectUrl === "string" ? res.data.redirectUrl : null;
        if (serverUrl) {
          try {
            const p = new URL(serverUrl).protocol;
            if (p === "https:" || p === "http:") window.location.href = serverUrl;
            else navigate(nextUrl || "/welcome");
          } catch {
            navigate(nextUrl || "/welcome");
          }
        } else {
          navigate(nextUrl || "/welcome");
        }
      } else {
        if (res.data?.email_not_verified) {
          setStatus(outlet, { tone: "warn", title: "ยังไม่ยืนยันอีเมล", message: "กรุณายืนยันอีเมลก่อนเข้าสู่ระบบ" });
        } else {
          setStatus(outlet, { tone: "err", title: "เข้าสู่ระบบไม่สำเร็จ", message: res.data?.error || "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง" });
        }
      }
    } catch (err) {
      setStatus(outlet, { tone: "err", title: "เกิดข้อผิดพลาด", message: err?.name === "AbortError" ? "หมดเวลาในการเชื่อมต่อ" : "ไม่สามารถเข้าสู่ระบบได้ในตอนนี้" });
    } finally {
      btn.removeAttribute("disabled");
    }
  });
}

