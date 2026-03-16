import { navigate } from "../router.js";
import { toast } from "../ui/toast.js";
import { resendMfa, verifyMfa } from "../core/auth.js";
import { authScaffold, escapeHtml } from "./_layout.js";

function setStatus(outlet, { tone, title, message }) {
  const s = outlet.querySelector("#status");
  if (!s) return;
  s.hidden = false;
  s.className = `status status--${tone}`;
  s.innerHTML = `<div class="status__title">${escapeHtml(title)}</div><div>${escapeHtml(message)}</div>`;
}

function getMfaContext() {
  const logId = sessionStorage.getItem("mfa_logId");
  const username = sessionStorage.getItem("mfa_username");
  const remember = sessionStorage.getItem("mfa_remember") === "true";
  const fingerprint = sessionStorage.getItem("mfa_fingerprint");
  const redirectBack = sessionStorage.getItem("mfa_redirect_back");
  const nextUrl = sessionStorage.getItem("mfa_next_url");
  return { logId, username, remember, fingerprint, redirectBack, nextUrl };
}

function clearMfaContext() {
  ["mfa_logId", "mfa_username", "mfa_remember", "mfa_fingerprint", "mfa_redirect_back", "mfa_next_url"].forEach((k) =>
    sessionStorage.removeItem(k),
  );
}

export async function renderMfa({ outlet } = {}) {
  if (!outlet) return;

  const ctx = getMfaContext();
  if (!ctx.logId || !ctx.username || !ctx.fingerprint) {
    toast({ tone: "warn", title: "เซสชันหมดอายุ", message: "กรุณาเข้าสู่ระบบใหม่" });
    navigate("/login");
    return;
  }

  outlet.innerHTML = authScaffold({
    title: "ยืนยันตัวตน",
    subtitle: "กรอกรหัส 6 หลักที่ส่งไปยังอีเมลของคุณ",
    formHtml: `
      <form id="form" class="stack" novalidate>
        <div class="field">
          <label class="label" for="code">รหัสยืนยัน</label>
          <input class="input mono" id="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="000000" required />
          <p class="hint">ถ้ายังไม่ได้รับอีเมล ให้ขอรหัสใหม่</p>
        </div>

        <div class="row row--between">
          <button class="btn btn--ghost" id="resend" type="button">
            <svg class="icon" aria-hidden="true"><use href="/assets/icons.svg#i-rotate"></use></svg>
            <span>ส่งรหัสใหม่</span>
          </button>
          <a href="/login" data-link class="link-dim">ยกเลิก</a>
        </div>

        <div class="auth-actions">
          <button class="btn btn--full" id="submit" type="submit">
            <svg class="icon" aria-hidden="true"><use href="/assets/icons.svg#i-check"></use></svg>
            <span>ยืนยัน</span>
          </button>
        </div>
      </form>
    `,
    footerHtml: `
      <div class="auth-links">
        <a href="/login" data-link>กลับไปเข้าสู่ระบบ</a>
        <a href="/register" data-link>สร้างบัญชีใหม่</a>
      </div>
    `,
  });

  const form = outlet.querySelector("#form");
  const btn = outlet.querySelector("#submit");
  const btnResend = outlet.querySelector("#resend");

  let cooldown = 0;
  let timer = null;
  function startCooldown(seconds) {
    cooldown = seconds;
    btnResend?.setAttribute("disabled", "true");
    const tick = () => {
      if (!btnResend) return;
      if (cooldown <= 0) {
        btnResend.removeAttribute("disabled");
        btnResend.querySelector("span").textContent = "ส่งรหัสใหม่";
        if (timer) window.clearInterval(timer);
        return;
      }
      btnResend.querySelector("span").textContent = `ส่งรหัสใหม่ (${cooldown}s)`;
      cooldown -= 1;
    };
    tick();
    timer = window.setInterval(tick, 1000);
  }

  btnResend?.addEventListener("click", async () => {
    if (cooldown > 0) return;
    setStatus(outlet, { tone: "warn", title: "กำลังดำเนินการ", message: "กำลังส่งรหัสใหม่…" });
    const r = await resendMfa({ username: ctx.username, logId: ctx.logId });
    if (r.ok) {
      toast({ tone: "ok", title: "ส่งแล้ว", message: "เราได้ส่งรหัสใหม่ไปที่อีเมลของคุณ" });
      startCooldown(60);
      setStatus(outlet, { tone: "ok", title: "พร้อมยืนยัน", message: "กรุณากรอกรหัสที่ได้รับ" });
    } else {
      setStatus(outlet, { tone: "err", title: "ส่งไม่สำเร็จ", message: r.data?.error || "กรุณาลองใหม่" });
    }
  });

  form?.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!btn) return;
    const code = outlet.querySelector("#code")?.value?.trim() || "";
    if (!/^\d{6}$/.test(code)) {
      setStatus(outlet, { tone: "err", title: "ตรวจสอบข้อมูล", message: "กรุณากรอกรหัส 6 หลัก" });
      return;
    }

    btn.setAttribute("disabled", "true");
    setStatus(outlet, { tone: "warn", title: "กำลังตรวจสอบ", message: "กำลังยืนยันรหัส…" });
    try {
      const res = await verifyMfa({
        username: ctx.username,
        logId: ctx.logId,
        code,
        remember: ctx.remember,
        fingerprint: ctx.fingerprint,
        redirectBack: ctx.redirectBack,
      });

      if (res.ok) {
        const serverUrl = typeof res.data?.redirectUrl === "string" ? res.data.redirectUrl : null;
        clearMfaContext();
        toast({ tone: "ok", title: "ยืนยันสำเร็จ", message: "กำลังพาคุณไปยังหน้าถัดไป" });
        if (serverUrl) {
          try {
            const p = new URL(serverUrl).protocol;
            if (p === "https:" || p === "http:") window.location.href = serverUrl;
            else navigate(ctx.nextUrl || "/welcome");
          } catch {
            navigate(ctx.nextUrl || "/welcome");
          }
        } else {
          navigate(ctx.nextUrl || "/welcome");
        }
      } else {
        setStatus(outlet, { tone: "err", title: "ยืนยันไม่สำเร็จ", message: res.data?.error || "รหัสไม่ถูกต้อง" });
        if (res.status === 429) {
          clearMfaContext();
          navigate("/login");
        }
      }
    } catch (err) {
      setStatus(outlet, { tone: "err", title: "เกิดข้อผิดพลาด", message: err?.name === "AbortError" ? "หมดเวลาในการเชื่อมต่อ" : "ไม่สามารถยืนยันได้ในตอนนี้" });
    } finally {
      btn.removeAttribute("disabled");
    }
  });
}

