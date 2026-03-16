import { navigate } from "../router.js";
import { toast } from "../ui/toast.js";
import { register, validateEmail, validatePassword, validateUsername } from "../core/auth.js";
import { authScaffold, escapeHtml } from "./_layout.js";

function setStatus(outlet, { tone, title, message }) {
  const s = outlet.querySelector("#status");
  if (!s) return;
  s.hidden = false;
  s.className = `status status--${tone}`;
  s.innerHTML = `<div class="status__title">${escapeHtml(title)}</div><div>${escapeHtml(message)}</div>`;
}

export async function renderRegister({ outlet } = {}) {
  if (!outlet) return;

  outlet.innerHTML = authScaffold({
    title: "สร้างบัญชี",
    subtitle: "เริ่มใช้งานด้วยบัญชีใหม่ และยืนยันอีเมลเพื่อความปลอดภัย",
    formHtml: `
      <form id="form" class="stack" novalidate>
        <div class="field">
          <label class="label" for="username">ชื่อผู้ใช้</label>
          <input class="input" id="username" name="username" autocomplete="username" maxlength="32" placeholder="เช่น touch" required />
        </div>

        <div class="field">
          <label class="label" for="email">อีเมล</label>
          <input class="input" id="email" name="email" autocomplete="email" maxlength="254" placeholder="name@company.com" required />
        </div>

        <div class="field">
          <label class="label" for="password">รหัสผ่าน</label>
          <input class="input" id="password" name="password" type="password" autocomplete="new-password" maxlength="128" placeholder="ตั้งรหัสผ่านที่คาดเดายาก" required />
          <p class="help">ต้องมีตัวพิมพ์ใหญ่/เล็ก ตัวเลข และสัญลักษณ์</p>
        </div>

        <div class="auth-actions">
          <button class="btn btn--full" id="submit" type="submit">
            <svg class="icon" aria-hidden="true"><use href="/assets/icons.svg#i-check"></use></svg>
            <span>สร้างบัญชี</span>
          </button>
        </div>
      </form>
    `,
    footerHtml: `
      <div class="auth-links">
        <a href="/login" data-link>มีบัญชีอยู่แล้ว</a>
        <a href="/developer" data-link>ไปพอร์ทัลนักพัฒนา</a>
      </div>
    `,
  });

  const form = outlet.querySelector("#form");
  const btn = outlet.querySelector("#submit");

  form?.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!btn) return;

    const username = outlet.querySelector("#username")?.value?.trim() || "";
    const email = outlet.querySelector("#email")?.value?.trim() || "";
    const password = outlet.querySelector("#password")?.value || "";

    const uErr = validateUsername(username);
    if (uErr) return setStatus(outlet, { tone: "err", title: "ตรวจสอบข้อมูล", message: uErr });
    const eErr = validateEmail(email);
    if (eErr) return setStatus(outlet, { tone: "err", title: "ตรวจสอบข้อมูล", message: eErr });
    const pErr = validatePassword(password);
    if (pErr) return setStatus(outlet, { tone: "err", title: "ตรวจสอบข้อมูล", message: pErr });

    btn.setAttribute("disabled", "true");
    setStatus(outlet, { tone: "warn", title: "กำลังดำเนินการ", message: "กำลังสร้างบัญชี…" });

    try {
      const res = await register({ username, email, password });
      if (res.ok) {
        if (res.data?.email_verification) {
          setStatus(outlet, {
            tone: "ok",
            title: "สร้างบัญชีสำเร็จ",
            message: "กรุณาตรวจสอบอีเมลเพื่อยืนยันบัญชี จากนั้นกลับมาเข้าสู่ระบบ",
          });
          toast({ tone: "ok", title: "ตรวจสอบอีเมล", message: "เราได้ส่งลิงก์ยืนยันไปที่อีเมลของคุณแล้ว" });
        } else {
          toast({ tone: "ok", title: "พร้อมใช้งาน", message: "สร้างบัญชีเรียบร้อย กำลังไปหน้าเข้าสู่ระบบ" });
          navigate("/login");
        }
      } else {
        setStatus(outlet, { tone: "err", title: "สร้างบัญชีไม่สำเร็จ", message: res.data?.error || "กรุณาลองใหม่อีกครั้ง" });
      }
    } catch (err) {
      setStatus(outlet, { tone: "err", title: "เกิดข้อผิดพลาด", message: err?.name === "AbortError" ? "หมดเวลาในการเชื่อมต่อ" : "ไม่สามารถสร้างบัญชีได้ในตอนนี้" });
    } finally {
      btn.removeAttribute("disabled");
    }
  });
}

