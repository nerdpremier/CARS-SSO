import { navigate } from "../router.js";
import { getSession } from "../core/session.js";
import { toast } from "../ui/toast.js";

export async function renderWelcome({ outlet } = {}) {
  if (!outlet) return;

  const session = await getSession();
  if (!session.authenticated) {
    navigate("/login");
    return;
  }

  // show chrome
  const topbar = document.getElementById("topbar");
  if (topbar) topbar.hidden = false;
  const userPill = document.getElementById("user-pill");
  const userName = document.getElementById("user-name");
  const btnLogout = document.getElementById("btn-logout");
  if (userPill) userPill.hidden = false;
  if (btnLogout) btnLogout.hidden = false;
  if (userName && session.user) userName.textContent = session.user;

  outlet.innerHTML = `
    <div class="stack stack--lg">
      <div class="split">
        <div class="card">
          <div class="card__inner stack">
            <span class="badge badge--ok">
              <span class="user-pill-dot" aria-hidden="true"></span>
              <span>เซสชันพร้อมใช้งาน</span>
            </span>
            <h1 class="card__title">ยินดีต้อนรับ</h1>
            <p class="card__subtitle">คุณเข้าสู่ระบบแล้วในฐานะ <span class="mono">${escapeHtml(session.user || "ผู้ใช้")}</span></p>

            <div class="row row--mt-4">
              <a class="btn" href="/developer" data-link>
                <svg class="icon" aria-hidden="true"><use href="/assets/icons.svg#i-link"></use></svg>
                <span>เปิดพอร์ทัลนักพัฒนา</span>
              </a>
              <button class="btn btn--ghost" id="btn-copy-token" type="button">
                <svg class="icon" aria-hidden="true"><use href="/assets/icons.svg#i-copy"></use></svg>
                <span>คัดลอกข้อมูลเซสชัน</span>
              </button>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card__inner stack">
            <h2 class="title-inline">ภาพรวมความปลอดภัย</h2>
            <div class="dashboard-grid dashboard-grid--single">
              <div class="metric">
                <div class="metric__label">นโยบาย</div>
                <div class="metric__value">Adaptive MFA</div>
              </div>
              <div class="metric">
                <div class="metric__label">สถานะ</div>
                <div class="metric__value">Active</div>
              </div>
              <div class="empty">
                หน้านี้เป็นแดชบอร์ดเริ่มต้นสำหรับผู้ใช้ทั่วไป
                โดยสามารถต่อยอดให้แสดงเหตุการณ์ความเสี่ยงล่าสุด, อุปกรณ์ที่เชื่อถือได้, และการแจ้งเตือนความปลอดภัยได้
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;

  outlet.querySelector("#btn-copy-token")?.addEventListener("click", async () => {
    const payload = JSON.stringify({ user: session.user, authenticated: true });
    try {
      await navigator.clipboard.writeText(payload);
      toast({ tone: "ok", title: "คัดลอกแล้ว", message: "คัดลอกข้อมูลเซสชันไปยังคลิปบอร์ด" });
    } catch {
      toast({ tone: "warn", title: "คัดลอกไม่สำเร็จ", message: "เบราว์เซอร์ไม่อนุญาตให้คัดลอกในบริบทนี้" });
    }
  });
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

