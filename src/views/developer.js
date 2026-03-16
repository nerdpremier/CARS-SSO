import { getSession } from "../core/session.js";
import { secureFetch } from "../core/csrf.js";
import { navigate } from "../router.js";
import { toast } from "../ui/toast.js";

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function fmtIso(iso) {
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return "";
    return d.toLocaleString("th-TH", { dateStyle: "medium", timeStyle: "short" });
  } catch {
    return "";
  }
}

async function apiGet(path) {
  const res = await secureFetch(path, { method: "GET" });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

async function apiPost(path, body) {
  const res = await secureFetch(path, { method: "POST", body: JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

export async function renderDeveloper({ outlet } = {}) {
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
            <div class="row" style="justify-content: space-between; align-items: start;">
              <div class="stack" style="gap: 10px;">
                <span class="badge">
                  <svg class="icon" aria-hidden="true"><use href="/assets/icons.svg#i-link"></use></svg>
                  <span>Developer Portal</span>
                </span>
                <h1 class="card__title">แดชบอร์ดการเชื่อมต่อ</h1>
                <p class="card__subtitle">จัดการคีย์, integrations, และตรวจสอบบันทึกเหตุการณ์ความเสี่ยง</p>
              </div>
              <a class="btn btn--ghost" href="/welcome" data-link>
                <svg class="icon" aria-hidden="true"><use href="/assets/icons.svg#i-arrow-left"></use></svg>
                <span>กลับแดชบอร์ด</span>
              </a>
            </div>

            <div class="tabs" role="tablist" aria-label="Developer sections">
              <button class="tab" type="button" role="tab" aria-selected="true"  data-tab="keys">
                <svg class="icon" aria-hidden="true"><use href="/assets/icons.svg#i-key"></use></svg>
                <span>API Keys</span>
              </button>
              <button class="tab" type="button" role="tab" aria-selected="false" data-tab="integrations">
                <svg class="icon" aria-hidden="true"><use href="/assets/icons.svg#i-sliders"></use></svg>
                <span>Integrations</span>
              </button>
              <button class="tab" type="button" role="tab" aria-selected="false" data-tab="logs">
                <svg class="icon" aria-hidden="true"><use href="/assets/icons.svg#i-list"></use></svg>
                <span>Logs</span>
              </button>
              <button class="tab" type="button" role="tab" aria-selected="false" data-tab="ai">
                <svg class="icon" aria-hidden="true"><use href="/assets/icons.svg#i-shield"></use></svg>
                <span>AI Decisions</span>
              </button>
            </div>

            <div id="panel" class="stack" style="gap: var(--s-4);"></div>
          </div>
        </div>

        <div class="card">
          <div class="card__inner stack">
            <h2 style="margin:0; font-family: var(--font-serif); letter-spacing: -0.02em;">OAuth Apps</h2>
            <p class="help">อ้างอิง endpoint เดิมของระบบ: <span class="mono">/api/oauth/clients</span></p>

            <div class="stack" style="gap: var(--s-3);">
              <div class="field">
                <label class="label" for="app-name">ชื่อแอป</label>
                <input class="input" id="app-name" placeholder="เช่น My Website" maxlength="128" />
              </div>
              <div class="field">
                <label class="label" for="cb-url">Callback URL</label>
                <input class="input" id="cb-url" placeholder="https://myapp.com/callback" maxlength="512" />
                <p class="hint">ต้องเป็น URL ที่อนุญาตให้ redirect กลับหลัง login</p>
              </div>
              <button class="btn" id="btn-create" type="button">
                <svg class="icon" aria-hidden="true"><use href="/assets/icons.svg#i-plus"></use></svg>
                <span>สร้างแอป</span>
              </button>
            </div>

            <div id="apps" class="stack" style="gap: var(--s-3); margin-top: var(--s-5);">
              <div class="empty">กำลังโหลดแอป…</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;

  const panel = outlet.querySelector("#panel");
  const tabs = Array.from(outlet.querySelectorAll(".tab"));

  function setTab(key) {
    for (const t of tabs) t.setAttribute("aria-selected", t.dataset.tab === key ? "true" : "false");
    renderPanel(key);
  }

  function renderPanel(key) {
    if (!panel) return;
    if (key === "keys") {
      panel.innerHTML = `
        <div class="status status--warn">
          <div class="status__title">API Keys (UI พร้อมต่อ backend)</div>
          <div>ตอนนี้ backend สำหรับ API keys ยังไม่พบใน repo จึงแสดงเป็นโครงหน้าแบบ production ที่พร้อมเสียบ endpoint</div>
        </div>
        <div class="row" style="justify-content: space-between;">
          <span class="badge"><span class="mono">Scope</span><span>read:logs, manage:keys</span></span>
          <button class="btn" type="button" id="btn-gen-key">
            <svg class="icon" aria-hidden="true"><use href="/assets/icons.svg#i-key"></use></svg>
            <span>สร้างคีย์ใหม่</span>
          </button>
        </div>
        <table class="table" aria-label="API keys table">
          <thead><tr><th>ชื่อ</th><th>คีย์</th><th>สร้างเมื่อ</th><th>สถานะ</th></tr></thead>
          <tbody id="keys-body">
            <tr><td colspan="4"><div class="empty">ยังไม่มีคีย์ — สร้างคีย์แรกของคุณได้เลย</div></td></tr>
          </tbody>
        </table>
      `;
      panel.querySelector("#btn-gen-key")?.addEventListener("click", () => {
        toast({ tone: "warn", title: "ยังไม่ผูก backend", message: "เพิ่ม endpoint สำหรับ API keys แล้วค่อยเชื่อมปุ่มนี้" });
      });
      return;
    }
    if (key === "integrations") {
      panel.innerHTML = `
        <div class="status status--ok">
          <div class="status__title">Integrations</div>
          <div>ออกแบบให้จัดการการเชื่อมต่อแบบ preset: OAuth (PKCE), SSO exchange, และ webhook logging</div>
        </div>
        <div class="empty">
          ตัวอย่างที่ควรทำต่อ: เพิ่มหน้า "Create Integration" และบันทึก config ต่อแอป (client) ในฐานข้อมูล
        </div>
      `;
      return;
    }
    if (key === "logs") {
      panel.innerHTML = `
        <div class="status status--warn">
          <div class="status__title">Logs</div>
          <div>UI รองรับการแสดงเหตุการณ์แบบตาราง + ตัวกรอง (filter) และรายละเอียดต่อรายการ</div>
        </div>
        <table class="table" aria-label="Security logs table">
          <thead><tr><th>เวลา</th><th>เหตุการณ์</th><th>ระดับความเสี่ยง</th><th>ผลลัพธ์</th></tr></thead>
          <tbody>
            <tr>
              <td>${escapeHtml(fmtIso(new Date().toISOString()))}</td>
              <td>LOGIN_ATTEMPT</td>
              <td><span class="badge badge--warn">MEDIUM</span></td>
              <td>REQUIRES_MFA</td>
            </tr>
            <tr>
              <td>${escapeHtml(fmtIso(new Date(Date.now() - 3600_000).toISOString()))}</td>
              <td>MFA_VERIFY</td>
              <td><span class="badge badge--ok">LOW</span></td>
              <td>ALLOW</td>
            </tr>
          </tbody>
        </table>
      `;
      return;
    }
    panel.innerHTML = `
      <div class="status status--ok">
        <div class="status__title">AI Security Decisions</div>
        <div>โครงหน้าเพื่ออธิบาย “ทำไมระบบถึง allow/deny/require MFA” แบบที่ตรวจสอบย้อนหลังได้</div>
      </div>
      <div class="empty">
        ตัวอย่างสิ่งที่ควรมี: risk score, signal breakdown (device, geo, velocity), และ policy ที่ถูกใช้ในการตัดสินใจ
      </div>
    `;
  }

  tabs.forEach((t) => t.addEventListener("click", () => setTab(t.dataset.tab)));
  setTab("keys");

  // OAuth apps (existing backend)
  const appsHost = outlet.querySelector("#apps");
  async function loadApps() {
    if (!appsHost) return;
    const res = await apiGet("/api/oauth/clients");
    if (!res.ok) {
      appsHost.innerHTML = `<div class="empty">โหลดแอปไม่สำเร็จ: ${escapeHtml(res.data?.error || "ไม่ทราบสาเหตุ")}</div>`;
      return;
    }
    const list = Array.isArray(res.data?.clients) ? res.data.clients : [];
    if (list.length === 0) {
      appsHost.innerHTML = `<div class="empty">ยังไม่มี OAuth apps — เริ่มด้วยการสร้างแอปแรก</div>`;
      return;
    }
    appsHost.innerHTML = `
      <table class="table" aria-label="OAuth apps table">
        <thead><tr><th>ชื่อ</th><th>Client ID</th><th>Callback</th><th>อัปเดตล่าสุด</th></tr></thead>
        <tbody>
          ${list
            .map(
              (c) => `
                <tr>
                  <td>${escapeHtml(c.name || "")}</td>
                  <td class="mono">${escapeHtml(c.client_id || "")}</td>
                  <td class="mono">${escapeHtml(c.redirect_uri || "")}</td>
                  <td>${escapeHtml(c.updated_at ? fmtIso(c.updated_at) : "")}</td>
                </tr>
              `,
            )
            .join("")}
        </tbody>
      </table>
    `;
  }

  outlet.querySelector("#btn-create")?.addEventListener("click", async () => {
    const name = outlet.querySelector("#app-name")?.value?.trim() || "";
    const redirect_uri = outlet.querySelector("#cb-url")?.value?.trim() || "";
    if (!name || !redirect_uri) {
      toast({ tone: "warn", title: "ข้อมูลไม่ครบ", message: "กรุณากรอกชื่อแอปและ Callback URL" });
      return;
    }
    const res = await apiPost("/api/oauth/clients", { action: "create", name, redirect_uri });
    if (res.ok) {
      toast({ tone: "ok", title: "สร้างแอปสำเร็จ", message: "โปรดบันทึก client secret ทันที (ถ้าระบบส่งมา)" });
      await loadApps();
    } else {
      toast({ tone: "err", title: "สร้างไม่สำเร็จ", message: res.data?.error || "กรุณาลองใหม่" });
    }
  });

  await loadApps();
}

