'use strict';

// ── State ──────────────────────────────────────────────────────
let pendingDeleteId   = null;
let pendingDeleteName = null;

// ── Init ───────────────────────────────────────────────────────
async function init() {
  let res;
  try {
    res = await fetch('/api/session', { credentials: 'include' });
  } catch {
    location.replace('/login');
    return;
  }

  if (!res.ok) {
    location.replace('/login?next=' + encodeURIComponent(location.href));
    return;
  }

  const data = await res.json();
  if (!data.authenticated) {
    location.replace('/login?next=' + encodeURIComponent(location.href));
    return;
  }

  document.body.classList.remove('auth-pending');
  document.getElementById('user-name').textContent = data.user;
  document.getElementById('portal').style.display = '';

  loadApps();
}

// ── Load apps ──────────────────────────────────────────────────
async function loadApps() {
  const list  = document.getElementById('apps-list');
  const count = document.getElementById('apps-count');

  try {
    const res = await fetch('/api/oauth/clients', { credentials: 'include' });
    if (!res.ok) throw new Error('load failed');
    const data = await res.json();
    const apps = data.clients || [];

    count.textContent = apps.length + ' / 10 apps';

    if (apps.length === 0) {
      list.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">🔌</div>
          <div class="empty-text">ยังไม่มี App</div>
          <div class="empty-hint">กรอกฟอร์มด้านบนเพื่อสร้าง App แรกของคุณ</div>
        </div>`;
      return;
    }

    list.innerHTML = apps.map((app, i) => `
      <div class="app-card" style="animation-delay:${i * 0.05}s" data-client-id="${esc(app.client_id)}" data-app-name="${esc(app.name)}">
        <div class="app-card-header">
          <div>
            <div class="app-name">${esc(app.name)}</div>
            <div class="app-id">${esc(app.client_id)}</div>
          </div>
        </div>
        <div class="app-uris">
          ${(app.redirect_uris || []).map(u => `<span class="uri-chip">${esc(u)}</span>`).join('')}
        </div>
        <div class="app-footer">
          <div class="app-date">สร้างเมื่อ ${formatDate(app.created_at)}</div>
          <button class="btn-rotate" data-action="rotate" data-client-id="${esc(app.client_id)}" data-app-name="${esc(app.name)}">
            🔄 Rotate Secret
          </button>
          <button class="btn-delete" data-action="delete" data-client-id="${esc(app.client_id)}" data-app-name="${esc(app.name)}">
            ลบ
          </button>
        </div>
      </div>`).join('');

    // event delegation สำหรับปุ่ม rotate / delete ใน app cards
    list.querySelectorAll('[data-action="rotate"]').forEach(btn => {
      btn.addEventListener('click', () => askRotate(btn.dataset.clientId, btn.dataset.appName));
    });
    list.querySelectorAll('[data-action="delete"]').forEach(btn => {
      btn.addEventListener('click', () => askDelete(btn.dataset.clientId, btn.dataset.appName));
    });

  } catch {
    list.innerHTML = `<div style="text-align:center;padding:20px;font-size:13px;color:#EF4444;">
      โหลดข้อมูลไม่สำเร็จ กรุณา refresh หน้า</div>`;
    count.textContent = '— apps';
  }
}

// ── Create App ─────────────────────────────────────────────────
async function createApp() {
  const name      = document.getElementById('input-name').value.trim();
  const uri       = document.getElementById('input-uri').value.trim();
  const btn       = document.getElementById('btn-create');
  const status    = document.getElementById('create-status');
  const resultBox = document.getElementById('result-box');

  resultBox.classList.remove('show');
  status.className   = '';
  status.style.display = 'none';

  if (!name) return showCreateError('กรุณาใส่ชื่อ App');
  if (!uri)  return showCreateError('กรุณาใส่ Callback URL');

  try {
    const parsed      = new URL(uri);
    const isLocalhost = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';
    if (parsed.protocol !== 'https:' && !isLocalhost)
      return showCreateError('Callback URL ต้องเป็น https:// (หรือ localhost สำหรับ dev)');
  } catch {
    return showCreateError('Callback URL format ไม่ถูกต้อง');
  }

  btn.disabled    = true;
  btn.textContent = 'กำลังสร้าง...';

  try {
    const res = await fetch('/api/oauth/clients', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, redirect_uris: [uri] })
    });

    const data = await res.json();
    if (!res.ok) { showCreateError(data.error || 'เกิดข้อผิดพลาด กรุณาลองใหม่'); return; }

    document.getElementById('res-client-id').textContent     = data.client_id;
    document.getElementById('res-client-secret').textContent = data.client_secret;
    resultBox.classList.add('show');

    document.getElementById('input-name').value = '';
    document.getElementById('input-uri').value  = '';

    loadApps();
  } catch {
    showCreateError('ไม่สามารถเชื่อมต่อเซิร์ฟเวอร์ได้ กรุณาลองใหม่');
  } finally {
    btn.disabled    = false;
    btn.textContent = 'สร้าง';
  }
}

function showCreateError(msg) {
  const el = document.getElementById('create-status');
  el.textContent   = '⚠️ ' + msg;
  el.className     = 'danger';
  document.getElementById('btn-create').disabled    = false;
  document.getElementById('btn-create').textContent = 'สร้าง';
}

// ── Rotate Secret ───────────────────────────────────────────────
function askRotate(clientId, appName) {
  if (!confirm(`⚠️ Rotate client_secret ของ "${appName}" ?\n\nToken เก่าทั้งหมดจะถูก revoke ทันที\nคุณจะต้องอัปเดต secret ในแอปพลิเคชันของคุณด้วย`)) return;
  doRotate(clientId);
}

async function doRotate(clientId) {
  try {
    const res = await fetch('/api/oauth/clients', {
      method: 'PATCH',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: clientId })
    });
    const data = await res.json();
    if (!res.ok) { alert(data.error || 'Rotate ไม่สำเร็จ'); return; }

    alert(`✅ Rotate สำเร็จ!\n\nClient ID: ${data.client_id}\nClient Secret ใหม่:\n${data.client_secret}\n\n⚠️ คัดลอกและบันทึกไว้ทันที จะไม่สามารถดูซ้ำได้`);
    loadApps();
  } catch {
    alert('ไม่สามารถเชื่อมต่อเซิร์ฟเวอร์ได้');
  }
}

// ── Delete ─────────────────────────────────────────────────────
function askDelete(clientId, appName) {
  pendingDeleteId   = clientId;
  pendingDeleteName = appName;
  document.getElementById('confirm-app-name').textContent = '"' + appName + '"';
  document.getElementById('confirm-overlay').classList.add('show');
}

function closeConfirm() {
  pendingDeleteId = pendingDeleteName = null;
  document.getElementById('confirm-overlay').classList.remove('show');
}

async function confirmDelete() {
  if (!pendingDeleteId) return;

  const btn = document.getElementById('btn-confirm-delete');
  btn.disabled    = true;
  btn.textContent = 'กำลังลบ...';

  try {
    const res = await fetch('/api/oauth/clients', {
      method: 'DELETE',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: pendingDeleteId })
    });

    if (!res.ok) { const d = await res.json(); alert(d.error || 'ลบไม่สำเร็จ กรุณาลองใหม่'); return; }

    closeConfirm();
    loadApps();
  } catch {
    alert('ไม่สามารถเชื่อมต่อเซิร์ฟเวอร์ได้');
  } finally {
    btn.disabled    = false;
    btn.textContent = 'ลบเลย';
  }
}

// ── Logout ─────────────────────────────────────────────────────
async function logout() {
  try { await fetch('/api/logout', { method: 'POST', credentials: 'include' }); } catch {}
  location.replace('/login');
}

// ── Helpers ────────────────────────────────────────────────────
function esc(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function formatDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('th-TH', { day: 'numeric', month: 'short', year: 'numeric' });
}

async function copyText(elemId, btn) {
  const text = document.getElementById(elemId).textContent;
  try {
    await navigator.clipboard.writeText(text);
    btn.textContent = '✅';
    setTimeout(() => { btn.textContent = '📋'; }, 1500);
  } catch {
    btn.textContent = '❌';
    setTimeout(() => { btn.textContent = '📋'; }, 1500);
  }
}

// ── DOMContentLoaded ───────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Enter กด create
  ['input-name', 'input-uri'].forEach(id => {
    document.getElementById(id).addEventListener('keydown', e => {
      if (e.key === 'Enter') createApp();
    });
  });

  // ปุ่ม create
  document.getElementById('btn-create').addEventListener('click', createApp);

  // ปุ่ม copy credentials
  document.getElementById('copy-client-id')    ?.addEventListener('click', function() { copyText('res-client-id', this); });
  document.getElementById('copy-client-secret')?.addEventListener('click', function() { copyText('res-client-secret', this); });

  // confirm overlay buttons
  document.getElementById('btn-cancel-confirm') .addEventListener('click', closeConfirm);
  document.getElementById('btn-confirm-delete') .addEventListener('click', confirmDelete);

  // logout
  document.getElementById('btn-logout').addEventListener('click', logout);

  // ปิด overlay เมื่อกด Escape
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeConfirm(); });
});

// ── Start ──────────────────────────────────────────────────────
init();
