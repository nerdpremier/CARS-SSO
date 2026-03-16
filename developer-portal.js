'use strict';

// CSP-safe: no element.style assignments; show/hide via element.hidden.

let pendingDeleteId   = null;
let pendingDeleteName = null;
let pendingRotateId   = null;
let pendingRotateName = null;

// ── CSRF ─────────────────────────────────────────────────────
let _csrfToken = null;
async function getCsrfToken() {
  if (_csrfToken) return _csrfToken;
  const res = await fetch('/api/csrf', { credentials: 'include' });
  if (!res.ok) throw new Error('Unable to fetch CSRF token');
  const data = await res.json();
  if (typeof data.token !== 'string' || !data.token) throw new Error('Invalid CSRF token');
  _csrfToken = data.token;
  return _csrfToken;
}
// apiFetch: ใช้สำหรับ mutating requests (POST/PATCH/DELETE) เท่านั้น
// แนบ X-CSRF-Token ทุกครั้ง + auto-retry เมื่อ token หมดอายุ (403)
async function apiFetch(url, options = {}) {
  const token = await getCsrfToken();
  const res = await fetch(url, {
    ...options,
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token, ...(options.headers || {}) },
  });
  if (res.status === 403) {
    _csrfToken = null;
    const token2 = await getCsrfToken();
    return fetch(url, {
      ...options,
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token2, ...(options.headers || {}) },
    });
  }
  return res;
}

async function init() {
  let res;
  try { res = await fetch('/api/session', { credentials: 'include' }); }
  catch { location.replace('/login'); return; }
  if (!res.ok) { location.replace('/login?next=' + encodeURIComponent(location.href)); return; }
  const data = await res.json();
  if (!data.authenticated) { location.replace('/login?next=' + encodeURIComponent(location.href)); return; }
  document.body.classList.remove('auth-pending');
  document.getElementById('user-name').textContent = data.user;
  document.getElementById('portal').classList.remove('portal--hidden');
  loadApps();
}

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
        <div class="apps-empty">
          <div class="apps-empty-icon">🔌</div>
          <div class="apps-empty-title">No apps yet</div>
          <div class="apps-empty-sub">Fill in the form above to create your first app.</div>
        </div>`;
      return;
    }
    list.innerHTML = apps.map(app => `
      <div class="app-card" role="listitem">
        <div class="app-card-main">
          <div class="app-name">${esc(app.name)}</div>
          <div class="app-id">${esc(app.client_id)}</div>
          <div>${(app.redirect_uris||[]).map(u=>`<span class="uri-chip" title="${esc(u)}">${esc(u)}</span>`).join('')}</div>
          <div class="app-date">Created ${formatDate(app.created_at)}</div>
        </div>
        <div class="app-card-actions">
          <button class="btn-rotate" type="button" data-action="rotate" data-client-id="${esc(app.client_id)}" data-app-name="${esc(app.name)}">🔄 Rotate Secret</button>
          <button class="btn-delete" type="button" data-action="delete" data-client-id="${esc(app.client_id)}" data-app-name="${esc(app.name)}">Delete</button>
        </div>
      </div>`).join('');
    list.querySelectorAll('[data-action="rotate"]').forEach(btn => btn.addEventListener('click', ()=>askRotate(btn.dataset.clientId, btn.dataset.appName)));
    list.querySelectorAll('[data-action="delete"]').forEach(btn => btn.addEventListener('click', ()=>askDelete(btn.dataset.clientId, btn.dataset.appName)));
  } catch {
    list.innerHTML = `<div class="apps-load-error">Failed to load apps. Please refresh the page.</div>`;
    count.textContent = '—';
  }
}

async function createApp() {
  const name      = document.getElementById('input-name').value.trim();
  const uri       = document.getElementById('input-uri').value.trim();
  const btn       = document.getElementById('btn-create');
  const resultBox = document.getElementById('result-box');

  resultBox.hidden = true;    // CSP-safe
  clearCreateStatus();

  if (!name) return showCreateError('Please enter an app name.');
  if (!uri)  return showCreateError('Please enter a Callback URL.');
  try {
    const parsed = new URL(uri);
    const isLocal = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';
    if (parsed.protocol !== 'https:' && !isLocal) return showCreateError('Callback URL must use https:// (or localhost for dev).');
  } catch { return showCreateError('Invalid Callback URL format.'); }

  btn.disabled = true; btn.textContent = 'Creating…';
  try {
    const res  = await apiFetch('/api/oauth/clients', {
      method: 'POST',
      body: JSON.stringify({
      name,
      redirect_uris: [uri],
      allowed_scopes: [
        'profile',
        ...(document.getElementById('scope-email')?.checked  ? ['email']  : []),
        ...(document.getElementById('scope-openid')?.checked ? ['openid'] : []),
      ],
    })
    });
    const data = await res.json();
    if (!res.ok) { showCreateError(data.error || 'An error occurred. Please try again.'); return; }
    document.getElementById('res-client-id').textContent     = data.client_id;
    document.getElementById('res-client-secret').textContent = data.client_secret;
    resultBox.hidden = false;   // CSP-safe: :not([hidden]) CSS makes it block
    resultBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    document.getElementById('input-name').value = '';
    document.getElementById('input-uri').value  = '';
    loadApps();
    if (window.CarsToast) {
      window.CarsToast({ type:'success', title:'App created', msg:'Credentials are shown once—save the secret now.', duration: 4200 });
    }
  } catch { showCreateError('Unable to connect to server. Please try again.'); }
  finally { btn.disabled = false; btn.textContent = 'Create App'; }
}

// FIX: className was 'create-error' (no CSS rule). Now uses 'danger' to match CSS.
function showCreateError(msg) {
  const el = document.getElementById('create-status');
  el.textContent = '⚠️ ' + msg;
  el.className   = 'danger';
  el.hidden      = false;    // CSP-safe
  document.getElementById('btn-create').disabled    = false;
  document.getElementById('btn-create').textContent = 'Create App';
}
function clearCreateStatus() {
  const el = document.getElementById('create-status');
  el.textContent = ''; el.className = ''; el.hidden = true;
}

function askRotate(clientId, appName) {
  pendingRotateId   = clientId;
  pendingRotateName = appName;
  document.getElementById('rotate-app-name').textContent = `"${appName}"`;
  document.getElementById('rotate-overlay').hidden = false;
}
function closeRotate() {
  pendingRotateId = null; pendingRotateName = null;
  document.getElementById('rotate-overlay').hidden = true;
}
async function confirmRotate() {
  if (!pendingRotateId) return;
  const btn = document.getElementById('btn-confirm-rotate');
  btn.disabled = true; btn.textContent = 'Rotating…';
  const id = pendingRotateId;
  closeRotate();
  await doRotate(id);
  btn.disabled = false; btn.textContent = 'Rotate';
}
async function doRotate(clientId) {
  try {
    const res  = await apiFetch('/api/oauth/clients', { method:'PATCH', body:JSON.stringify({client_id:clientId}) });
    const data = await res.json();
    if (!res.ok) {
      (window.CarsToast ? window.CarsToast({ type:'danger', title:'Rotate failed', msg: data.error || 'Please try again.' }) : alert(data.error||'Rotation failed. Please try again.'));
      return;
    }
    document.getElementById('res-client-id').textContent     = data.client_id;
    document.getElementById('res-client-secret').textContent = data.client_secret;
    document.getElementById('result-box').hidden = false;
    document.getElementById('result-box').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    loadApps();
    if (window.CarsToast) {
      window.CarsToast({ type:'success', title:'Secret rotated', msg:'All prior tokens were revoked. Update your app config.', duration: 4200 });
    }
  } catch {
    (window.CarsToast ? window.CarsToast({ type:'danger', title:'Network error', msg:'Unable to connect. Please try again.' }) : alert('Unable to connect to server. Please try again.'));
  }
}

function askDelete(clientId, appName) {
  pendingDeleteId   = clientId;
  pendingDeleteName = appName;
  document.getElementById('confirm-app-name').textContent = `"${appName}"`;
  document.getElementById('confirm-overlay').hidden = false;  // CSP-safe: :not([hidden]) shows as flex
}
function closeConfirm() {
  pendingDeleteId = null; pendingDeleteName = null;
  document.getElementById('confirm-overlay').hidden = true;
}
async function confirmDelete() {
  if (!pendingDeleteId) return;
  const btn = document.getElementById('btn-confirm-delete');
  btn.disabled = true; btn.textContent = 'Deleting…';
  try {
    const res = await apiFetch('/api/oauth/clients', { method:'DELETE', body:JSON.stringify({client_id:pendingDeleteId}) });
    if (!res.ok) {
      const d=await res.json();
      (window.CarsToast ? window.CarsToast({ type:'danger', title:'Delete failed', msg: d.error || 'Please try again.' }) : alert(d.error||'Delete failed. Please try again.'));
      return;
    }
    closeConfirm(); loadApps();
    if (window.CarsToast) {
      window.CarsToast({ type:'success', title:'App deleted', msg:'All tokens were revoked immediately.', duration: 3200 });
    }
  } catch {
    (window.CarsToast ? window.CarsToast({ type:'danger', title:'Network error', msg:'Unable to connect. Please try again.' }) : alert('Unable to connect to server. Please try again.'));
  }
  finally { btn.disabled=false; btn.textContent='Delete'; }
}

async function logout() {
  try { await apiFetch('/api/logout',{method:'POST'}); } catch {}
  location.replace('/login');
}

function esc(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
}
function formatDate(iso) {
  if (!iso) return '—';
  // [FIX] escape output ก่อนใส่ใน innerHTML
  // new Date(malicious_string) → toLocaleDateString คืน "Invalid Date" (safe string)
  // แต่ถ้า browser locale plugin หรือ Intl polyfill behave แปลก → esc() เป็น defense-in-depth
  return esc(new Date(iso).toLocaleDateString('en-US',{day:'numeric',month:'short',year:'numeric'}));
}
async function copyText(elemId, btn) {
  const text = document.getElementById(elemId)?.textContent||'';
  try { await navigator.clipboard.writeText(text); btn.textContent='✅ Copied'; setTimeout(()=>{btn.textContent='Copy';},1800); }
  catch { btn.textContent='❌ Failed'; setTimeout(()=>{btn.textContent='Copy';},1800); }
}

document.addEventListener('DOMContentLoaded', () => {
  ['input-name','input-uri'].forEach(id=>document.getElementById(id)?.addEventListener('keydown',e=>{if(e.key==='Enter')createApp();}));
  document.getElementById('btn-create')        ?.addEventListener('click', createApp);
  document.getElementById('copy-client-id')    ?.addEventListener('click', function(){copyText('res-client-id',this);});
  document.getElementById('copy-client-secret')?.addEventListener('click', function(){copyText('res-client-secret',this);});
  document.getElementById('btn-cancel')        ?.addEventListener('click', closeConfirm);
  document.getElementById('btn-confirm-delete')?.addEventListener('click', confirmDelete);
  document.getElementById('btn-rotate-cancel') ?.addEventListener('click', closeRotate);
  document.getElementById('btn-confirm-rotate')?.addEventListener('click', confirmRotate);
  document.getElementById('btn-logout')        ?.addEventListener('click', logout);
  document.addEventListener('keydown', e=>{if(e.key==='Escape'){closeConfirm();closeRotate();}});
});

init();
