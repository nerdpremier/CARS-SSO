'use strict';

// CSP-safe: no element.style assignments; show/hide via element.hidden.

let pendingDeleteId   = null;
let pendingDeleteName = null;

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
    const res  = await fetch('/api/oauth/clients', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, redirect_uris: [uri] })
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
  if (!confirm(`Rotate the client secret for "${appName}"?\n\nAll existing tokens will be revoked immediately.\nYou will need to update the secret in your application.`)) return;
  doRotate(clientId);
}
async function doRotate(clientId) {
  try {
    const res  = await fetch('/api/oauth/clients', { method:'PATCH', credentials:'include', headers:{'Content-Type':'application/json'}, body:JSON.stringify({client_id:clientId}) });
    const data = await res.json();
    if (!res.ok) { alert(data.error||'Rotation failed. Please try again.'); return; }
    alert(`✅ Secret rotated successfully!\n\nClient ID: ${data.client_id}\nNew Client Secret:\n${data.client_secret}\n\n⚠️ Copy and save this now — it cannot be viewed again.`);
    loadApps();
  } catch { alert('Unable to connect to server. Please try again.'); }
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
    const res = await fetch('/api/oauth/clients', { method:'DELETE', credentials:'include', headers:{'Content-Type':'application/json'}, body:JSON.stringify({client_id:pendingDeleteId}) });
    if (!res.ok) { const d=await res.json(); alert(d.error||'Delete failed. Please try again.'); return; }
    closeConfirm(); loadApps();
  } catch { alert('Unable to connect to server. Please try again.'); }
  finally { btn.disabled=false; btn.textContent='Delete'; }
}

async function logout() {
  try { await fetch('/api/logout',{method:'POST',credentials:'include'}); } catch {}
  location.replace('/login');
}

function esc(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
}
function formatDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('en-US',{day:'numeric',month:'short',year:'numeric'});
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
  document.getElementById('btn-logout')        ?.addEventListener('click', logout);
  document.addEventListener('keydown', e=>{if(e.key==='Escape')closeConfirm();});
});

init();
