// authorize.js — CARS SSO OAuth Consent Page
//
// [FIX-PKCE] เพิ่ม scope, code_challenge, code_challenge_method ใน _oauthParams
//   เดิม: init() ไม่ได้อ่าน PKCE params จาก URL → handleAllow() ไม่ส่ง challenge ไป POST
//         oauth.js INSERT oauth_codes โดยไม่มี code_challenge → client ส่ง code_verifier
//         แต่ server ไม่มี challenge ไว้ match → PKCE ถูกละเลยทั้งหมด
//   แก้:  อ่าน + เก็บ PKCE params ใน _oauthParams, ส่งใน POST body ด้วย
//
// CSP-safe: no element.style assignments; show/hide via element.hidden.
'use strict';

let _oauthParams  = {};
let _isSubmitting = false;

// safeRedirect: ตรวจ scheme ก่อน window.location.replace()
// data.redirect_url มาจาก server ซึ่งตรวจ registered URI แล้ว
// แต่ defense-in-depth: client ต้องตรวจเองด้วยในกรณีที่ server response ถูก tamper
// อนุญาตเฉพาะ https: และ http: (localhost dev) — ป้องกัน javascript: / data: / file: scheme
function safeRedirect(url) {
  if (typeof url !== 'string') return;
  let parsed;
  try { parsed = new URL(url); } catch { return; }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return;
  window.location.replace(url);
}

// ── CSRF ──────────────────────────────────────────────────────
// handleAllow ส่ง POST ไป /api/oauth/authorize ต้องแนบ CSRF token
// ใช้ pattern เดียวกับ script.js (double-submit cookie)
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

const $id = id => document.getElementById(id);

function showStatus(msg, type = 'danger') {
  const el = $id('status-msg');
  if (!el) return;
  el.textContent = msg;
  el.className   = `status-box ${type}`;
  el.hidden      = false;
}

function setSubmitting(on) {
  const btnAllow = $id('btn-allow');
  const btnDeny  = $id('btn-deny');
  if (!btnAllow || !btnDeny) return;
  btnAllow.disabled = on;
  btnDeny.disabled  = on;
  if (on) { btnAllow.textContent = 'Processing…'; btnAllow.classList.add('btn--loading'); }
  else    { btnAllow.textContent = 'Allow Access'; btnAllow.classList.remove('btn--loading'); }
}

function showError(msg) {
  $id('loading-overlay').hidden = true;
  $id('consent-ui').hidden      = true;
  $id('error-ui').hidden        = false;
  $id('error-msg').textContent  = msg;
}

async function init() {
  document.body.classList.remove('auth-pending');
  $id('main-card').hidden = false;

  const sp           = new URLSearchParams(window.location.search);
  const clientId     = sp.get('client_id');
  const redirectUri  = sp.get('redirect_uri');
  const responseType = sp.get('response_type');
  const state        = sp.get('state');

  // [FIX-PKCE] อ่าน PKCE + scope params ที่ client ส่งมา
  const scope                = sp.get('scope')                  || null;
  const codeChallenge        = sp.get('code_challenge')         || null;
  const codeChallengeMethod  = sp.get('code_challenge_method')  || null;

  if (!clientId || !redirectUri || !state || responseType !== 'code') {
    showError('Missing or invalid OAuth parameters.');
    return;
  }

  // [FIX-PKCE] เก็บ PKCE + scope ไว้ใน _oauthParams เพื่อส่งใน handleAllow()
  _oauthParams = {
    clientId,
    redirectUri,
    state,
    scope,
    codeChallenge,
    codeChallengeMethod,
  };

  let data;
  try {
    const apiUrl = new URL('/api/oauth/authorize', window.location.origin);
    apiUrl.searchParams.set('client_id',     clientId);
    apiUrl.searchParams.set('redirect_uri',  redirectUri);
    apiUrl.searchParams.set('response_type', responseType);
    apiUrl.searchParams.set('state',         state);

    // [FIX-PKCE] ส่ง PKCE + scope ไปใน GET เพื่อให้ server validate ก่อนแสดง consent UI
    if (scope)               apiUrl.searchParams.set('scope',                 scope);
    if (codeChallenge)       apiUrl.searchParams.set('code_challenge',        codeChallenge);
    if (codeChallengeMethod) apiUrl.searchParams.set('code_challenge_method', codeChallengeMethod);

    const res = await fetch(apiUrl.toString(), { credentials: 'include' });
    data = await res.json();

    if (res.status === 401) {
      // ไม่ได้ login → redirect ไป login พร้อม ?next= เพื่อกลับมา consent หลัง login
      window.location.replace(`/login?next=${encodeURIComponent(window.location.href)}`);
      return;
    }
    if (!res.ok) { showError(data?.error || 'Failed to verify request.'); return; }
  } catch {
    showError('Unable to connect to server. Please try again.');
    return;
  }

  // อัปเดต scope จาก server response (server อาจ trim scope ลง)
  if (Array.isArray(data.scope)) {
    _oauthParams.scope = data.scope.join(' ');
  }

  const appName  = data.app_name || 'Application';
  const username = data.username || '';
  $id('app-badge-name').textContent   = appName;
  $id('consent-subtitle').textContent = `"${appName}" is requesting access to your account.`;
  $id('user-chip-name').textContent   = username;
  $id('footer-username').textContent  = username;
  $id('user-chip').hidden             = false;
  $id('loading-overlay').hidden       = true;
  $id('consent-ui').hidden            = false;

  // แสดง scopes ที่ขอ (ถ้ามี element)
  const scopeListEl = $id('scope-list');
  if (scopeListEl && data.scope) {
    const scopes = Array.isArray(data.scope) ? data.scope : [data.scope];
    scopeListEl.textContent = scopes.join(', ');
  }
}

async function handleAllow() {
  if (_isSubmitting) return;
  _isSubmitting = true;
  const sm = $id('status-msg');
  if (sm) { sm.className = 'status-box'; sm.hidden = true; }
  setSubmitting(true);

  try {
    // [FIX-PKCE] ส่ง scope + PKCE params ใน POST body ด้วย
    const body = {
      client_id:    _oauthParams.clientId,
      redirect_uri: _oauthParams.redirectUri,
      state:        _oauthParams.state,
      approved:     true,
    };

    // เพิ่ม scope ถ้ามีค่า
    if (_oauthParams.scope) {
      body.scope = _oauthParams.scope;
    }

    // เพิ่ม PKCE ถ้ามีค่า (ทั้งคู่ต้องมีพร้อมกัน)
    if (_oauthParams.codeChallenge && _oauthParams.codeChallengeMethod) {
      body.code_challenge        = _oauthParams.codeChallenge;
      body.code_challenge_method = _oauthParams.codeChallengeMethod;
    }

    const csrfToken = await getCsrfToken();
    const res = await fetch('/api/oauth/authorize', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
      body: JSON.stringify(body),
    });
    // auto-retry หาก CSRF หมดอายุ
    let data = await res.json();
    if (res.status === 403) {
      _csrfToken = null;
      const csrfToken2 = await getCsrfToken();
      const res2 = await fetch('/api/oauth/authorize', {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken2 },
        body: JSON.stringify(body),
      });
      data = await res2.json();
      if (!res2.ok) {
        if (res2.status === 401) { window.location.replace(`/login?next=${encodeURIComponent(window.location.href)}`); return; }
        showStatus(data?.error || 'An error occurred. Please try again.');
        setSubmitting(false); _isSubmitting = false; return;
      }
      safeRedirect(data.redirect_url);
      return;
    }

    if (!res.ok) {
      if (res.status === 401) {
        window.location.replace(`/login?next=${encodeURIComponent(window.location.href)}`);
        return;
      }
      showStatus(data?.error || 'An error occurred. Please try again.');
      setSubmitting(false);
      _isSubmitting = false;
      return;
    }
    safeRedirect(data.redirect_url);
  } catch {
    showStatus('Unable to connect to server. Please try again.');
    setSubmitting(false);
    _isSubmitting = false;
  }
}

async function handleDeny() {
  if (_isSubmitting) return;
  if (!_oauthParams.clientId || !_oauthParams.redirectUri || !_oauthParams.state) {
    showError('Cannot process denial — authorization parameters are missing.');
    return;
  }
  _isSubmitting = true;
  setSubmitting(true);
  const denyBody = JSON.stringify({
    client_id:    _oauthParams.clientId,
    redirect_uri: _oauthParams.redirectUri,
    state:        _oauthParams.state,
    approved:     false,
  });
  try {
    const csrfToken = await getCsrfToken();
    const res = await fetch('/api/oauth/authorize', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
      body: denyBody,
    });
    let data = await res.json();
    // [FIX] CSRF 403 retry — same pattern as handleAllow()
    if (res.status === 403) {
      _csrfToken = null;
      const csrfToken2 = await getCsrfToken();
      const res2 = await fetch('/api/oauth/authorize', {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken2 },
        body: denyBody,
      });
      data = await res2.json();
      if (!res2.ok) {
        if (res2.status === 401) { window.location.replace(`/login?next=${encodeURIComponent(window.location.href)}`); return; }
        showError(data?.error || 'An error occurred.');
        setSubmitting(false); _isSubmitting = false; return;
      }
      safeRedirect(data.redirect_url);
      return;
    }
    if (!res.ok) {
      if (res.status === 401) { window.location.replace(`/login?next=${encodeURIComponent(window.location.href)}`); return; }
      showError(data?.error || 'An error occurred.');
      setSubmitting(false); _isSubmitting = false; return;
    }
    safeRedirect(data.redirect_url);
  } catch {
    showError('Unable to connect to server. Please try again.');
    setSubmitting(false); _isSubmitting = false;
  }
}

// [FIX] handleSignOut: POST /api/logout แล้ว redirect ไป /login
// เดิม authorize.html มี <a href="/logout"> ซึ่งไม่มี route ใน vercel.json → 404
// ผู้ใช้ที่ต้องการ sign out ก่อน authorize จะทำไม่ได้
async function handleSignOut() {
  try {
    const csrfToken = await getCsrfToken();
    await fetch('/api/logout', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
    });
  } catch { /* ไม่สนใจ error — redirect ต่อเสมอ */ }
  window.location.replace('/login');
}

document.addEventListener('DOMContentLoaded', () => {
  $id('btn-allow')  ?.addEventListener('click', handleAllow);
  $id('btn-deny')   ?.addEventListener('click', handleDeny);
  $id('btn-signout')?.addEventListener('click', handleSignOut);
  init();
});
