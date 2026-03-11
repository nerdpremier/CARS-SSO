// ============================================================
// authorize.js — OAuth Consent Page Logic
//
// Flow:
//   1. Read query params (client_id, redirect_uri, response_type, state)
//   2. GET /api/oauth/authorize → fetch app info + verify session
//   3. If not logged in → redirect to /login?next=<current URL>
//   4. Show consent UI
//   5. Allow: POST /api/oauth/authorize → redirect to redirect_url
//   6. Deny:  redirect to redirect_uri?error=access_denied&state=...
// ============================================================
'use strict';

// ── State ──────────────────────────────────────────────────────
let _oauthParams  = {};
let _isSubmitting = false;

// ── DOM helpers ────────────────────────────────────────────────
const $id     = id => document.getElementById(id);
const $loading = () => $id('loading-overlay');
const $consent = () => $id('consent-ui');
const $errorUi = () => $id('error-ui');

// ── Status helpers ─────────────────────────────────────────────
function showStatus(msg, type = 'danger') {
  const el = $id('status-msg');
  if (!el) return;
  el.textContent  = msg;
  el.className    = `status-box ${type}`;
  el.style.display = 'block';
}

function setSubmitting(on) {
  const btnAllow = $id('btn-allow');
  const btnDeny  = $id('btn-deny');
  if (!btnAllow || !btnDeny) return;
  btnAllow.disabled = on;
  btnDeny.disabled  = on;
  if (on) {
    btnAllow.textContent = 'Processing...';
    btnAllow.classList.add('btn--loading');
  } else {
    btnAllow.textContent = '✓ Allow';
    btnAllow.classList.remove('btn--loading');
  }
}

function showError(msg) {
  $loading().style.display = 'none';
  $consent().style.display = 'none';
  $id('error-ui').style.display  = 'block';
  $id('error-msg').textContent   = msg;
}

// ── Main: load session + app info, then show consent ──────────
async function init() {
  document.body.classList.remove('auth-pending');
  $id('main-card').style.display = '';

  // Parse OAuth params from URL
  const sp            = new URLSearchParams(window.location.search);
  const clientId      = sp.get('client_id');
  const redirectUri   = sp.get('redirect_uri');
  const responseType  = sp.get('response_type');
  const state         = sp.get('state');

  // Basic param validation before hitting the API
  if (!clientId || !redirectUri || !state || responseType !== 'code') {
    showError('Missing or invalid OAuth parameters.');
    return;
  }

  // Persist params for use in handleAllow / handleDeny
  _oauthParams = { clientId, redirectUri, state };

  // Fetch app info and verify session
  let data;
  try {
    const apiUrl = new URL('/api/oauth/authorize', window.location.origin);
    apiUrl.searchParams.set('client_id',     clientId);
    apiUrl.searchParams.set('redirect_uri',  redirectUri);
    apiUrl.searchParams.set('response_type', responseType);
    apiUrl.searchParams.set('state',         state);

    const res = await fetch(apiUrl.toString(), { credentials: 'include' });
    data = await res.json();

    // Not logged in → redirect to login with return URL
    if (res.status === 401) {
      const next = encodeURIComponent(window.location.href);
      window.location.replace(`/login?next=${next}`);
      return;
    }

    if (!res.ok) {
      showError(data?.error || 'Failed to verify authorization request.');
      return;
    }
  } catch {
    showError('Unable to connect to server. Please try again.');
    return;
  }

  // Populate and reveal consent UI
  const appName  = data.app_name || 'Application';
  const username = data.username || '';

  $id('app-badge-name').textContent   = appName;
  $id('consent-subtitle').textContent = `"${appName}" is requesting access to your account.`;
  $id('user-chip-name').textContent   = username;
  $id('footer-username').textContent  = username;
  $id('user-chip').style.display      = 'inline-flex';

  $loading().style.display = 'none';
  $consent().style.display = 'block';
}

// ── Allow ──────────────────────────────────────────────────────
async function handleAllow() {
  if (_isSubmitting) return;
  _isSubmitting = true;
  $id('status-msg').style.display = 'none';
  setSubmitting(true);

  try {
    const res = await fetch('/api/oauth/authorize', {
      method:      'POST',
      credentials: 'include',
      headers:     { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id:    _oauthParams.clientId,
        redirect_uri: _oauthParams.redirectUri,
        state:        _oauthParams.state,
        approved:     true
      })
    });

    const data = await res.json();

    if (!res.ok) {
      // Session expired — redirect back to login
      if (res.status === 401) {
        const next = encodeURIComponent(window.location.href);
        window.location.replace(`/login?next=${next}`);
        return;
      }
      showStatus(data?.error || 'An error occurred. Please try again.');
      setSubmitting(false);
      _isSubmitting = false;
      return;
    }

    // Redirect to the external app with the authorization code
    window.location.replace(data.redirect_url);

  } catch {
    showStatus('Unable to connect to server. Please try again.');
    setSubmitting(false);
    _isSubmitting = false;
  }
}

// ── Deny ───────────────────────────────────────────────────────
function handleDeny() {
  if (_isSubmitting) return;
  _isSubmitting = true;
  setSubmitting(true);

  // Redirect back with error=access_denied (no API call needed)
  const denyUrl = new URL(_oauthParams.redirectUri);
  denyUrl.searchParams.set('error', 'access_denied');
  denyUrl.searchParams.set('state', _oauthParams.state);
  window.location.replace(denyUrl.toString());
}

// ── Boot ───────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  $id('btn-allow')?.addEventListener('click', handleAllow);
  $id('btn-deny')?.addEventListener('click',  handleDeny);
  init();
});
