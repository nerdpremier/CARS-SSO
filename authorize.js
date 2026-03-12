// authorize.js — CARS SSO OAuth Consent Page
'use strict';

let _oauthParams  = {};
let _isSubmitting = false;

const $id = id => document.getElementById(id);

function showStatus(msg, type = 'danger') {
  const el = $id('status-msg');
  if (!el) return;
  el.textContent = msg;
  el.className = `status-box ${type}`;
}

function setSubmitting(on) {
  const btnAllow = $id('btn-allow');
  const btnDeny  = $id('btn-deny');
  if (!btnAllow || !btnDeny) return;
  btnAllow.disabled = on;
  btnDeny.disabled  = on;
  if (on) {
    btnAllow.textContent = 'Processing…';
    btnAllow.classList.add('btn--loading');
  } else {
    btnAllow.textContent = 'Allow Access';
    btnAllow.classList.remove('btn--loading');
  }
}

function showError(msg) {
  $id('loading-overlay').style.display = 'none';
  $id('consent-ui').style.display      = 'none';
  $id('error-ui').style.display        = 'block';
  $id('error-msg').textContent         = msg;
}

async function init() {
  document.body.classList.remove('auth-pending');
  document.body.style.visibility = '';
  $id('main-card').style.display = '';

  const sp           = new URLSearchParams(window.location.search);
  const clientId     = sp.get('client_id');
  const redirectUri  = sp.get('redirect_uri');
  const responseType = sp.get('response_type');
  const state        = sp.get('state');

  if (!clientId || !redirectUri || !state || responseType !== 'code') {
    showError('Missing or invalid OAuth parameters.');
    return;
  }
  _oauthParams = { clientId, redirectUri, state };

  let data;
  try {
    const apiUrl = new URL('/api/oauth/authorize', window.location.origin);
    apiUrl.searchParams.set('client_id',     clientId);
    apiUrl.searchParams.set('redirect_uri',  redirectUri);
    apiUrl.searchParams.set('response_type', responseType);
    apiUrl.searchParams.set('state',         state);

    const res = await fetch(apiUrl.toString(), { credentials: 'include' });
    data = await res.json();

    if (res.status === 401) {
      window.location.replace(`/login?next=${encodeURIComponent(window.location.href)}`);
      return;
    }
    if (!res.ok) { showError(data?.error || 'Failed to verify request.'); return; }
  } catch {
    showError('Unable to connect to server. Please try again.');
    return;
  }

  const appName  = data.app_name || 'Application';
  const username = data.username || '';
  $id('app-badge-name').textContent   = appName;
  $id('consent-subtitle').textContent = `"${appName}" is requesting access to your account.`;
  $id('user-chip-name').textContent   = username;
  $id('footer-username').textContent  = username;
  $id('user-chip').style.display      = 'inline-flex';
  $id('loading-overlay').style.display = 'none';
  $id('consent-ui').style.display      = 'block';
}

async function handleAllow() {
  if (_isSubmitting) return;
  _isSubmitting = true;
  $id('status-msg').className = 'status-box';
  setSubmitting(true);

  try {
    const res = await fetch('/api/oauth/authorize', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: _oauthParams.clientId, redirect_uri: _oauthParams.redirectUri,
        state: _oauthParams.state, approved: true
      })
    });
    const data = await res.json();

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
    window.location.replace(data.redirect_url);
  } catch {
    showStatus('Unable to connect to server. Please try again.');
    setSubmitting(false);
    _isSubmitting = false;
  }
}

function handleDeny() {
  if (_isSubmitting) return;
  _isSubmitting = true;
  setSubmitting(true);
  const url = new URL(_oauthParams.redirectUri);
  url.searchParams.set('error', 'access_denied');
  url.searchParams.set('state', _oauthParams.state);
  window.location.replace(url.toString());
}

document.addEventListener('DOMContentLoaded', () => {
  $id('btn-allow')?.addEventListener('click', handleAllow);
  $id('btn-deny')?.addEventListener('click',  handleDeny);
  init();
});
