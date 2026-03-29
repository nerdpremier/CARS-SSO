'use strict';

let _oauthParams  = {};
let _isSubmitting = false;
let _preLoginLogId = null;

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

function getSecureFp() {
  try {
    let id = localStorage.getItem('_device_fp');
    if (!id) { id = crypto.randomUUID(); localStorage.setItem('_device_fp', id); }
    return id;
  } catch {
    try {
      const h = [screen.width+'x'+screen.height, navigator.hardwareConcurrency||0, navigator.language||''].join('|');
      return btoa(encodeURIComponent(h)).substring(0, 128);
    } catch { return crypto.randomUUID(); }
  }
}

function getDeviceInfo() {
  const device = `Screen:${screen.width}x${screen.height} | CPU:${navigator.hardwareConcurrency}`;
  console.log('[DEBUG] Device info collected:', device);
  return device;
}

async function init() {
  document.body.classList.remove('auth-pending');
  $id('main-card').hidden = false;

  const sp           = new URLSearchParams(window.location.search);
  const clientId     = sp.get('client_id');
  const redirectUri  = sp.get('redirect_uri');
  const responseType = sp.get('response_type');
  const state        = sp.get('state');

  const scope                = sp.get('scope')                  || null;
  const codeChallenge        = sp.get('code_challenge')         || null;
  const codeChallengeMethod  = sp.get('code_challenge_method')  || null;
  const preLoginLogIdParam   = sp.get('pre_login_log_id')       || null;

  if (!clientId || !redirectUri || !state || responseType !== 'code') {
    showError('Missing or invalid OAuth parameters.');
    return;
  }

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

    const fingerprint = getSecureFp();
    const device = getDeviceInfo();
    apiUrl.searchParams.set('fingerprint', fingerprint);
    apiUrl.searchParams.set('device', device);

    console.log('[DEBUG] Sending GET with device:', device, 'fingerprint:', fingerprint);

    if (scope)               apiUrl.searchParams.set('scope',                 scope);
    if (codeChallenge)       apiUrl.searchParams.set('code_challenge',        codeChallenge);
    if (codeChallengeMethod) apiUrl.searchParams.set('code_challenge_method', codeChallengeMethod);
    if (preLoginLogIdParam && /^\d+$/.test(preLoginLogIdParam))
                             apiUrl.searchParams.set('pre_login_log_id',      preLoginLogIdParam);

    const res = await fetch(apiUrl.toString(), { credentials: 'include' });
    data = await res.json();

    if (res.status === 401) {
      document.cookie = 'session_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';

      const currentUrl = new URL(window.location.href);
      const redirectBack = currentUrl.searchParams.get('redirect_uri');
      
      // Remove pre_login_log_id to prevent stale ID issues when switching browsers
      currentUrl.searchParams.delete('pre_login_log_id');
      const nextUrl = currentUrl.toString();
      
      const loginUrl = new URL('/login', window.location.origin);
      loginUrl.searchParams.set('next', nextUrl);
      if (redirectBack) {
        loginUrl.searchParams.set('redirect_back', redirectBack);
      }
      window.location.replace(loginUrl.toString());
      return;
    }
    if (!res.ok) { showError(data?.error || 'Failed to verify request.'); return; }
  } catch {
    showError('Unable to connect to server. Please try again.');
    return;
  }

  if (Array.isArray(data.scope)) {
    _oauthParams.scope = data.scope.join(' ');
  }

  if (data.pre_login_log_id) {
    _preLoginLogId = data.pre_login_log_id;
    console.log(`[INFO] authorize.js: Received pre_login_log_id=${_preLoginLogId}`);
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

    const body = {
      client_id:    _oauthParams.clientId,
      redirect_uri: _oauthParams.redirectUri,
      state:        _oauthParams.state,
      approved:     true,
    };

    const fingerprint = getSecureFp();
    const device = getDeviceInfo();
    body.fingerprint = fingerprint;
    body.device = device;

    console.log('[DEBUG] Sending POST with device:', device, 'fingerprint:', fingerprint);

    if (_oauthParams.scope) {
      body.scope = _oauthParams.scope;
    }

    if (_oauthParams.codeChallenge && _oauthParams.codeChallengeMethod) {
      body.code_challenge        = _oauthParams.codeChallenge;
      body.code_challenge_method = _oauthParams.codeChallengeMethod;
    }

    if (_preLoginLogId) {
      body.pre_login_log_id = _preLoginLogId;
    }

    const res = await fetch('/api/oauth/authorize', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await res.json();

    if (!res.ok) {
      if (res.status === 401) {
        const currentUrl = new URL(window.location.href);
        const redirectBack = currentUrl.searchParams.get('redirect_uri');
        const loginUrl = new URL('/login', window.location.origin);
        loginUrl.searchParams.set('next', window.location.href);
        if (redirectBack) {
          loginUrl.searchParams.set('redirect_back', redirectBack);
        }
        window.location.replace(loginUrl.toString());
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
  if (!_oauthParams.redirectUri || !_oauthParams.state) {
    showError('Cannot process denial — authorization parameters are missing.');
    return;
  }
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

  const signOutLink = $id('signout-link');
  if (signOutLink) {
    signOutLink.addEventListener('click', async (e) => {
      e.preventDefault();
      
      const currentUrl = window.location.href;
      sessionStorage.setItem('post_logout_redirect', currentUrl);
      
      let csrfToken = null;
      try {
        const csrfRes = await fetch('/api/csrf', { credentials: 'include', cache: 'no-store' });
        if (csrfRes.ok) {
          const csrfData = await csrfRes.json();
          csrfToken = csrfData?.token;
        }
      } catch (err) {
        console.warn('Failed to get CSRF token:', err);
      }
      
      const headers = { 'Content-Type': 'application/json' };
      if (csrfToken) {
        headers['X-CSRF-Token'] = csrfToken;
      }
      
      fetch('/api/logout', {
        method: 'POST',
        credentials: 'include',
        headers
      }).catch(() => {}).finally(() => {
        document.cookie = 'session_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; SameSite=Strict';
        document.cookie = 'csrf_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; SameSite=Strict';
        window.location.href = '/logout';
      });
    });
  }

  init();
});
