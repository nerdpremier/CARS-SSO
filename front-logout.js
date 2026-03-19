// Front-channel logout for customer apps:
// - Same-origin to SSO, so cookies + CSRF work
// - Then redirect back to ?next=

function safeNext() {
  try {
    // [FIX-LOGOUT] ตรวจสอบว่ามี URL ที่เก็บไว้ก่อน logout หรือไม่
    const postLogoutRedirect = sessionStorage.getItem('post_logout_redirect');
    if (postLogoutRedirect) {
      sessionStorage.removeItem('post_logout_redirect');
      // สร้าง URL สำหรับ login พร้อม next=
      const loginUrl = new URL('/login', window.location.origin);
      loginUrl.searchParams.set('next', postLogoutRedirect);
      return loginUrl.toString();
    }
    
    const sp = new URLSearchParams(window.location.search);
    const next = sp.get('next');
    if (!next) return '/login';
    const u = new URL(next);
    const isHttps = u.protocol === 'https:';
    const isLocal = u.protocol === 'http:' && (u.hostname === 'localhost' || u.hostname === '127.0.0.1');
    return (isHttps || isLocal) ? u.toString() : '/login';
  } catch {
    return '/login';
  }
}

function setStatus(msg, type) {
  const box = document.getElementById('status-box');
  if (!box) return;
  box.className = 'status-box';
  box.hidden = false;
  if (type === 'danger') box.classList.add('danger');
  else if (type === 'success') box.classList.add('success');
  else box.classList.add('loading');
  box.textContent = msg;
}

(async function () {
  try {
    // 1) Fetch CSRF token (sets csrf_token cookie + returns token)
    const csrfRes = await fetch('/api/csrf', { credentials: 'include', cache: 'no-store' });
    const csrfData = csrfRes.ok ? await csrfRes.json().catch(() => null) : null;
    const token = csrfData && typeof csrfData.token === 'string' ? csrfData.token : null;

    // 2) POST logout with CSRF header
    const logoutRes = await fetch('/api/logout', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { 'X-CSRF-Token': token } : {}),
      },
      body: JSON.stringify({}),
      cache: 'no-store',
    });

    if (!logoutRes.ok) {
      setStatus('Logout failed. Redirecting…', 'danger');
    } else {
      setStatus('Signed out. Redirecting…', 'success');
    }
  } catch (e) {
    setStatus('Logout failed. Redirecting…', 'danger');
  } finally {
    window.location.replace(safeNext());
  }
})();

