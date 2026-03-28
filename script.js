let _submitting = false;
let resendCooldown = 0;
let resendTimerInterval;
let countdownTimer;

async function withGuard(fn, event) {
    if (_submitting) return;
    _submitting = true;
    let btn = null;
    if (event && event.target) {
        if (event.target.tagName === 'FORM') btn = event.target.querySelector('button[type="submit"],.btn-primary');
        else if (event.target.tagName === 'BUTTON') btn = event.target;
    }
    if (btn) btn.classList.add('btn--loading');
    try { await fn(); }
    finally { _submitting = false; if (btn) btn.classList.remove('btn--loading'); }
}

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
async function secureHeaders() {
    const token = await getCsrfToken();
    return { 'Content-Type': 'application/json', 'X-CSRF-Token': token };
}
async function secureFetch(url, options = {}, timeoutMs = 15000) {
    const controller = new AbortController();
    const timeoutId  = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const headers = await secureHeaders();
        const res = await fetch(url, {
            ...options, credentials: 'include',
            headers: { ...headers, ...(options.headers || {}) }, signal: controller.signal
        });
        if (res.status === 403) {
            _csrfToken = null;
            const rc = new AbortController(), rt = setTimeout(() => rc.abort(), timeoutMs);
            try {
                const rh = await secureHeaders();
                return await fetch(url, { ...options, credentials: 'include', headers: { ...rh, ...(options.headers || {}) }, signal: rc.signal });
            } finally { clearTimeout(rt); }
        }
        return res;
    } finally { clearTimeout(timeoutId); }
}

function updateStatus(type, msg) {
    const box = document.getElementById('status-box');
    if (!box) return;
    box.className = 'status-box';
    box.hidden = false;
    if (type === 'danger')       box.classList.add('danger');
    else if (type === 'success') box.classList.add('success');
    else if (type === 'warning') box.classList.add('warning');
    else                         box.classList.add('loading');
    box.textContent = msg;
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

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
function validateEmail(e)    { return (!e || !EMAIL_REGEX.test(e)) ? 'กรุณากรอกอีเมลที่ถูกต้อง' : null; }
function validatePassword(p) {
    const r = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    return (p && !r.test(p)) ? 'รหัสผ่านต้องมีอย่างน้อย 8 ตัวอักษร พร้อมตัวพิมพ์ใหญ่ พิมพ์เล็ก ตัวเลข และสัญลักษณ์' : null;
}
function validateInputs(u, p) {
    if (u && u.length > 32)  return 'ชื่อผู้ใช้ต้องมีไม่เกิน 32 ตัวอักษร';
    if (p && p.length > 128) return 'รหัสผ่านต้องมีไม่เกิน 128 ตัวอักษร';
    if (u && !/^[a-zA-Z0-9]+$/.test(u)) return 'ชื่อผู้ใช้สามารถใช้ได้เฉพาะตัวอักษรภาษาอังกฤษและตัวเลขเท่านั้น';
    return validatePassword(p);
}

const PASSWORD_RULES = [
    { id:'rule-length',  test: p=>p.length>=8,        label:'อย่างน้อย 8 ตัวอักษร' },
    { id:'rule-upper',   test: p=>/[A-Z]/.test(p),    label:'ตัวอักษรพิมพ์ใหญ่ (A–Z)' },
    { id:'rule-lower',   test: p=>/[a-z]/.test(p),    label:'ตัวอักษรพิมพ์เล็ก (a–z)' },
    { id:'rule-number',  test: p=>/\d/.test(p),        label:'ตัวเลข (0–9)' },
    { id:'rule-special', test: p=>/[@$!%*?&]/.test(p), label:'สัญลักษณ์ (@$!%*?&)' },
];
function checkPasswordStrength(password) {
    PASSWORD_RULES.forEach(({ id, test, label }) => {
        const el = document.getElementById(id); if (!el) return;
        const pass = test(password);
        el.classList.toggle('pass', pass);
        el.setAttribute('aria-label', `${pass?'Met':'Not met'}: ${label}`);
    });
}

async function handleRegister() {
    const username = document.getElementById('username')?.value.trim();
    const email    = document.getElementById('email')?.value.trim();
    const password = document.getElementById('password')?.value;
    if (!username||!email||!password) return updateStatus('danger','Please fill in all fields.');
    const ie = validateInputs(username,password); if (ie) return updateStatus('danger',ie);
    const ee = validateEmail(email);              if (ee) return updateStatus('danger',ee);
    updateStatus('loading','Creating your account…');

    const sp = new URLSearchParams(window.location.search);
    let nextUrl = sp.get('next');
    let redirectBack = sp.get('redirect_back');

    if (nextUrl) {
        try {
            let decoded = nextUrl;
            for (let i = 0; i < 3; i++) {
                const prev = decoded;
                decoded = decodeURIComponent(decoded);
                if (prev === decoded) break;
            }
            nextUrl = decoded;
        } catch {}
    }

    try {
        const reqBody = {action:'register',username,email,password};
        if (nextUrl) reqBody.next = nextUrl;
        if (redirectBack) reqBody.redirect_back = redirectBack;

        const res  = await secureFetch('/api/auth',{method:'POST',body:JSON.stringify(reqBody)});
        const data = await res.json();
        if (res.ok) {
            if (data.email_verification) {
                updateStatus('success','Account created! Check your email to verify before signing in.');
                const form = document.getElementById('register-form');
                if (form) form.hidden = true;

                const pendingNext = nextUrl || redirectBack;
                if (pendingNext) sessionStorage.setItem('post_verify_redirect', pendingNext);
            } else {
                updateStatus('success','Account created! Redirecting…');

                const loginUrl = new URL('/login', window.location.origin);
                if (nextUrl) loginUrl.searchParams.set('next', nextUrl);
                if (redirectBack) loginUrl.searchParams.set('redirect_back', redirectBack);

                const dest = loginUrl.toString();
                setTimeout(() => window.location.href = dest, 1500);
            }
        } else { updateStatus('danger', data.error||'An error occurred. Please try again.'); }
    } catch (err) {
        updateStatus('danger', err.name==='AbortError'?'Request timed out. Please try again.':'Something went wrong. Please try again later.');
    }
}

async function preLoginCheck() {
    const username = document.getElementById('username')?.value.trim();
    const password = document.getElementById('password')?.value;
    const remember = document.getElementById('remember-device')?.checked;
    const sp = new URLSearchParams(window.location.search);

    const pendingRedirect = sp.get('verified') ? sessionStorage.getItem('post_verify_redirect') : null;
    if (pendingRedirect) sessionStorage.removeItem('post_verify_redirect');

    let nextUrl = sp.get('next');

    if (nextUrl) {
        try {

            let decoded = nextUrl;
            let attempts = 0;
            while (attempts < 5) {
                try {
                    const prevDecoded = decoded;
                    decoded = decodeURIComponent(decoded);
                    if (prevDecoded === decoded) break; 
                    attempts++;
                } catch {
                    break; 
                }
            }
            nextUrl = decoded;

            try {
                const parsedNext = new URL(nextUrl, window.location.origin);
                        if (parsedNext.pathname === '/oauth/authorize') {

                }
            } catch (urlErr) {
                console.error('[ERROR] Failed to parse decoded URL:', urlErr);

            }
        } catch (err) {
            console.error('[ERROR] Failed to decode nextUrl:', err);

        }
    }

    nextUrl = nextUrl || (pendingRedirect?.startsWith('/') ? pendingRedirect : null) || null;
    const redirect_back = sp.get('redirect_back') || (pendingRedirect && !pendingRedirect.startsWith('/') ? pendingRedirect : null) || null;

    if (!username||!password) return updateStatus('danger','Please enter your username and password.');
    updateStatus('loading','Verifying your credentials…');
    try {
        const fingerprint = getSecureFp();
        const device = `Screen:${screen.width}x${screen.height} | CPU:${navigator.hardwareConcurrency}`;

        const storedLogId = sessionStorage.getItem('oauth_logId');
        const storedUsername = sessionStorage.getItem('oauth_username');
        let riskRes;

        if (storedLogId && storedUsername && storedUsername === username) {

            riskRes = await secureFetch('/api/assess',{
                method:'POST',
                body:JSON.stringify({
                    username,device,fingerprint,
                    reuse_log_id: storedLogId,
                    next: nextUrl 
                })
            });

            sessionStorage.removeItem('oauth_logId');
            sessionStorage.removeItem('oauth_username');
        } else {

            riskRes = await secureFetch('/api/assess',{
                method:'POST',
                body:JSON.stringify({
                    username,device,fingerprint,
                    next: nextUrl 
                })
            });
        }

        const riskData = await riskRes.json();
        if (riskData.risk_level==='HIGH') { startAccountLockdown(60); return; }
        if (!riskRes.ok) return updateStatus('danger','Something went wrong. Please try again later.');
        if (!riskData.logId) return updateStatus('danger','Incorrect username or password.');
        const logIdNum = Number(riskData.logId);
        if (!Number.isInteger(logIdNum)||logIdNum<=0) return updateStatus('danger','Incorrect username or password.');
        const safeLogId = String(logIdNum);

        const authBody = {action:'login',username,password,fingerprint,logId:safeLogId,remember};
        if (redirect_back) authBody.redirect_back = redirect_back;
        if (nextUrl) authBody.next = nextUrl; 

        if (redirect_back) {
            sessionStorage.setItem('oauth_logId', safeLogId);
            sessionStorage.setItem('oauth_username', username);
        }

        const authRes  = await secureFetch('/api/auth',{method:'POST',body:JSON.stringify(authBody)});
        const authData = await authRes.json();

        if (authRes.ok) {
            if (authData.mfa_required) {
                updateStatus('success', authData.email_pending
                    ? 'New device detected. If you don\'t receive the email within 1 minute, click "Resend Code".'
                    : 'Please enter the verification code sent to your email.');
                sessionStorage.setItem('mfa_logId',safeLogId);
                sessionStorage.setItem('mfa_username',username);
                sessionStorage.setItem('mfa_remember',String(remember));
                sessionStorage.setItem('mfa_fingerprint',fingerprint);

                if (redirect_back) sessionStorage.setItem('mfa_redirect_back', redirect_back);
                if (nextUrl)       sessionStorage.setItem('mfa_next_url', nextUrl);
                setTimeout(()=>window.location.href='/mfa',1500);
            } else {
                updateStatus('success','Signed in successfully. Redirecting…');

                let dest = authData.redirectUrl;
                const returnedLogId = authData.logId || safeLogId;

                if (!dest) {

                    if (nextUrl && nextUrl.includes('/oauth/authorize')) {
                        // แปะ pre_login_log_id ไปกับ OAuth authorize URL
                        const oauthUrl = new URL(nextUrl, window.location.origin);
                        oauthUrl.searchParams.set('pre_login_log_id', returnedLogId);
                        dest = oauthUrl.toString();
                    } else {
                        dest = nextUrl || '/welcome';
                    }
                } else {
                }
                setTimeout(()=>window.location.href=dest,1000);
            }
        } else {
            if (authData.email_not_verified) updateStatus('warning','Please verify your email before signing in. Check your inbox (or spam folder).');
            else updateStatus('danger', authData.error||'Incorrect username or password.');
        }
    } catch (err) {
        updateStatus('danger', err.name==='AbortError'?'Request timed out. Please try again.':'Something went wrong. Please try again later.');
    }
}

async function verifyMFA() {
    const code        = document.getElementById('mfa-code')?.value.trim();
    const logId       = sessionStorage.getItem('mfa_logId');
    const remember    = sessionStorage.getItem('mfa_remember');
    const username    = sessionStorage.getItem('mfa_username');
    const fingerprint = sessionStorage.getItem('mfa_fingerprint');
    const redirect_back = sessionStorage.getItem('mfa_redirect_back');

    const nextUrl     = sessionStorage.getItem('mfa_next_url');

    if (!code||!logId||!username) return updateStatus('danger','Session data missing. Please sign in again.');
    updateStatus('loading','Verifying your code…');
    try {
        const body = {action:'verify',logId,code,remember:remember==='true',username,fingerprint};
        if (redirect_back) body.redirect_back = redirect_back;

        const res = await secureFetch('/api/mfa',{method:'POST',body:JSON.stringify(body)});
        if (res.ok) {
            const data = await res.json();

            ['mfa_logId','mfa_username','mfa_remember','mfa_fingerprint',
             'mfa_redirect_back','mfa_next_url'].forEach(k=>sessionStorage.removeItem(k));
            updateStatus('success','Identity verified. Redirecting…');

            let dest = data.redirectUrl;
            if (!dest) {

                if (nextUrl && nextUrl.includes('/oauth/authorize')) {
                    // แปะ pre_login_log_id ไปกับ OAuth authorize URL
                    const oauthUrl = new URL(nextUrl, window.location.origin);
                    oauthUrl.searchParams.set('pre_login_log_id', logId);
                    dest = oauthUrl.toString();
                } else {
                    dest = nextUrl || '/welcome';
                }
            }
            setTimeout(()=>window.location.href=dest,1000);
        } else {
            const data = await res.json();
            updateStatus('danger', data.error||'Invalid code. Please try again.');
        }
    } catch (err) { updateStatus('danger', err.name==='AbortError'?'Request timed out.':'Something went wrong.'); }
}

async function resendMFA() {
    if (resendCooldown>0) return;
    const logId=sessionStorage.getItem('mfa_logId'), username=sessionStorage.getItem('mfa_username');
    updateStatus('loading','Sending a new code…');
    try {
        const res=await secureFetch('/api/mfa',{method:'POST',body:JSON.stringify({action:'resend',logId,username})});
        const data=await res.json();
        if (res.ok) { startResendCooldown(60); updateStatus('success','A new code has been sent. Check your email.'); }
        else updateStatus('danger',data.error||'Failed to resend. Please try again.');
    } catch (err) { updateStatus('danger', err.name==='AbortError'?'Request timed out.':'Something went wrong.'); }
}
function startResendCooldown(seconds) {
    const btn=document.getElementById('resend-btn'); if (!btn) return;
    resendCooldown=seconds; btn.disabled=true;
    clearInterval(resendTimerInterval);
    resendTimerInterval=setInterval(()=>{
        if (resendCooldown<=0) { clearInterval(resendTimerInterval); btn.disabled=false; btn.textContent='Resend Code'; return; }
        btn.textContent=`Resend (${resendCooldown}s)`; resendCooldown--;
    },1000);
}
function startAccountLockdown(seconds) {
    const btn=document.getElementById('login-btn'); let remaining=seconds;
    if (btn) btn.disabled=true;
    updateStatus('danger',`Account temporarily locked. Please wait ${remaining} seconds.`); remaining--;
    clearInterval(countdownTimer);
    countdownTimer=setInterval(()=>{
        if (remaining<=0) { clearInterval(countdownTimer); if (btn) btn.disabled=false; updateStatus('success','Lockout period ended. You may try again.'); return; }
        updateStatus('danger',`Account temporarily locked. Please wait ${remaining} seconds.`); remaining--;
    },1000);
}

async function requestPasswordReset() {
    const email=document.getElementById('reset-email')?.value.trim();
    if (!email) return updateStatus('danger','Please enter your email address.');
    const err=validateEmail(email); if (err) return updateStatus('danger',err);
    updateStatus('loading','Sending reset link…');
    try {
        const res=await secureFetch('/api/password',{method:'POST',body:JSON.stringify({action:'forgot',email})});
        const data=await res.json();
        if (res.ok) updateStatus('success',data.message||'Reset link sent. Check your email.');
        else updateStatus('danger',data.error||'An error occurred. Please try again.');
    } catch (err) { updateStatus('danger', err.name==='AbortError'?'Request timed out.':'Something went wrong.'); }
}
async function executePasswordReset() {
    const newPw=document.getElementById('new-password')?.value;
    const confPw=document.getElementById('confirm-password')?.value;
    if (!newPw||!confPw) return updateStatus('danger','Please fill in both password fields.');
    if (newPw!==confPw)  return updateStatus('danger','Passwords do not match.');
    const err=validatePassword(newPw); if (err) return updateStatus('danger',err);
    const token=new URLSearchParams(window.location.search).get('token');
    if (!token) return updateStatus('danger','Invalid link. Please request a new reset link.');

    const sp = new URLSearchParams(window.location.search);
    let nextUrl = sp.get('next');
    let redirectBack = sp.get('redirect_back');

    if (nextUrl) {
        try {
            let decoded = nextUrl;
            for (let i = 0; i < 3; i++) {
                const prev = decoded;
                decoded = decodeURIComponent(decoded);
                if (prev === decoded) break;
            }
            nextUrl = decoded;
        } catch {}
    }

    updateStatus('loading','Saving your new password…');
    try {
        const res=await secureFetch('/api/password',{method:'POST',body:JSON.stringify({action:'reset',token,password:newPw})});
        const data=await res.json();
        if (res.ok) { 
            updateStatus('success','Password updated. Redirecting to sign in…'); 

            const loginUrl = new URL('/login', window.location.origin);
            if (nextUrl) loginUrl.searchParams.set('next', nextUrl);
            if (redirectBack) loginUrl.searchParams.set('redirect_back', redirectBack);
            const dest = (nextUrl || redirectBack) ? loginUrl.toString() : '/login';
            setTimeout(() => window.location.href = dest, 2000); 
        }
        else updateStatus('danger',data.error||'An error occurred. Please try again.');
    } catch (err) { updateStatus('danger', err.name==='AbortError'?'Request timed out.':'Something went wrong.'); }
}

async function checkAuth() {
    try {
        const controller=new AbortController(), timeoutId=setTimeout(()=>controller.abort(),15000);
        let res;
        try { res=await fetch('/api/session',{credentials:'include',signal:controller.signal}); }
        finally { clearTimeout(timeoutId); }
        if (!res.ok) { window.location.replace('/login'); return; }
        const data=await res.json();
        if (!data.authenticated) { window.location.replace('/login'); return; }
        const el=document.getElementById('user-display');
        if (el&&typeof data.user==='string'&&data.user) el.textContent=data.user;
        document.body.classList.remove('auth-pending');
    } catch { window.location.replace('/login'); }
}
async function logout() {
    try { await secureFetch('/api/logout',{method:'POST'}); } catch {}
    // Clear cookies on client side as well
    document.cookie = 'session_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; SameSite=Strict';
    document.cookie = 'csrf_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; SameSite=Strict';
    window.location.replace('/login');
}

document.addEventListener('DOMContentLoaded', () => {
    // Clear any stale session cookie on login page load
    if (document.getElementById('login-form')) {
        document.cookie = 'session_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
    }

    if (document.getElementById('user-display')) checkAuth();
    document.getElementById('logout-btn')     ?.addEventListener('click', e=>withGuard(logout,e));
    document.getElementById('client-console-btn') ?.addEventListener('click', ()=>{window.location.href='/console';});
    if (document.getElementById('login-form')) {
        const qp=new URLSearchParams(window.location.search);
        if      (qp.get('verified')==='1')          updateStatus('success','Email verified! You can now sign in.');
        else if (qp.get('error')==='token_expired') updateStatus('warning','Your verification link has expired. Please register again.');
        else if (qp.get('error')==='invalid_token') updateStatus('danger', 'Invalid verification link. Please check your email again.');
    }
    document.getElementById('login-form')    ?.addEventListener('submit', e=>{e.preventDefault();withGuard(preLoginCheck,e);});
    document.getElementById('register-form') ?.addEventListener('submit', e=>{e.preventDefault();withGuard(handleRegister,e);});
    document.getElementById('mfa-form')      ?.addEventListener('submit', e=>{e.preventDefault();withGuard(verifyMFA,e);});
    document.getElementById('forgot-form')   ?.addEventListener('submit', e=>{e.preventDefault();withGuard(requestPasswordReset,e);});
    document.getElementById('reset-form')    ?.addEventListener('submit', e=>{e.preventDefault();withGuard(executePasswordReset,e);});
    document.getElementById('password')      ?.addEventListener('input', e=>checkPasswordStrength(e.target.value));
    document.getElementById('new-password')  ?.addEventListener('input', e=>checkPasswordStrength(e.target.value));
    document.getElementById('resend-btn')    ?.addEventListener('click', e=>withGuard(resendMFA,e));
    if (document.getElementById('mfa-code')) {
        if (!sessionStorage.getItem('mfa_logId')||!sessionStorage.getItem('mfa_username')) {
            window.location.replace('/login'); return;
        }
    }
});
