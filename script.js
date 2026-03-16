// ==========================================
// CARS SSO — Core Frontend Logic
// CSP-safe: no element.style assignments.
// Show/hide via element.hidden (sets [hidden] attr, not inline style).
//
// [FIX-REDIRECT] แยก ?next= (same-origin, สำหรับ OAuth consent page)
//   ออกจาก ?redirect_back= (third-party SSO token redirect)
//
//   เดิม: script ส่งทั้งสองเป็น redirect_back ไปยัง auth API
//         validateRedirectBack() ตรวจกับ oauth_clients.redirect_uris
//         /oauth/authorize?... ไม่เคยอยู่ใน registered URIs
//         → redirectUrl = null → user ไป /welcome แทนกลับ consent page
//
//   แก้:  ?next= → หลัง login สำเร็จ redirect ฝั่ง frontend โดยตรง
//         ?redirect_back= → ส่งไป auth API เพื่อสร้าง SSO token เท่านั้น
// ==========================================

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

// ── UI Helpers ───────────────────────────────────────────────
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

// ── Device Fingerprint ───────────────────────────────────────
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

// ── Validation ───────────────────────────────────────────────
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
function validateEmail(e)    { return (!e || !EMAIL_REGEX.test(e)) ? 'Please enter a valid email address.' : null; }
function validatePassword(p) {
    const r = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    return (p && !r.test(p)) ? 'Password must be 8+ characters with uppercase, lowercase, a number, and a symbol.' : null;
}
function validateInputs(u, p) {
    if (u && u.length > 32)  return 'Username must be 32 characters or fewer.';
    if (p && p.length > 128) return 'Password must be 128 characters or fewer.';
    if (u && !/^[a-zA-Z0-9]+$/.test(u)) return 'Username may only contain letters and numbers.';
    return validatePassword(p);
}

// ── Password Strength ────────────────────────────────────────
const PASSWORD_RULES = [
    { id:'rule-length',  test: p=>p.length>=8,        label:'At least 8 characters' },
    { id:'rule-upper',   test: p=>/[A-Z]/.test(p),    label:'Uppercase letter (A–Z)' },
    { id:'rule-lower',   test: p=>/[a-z]/.test(p),    label:'Lowercase letter (a–z)' },
    { id:'rule-number',  test: p=>/\d/.test(p),        label:'Number (0–9)' },
    { id:'rule-special', test: p=>/[@$!%*?&]/.test(p), label:'Symbol (@$!%*?&)' },
];
function checkPasswordStrength(password) {
    PASSWORD_RULES.forEach(({ id, test, label }) => {
        const el = document.getElementById(id); if (!el) return;
        const icon = el.querySelector('.rule-icon');
        const pass = test(password);
        el.classList.toggle('pass', pass);
        el.setAttribute('aria-label', `${pass?'Met':'Not met'}: ${label}`);
        if (icon) icon.textContent = pass ? '✓' : '✗';
    });
}

// ── Register ─────────────────────────────────────────────────
async function handleRegister() {
    const username = document.getElementById('username')?.value.trim();
    const email    = document.getElementById('email')?.value.trim();
    const password = document.getElementById('password')?.value;
    if (!username||!email||!password) return updateStatus('danger','Please fill in all fields.');
    const ie = validateInputs(username,password); if (ie) return updateStatus('danger',ie);
    const ee = validateEmail(email);              if (ee) return updateStatus('danger',ee);
    updateStatus('loading','Creating your account…');
    try {
        const res  = await secureFetch('/api/auth',{method:'POST',body:JSON.stringify({action:'register',username,email,password})});
        const data = await res.json();
        if (res.ok) {
            if (data.email_verification) {
                updateStatus('success','✅ Account created! Check your email to verify before signing in.');
                const form = document.getElementById('register-form');
                if (form) form.hidden = true;
                // [FIX] บันทึก next/redirect_back ไว้ใน sessionStorage
                // เมื่อ user verify email แล้วกลับมา login ใหม่ params จะยังอยู่
                const sp2 = new URLSearchParams(window.location.search);
                const pendingNext = sp2.get('next') || sp2.get('redirect_back');
                if (pendingNext) sessionStorage.setItem('post_verify_redirect', pendingNext);
            } else {
                updateStatus('success','Account created! Redirecting…');
                setTimeout(()=>window.location.href='/login',1500);
            }
        } else { updateStatus('danger', data.error||'An error occurred. Please try again.'); }
    } catch (err) {
        updateStatus('danger', err.name==='AbortError'?'Request timed out. Please try again.':'Something went wrong. Please try again later.');
    }
}

// ── Login ─────────────────────────────────────────────────────
async function preLoginCheck() {
    const username = document.getElementById('username')?.value.trim();
    const password = document.getElementById('password')?.value;
    const remember = document.getElementById('remember-device')?.checked;
    const sp = new URLSearchParams(window.location.search);

    // [FIX-REDIRECT] แยก 2 ประเภทออกจากกัน:
    //   nextUrl       = same-origin URL เช่น /oauth/authorize?... (redirect หลัง login ฝั่ง frontend)
    //   redirect_back = registered third-party callback URL (สำหรับ SSO token creation ใน auth API)
    // [FIX] restore next/redirect_back ที่ save ไว้ตอน register (กรณี verified=1 params หาย)
    const pendingRedirect = sp.get('verified') ? sessionStorage.getItem('post_verify_redirect') : null;
    if (pendingRedirect) sessionStorage.removeItem('post_verify_redirect');
    const nextUrl       = sp.get('next')          || (pendingRedirect?.startsWith('/') ? pendingRedirect : null) || null;
    const redirect_back = sp.get('redirect_back') || (pendingRedirect && !pendingRedirect.startsWith('/') ? pendingRedirect : null) || null;

    if (!username||!password) return updateStatus('danger','Please enter your username and password.');
    updateStatus('loading','Verifying your credentials…');
    try {
        const fingerprint = getSecureFp();
        const device = `Screen:${screen.width}x${screen.height} | CPU:${navigator.hardwareConcurrency}`;
        const riskRes  = await secureFetch('/api/assess',{method:'POST',body:JSON.stringify({username,device,fingerprint})});
        const riskData = await riskRes.json();
        if (riskData.risk_level==='HIGH') { startAccountLockdown(60); return; }
        if (!riskRes.ok) return updateStatus('danger','Something went wrong. Please try again later.');
        if (!riskData.logId) return updateStatus('danger','Incorrect username or password.');
        const logIdNum = Number(riskData.logId);
        if (!Number.isInteger(logIdNum)||logIdNum<=0) return updateStatus('danger','Incorrect username or password.');
        const safeLogId = String(logIdNum);

        // [FIX-REDIRECT] ส่งเฉพาะ redirect_back (third-party SSO) ไปยัง auth API
        // ไม่ส่ง nextUrl เพราะ validateRedirectBack() จะ reject URL ที่ไม่ใช่ registered redirect_uri
        const authBody = {action:'login',username,password,fingerprint,logId:safeLogId,remember};
        if (redirect_back) authBody.redirect_back = redirect_back;

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
                // [FIX-REDIRECT] บันทึกทั้งสอง URL ใน sessionStorage สำหรับ MFA path
                if (redirect_back) sessionStorage.setItem('mfa_redirect_back', redirect_back);
                if (nextUrl)       sessionStorage.setItem('mfa_next_url', nextUrl);
                setTimeout(()=>window.location.href='/mfa',1500);
            } else {
                updateStatus('success','Signed in successfully. Redirecting…');
                // [FIX-REDIRECT] ลำดับ priority: SSO redirect → same-origin next → welcome
                const dest = authData.redirectUrl || nextUrl || '/welcome';
                setTimeout(()=>window.location.href=dest,1000);
            }
        } else {
            if (authData.email_not_verified) updateStatus('warning','📧 Please verify your email before signing in. Check your inbox (or spam folder).');
            else updateStatus('danger', authData.error||'Incorrect username or password.');
        }
    } catch (err) {
        updateStatus('danger', err.name==='AbortError'?'Request timed out. Please try again.':'Something went wrong. Please try again later.');
    }
}

// ── MFA ───────────────────────────────────────────────────────
async function verifyMFA() {
    const code        = document.getElementById('mfa-code')?.value.trim();
    const logId       = sessionStorage.getItem('mfa_logId');
    const remember    = sessionStorage.getItem('mfa_remember');
    const username    = sessionStorage.getItem('mfa_username');
    const fingerprint = sessionStorage.getItem('mfa_fingerprint');
    const redirect_back = sessionStorage.getItem('mfa_redirect_back');
    // [FIX-REDIRECT] อ่าน mfa_next_url สำหรับ same-origin redirect หลัง MFA
    const nextUrl     = sessionStorage.getItem('mfa_next_url');

    if (!code||!logId||!username) return updateStatus('danger','Session data missing. Please sign in again.');
    updateStatus('loading','Verifying your code…');
    try {
        const body = {action:'verify',logId,code,remember:remember==='true',username,fingerprint};
        if (redirect_back) body.redirect_back = redirect_back;

        const res = await secureFetch('/api/mfa',{method:'POST',body:JSON.stringify(body)});
        if (res.ok) {
            const data = await res.json();
            // ล้าง sessionStorage ทั้งหมด
            ['mfa_logId','mfa_username','mfa_remember','mfa_fingerprint',
             'mfa_redirect_back','mfa_next_url'].forEach(k=>sessionStorage.removeItem(k));
            updateStatus('success','Identity verified. Redirecting…');
            // [FIX-REDIRECT] ลำดับ priority: SSO redirect → same-origin next → welcome
            const dest = data.redirectUrl || nextUrl || '/welcome';
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
    updateStatus('danger',`🔒 Account temporarily locked. Please wait ${remaining} seconds.`); remaining--;
    clearInterval(countdownTimer);
    countdownTimer=setInterval(()=>{
        if (remaining<=0) { clearInterval(countdownTimer); if (btn) btn.disabled=false; updateStatus('success','Lockout period ended. You may try again.'); return; }
        updateStatus('danger',`🔒 Account temporarily locked. Please wait ${remaining} seconds.`); remaining--;
    },1000);
}

// ── Forgot / Reset Password ───────────────────────────────────
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
    updateStatus('loading','Saving your new password…');
    try {
        const res=await secureFetch('/api/password',{method:'POST',body:JSON.stringify({action:'reset',token,password:newPw})});
        const data=await res.json();
        if (res.ok) { updateStatus('success','Password updated. Redirecting to sign in…'); setTimeout(()=>window.location.href='/login',2000); }
        else updateStatus('danger',data.error||'An error occurred. Please try again.');
    } catch (err) { updateStatus('danger', err.name==='AbortError'?'Request timed out.':'Something went wrong.'); }
}

// ── Session Check ─────────────────────────────────────────────
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
    window.location.replace('/login');
}

// ── DOMContentLoaded ──────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    if (document.getElementById('user-display')) checkAuth();
    document.getElementById('logout-btn')     ?.addEventListener('click', e=>withGuard(logout,e));
    document.getElementById('dev-portal-btn') ?.addEventListener('click', ()=>{window.location.href='/developer';});
    if (document.getElementById('login-form')) {
        const qp=new URLSearchParams(window.location.search);
        if      (qp.get('verified')==='1')          updateStatus('success','✅ Email verified! You can now sign in.');
        else if (qp.get('error')==='token_expired') updateStatus('warning','⏰ Your verification link has expired. Please register again.');
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
