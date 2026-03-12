// ==========================================
// 🛡️ CARS SSO — Core Frontend Logic
// ==========================================

// ── Module-level state ──────────────────────────────────────
let _submitting = false;
let resendCooldown = 0;
let resendTimerInterval;
let countdownTimer;

// ── Guard wrapper ───────────────────────────────────────────
async function withGuard(fn, event) {
    if (_submitting) return;
    _submitting = true;

    let btn = null;
    if (event && event.target) {
        if (event.target.tagName === 'FORM') {
            btn = event.target.querySelector('button[type="submit"], .btn-primary');
        } else if (event.target.tagName === 'BUTTON') {
            btn = event.target;
        }
    }
    if (btn) btn.classList.add('btn--loading');

    try {
        await fn();
    } finally {
        _submitting = false;
        if (btn) btn.classList.remove('btn--loading');
    }
}

// ── CSRF Token Management ────────────────────────────────────
let _csrfToken = null;

async function getCsrfToken() {
    if (_csrfToken) return _csrfToken;
    const res = await fetch('/api/csrf', { credentials: 'include' });
    if (!res.ok) throw new Error('Unable to fetch CSRF token');
    const data = await res.json();
    if (typeof data.token !== 'string' || !data.token) {
        throw new Error('Invalid CSRF token received from server');
    }
    _csrfToken = data.token;
    return _csrfToken;
}

async function secureHeaders() {
    const token = await getCsrfToken();
    return {
        'Content-Type': 'application/json',
        'X-CSRF-Token': token
    };
}

async function secureFetch(url, options = {}, timeoutMs = 15000) {
    const controller = new AbortController();
    const timeoutId  = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const headers = await secureHeaders();
        const res = await fetch(url, {
            ...options,
            credentials: 'include',
            headers: { ...headers, ...(options.headers || {}) },
            signal: controller.signal
        });
        if (res.status === 403) {
            _csrfToken = null;
            const retryController = new AbortController();
            const retryTimeoutId  = setTimeout(() => retryController.abort(), timeoutMs);
            try {
                const retryHeaders = await secureHeaders();
                return await fetch(url, {
                    ...options,
                    credentials: 'include',
                    headers: { ...retryHeaders, ...(options.headers || {}) },
                    signal: retryController.signal
                });
            } finally {
                clearTimeout(retryTimeoutId);
            }
        }
        return res;
    } finally {
        clearTimeout(timeoutId);
    }
}

// ── UI Helpers ───────────────────────────────────────────────
function updateStatus(type, msg) {
    const box = document.getElementById('status-box');
    if (!box) return;
    box.className = 'status-box';
    box.style.display = 'block';
    if (type === 'danger')       box.classList.add('danger');
    else if (type === 'success') box.classList.add('success');
    else if (type === 'warning') box.classList.add('warning');
    else                         box.classList.add('loading');
    box.textContent = msg;
}

// ── Device Fingerprint ───────────────────────────────────────
function getSecureFp() {
    try {
        let storedId = localStorage.getItem('_device_fp');
        if (!storedId) {
            storedId = crypto.randomUUID();
            localStorage.setItem('_device_fp', storedId);
        }
        return storedId;
    } catch {
        try {
            const hardware = [
                screen.width + 'x' + screen.height,
                navigator.hardwareConcurrency || 0,
                navigator.language || ''
            ].join('|');
            return btoa(encodeURIComponent(hardware)).substring(0, 128);
        } catch {
            return crypto.randomUUID();
        }
    }
}

// ── Validation ───────────────────────────────────────────────
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateEmail(email) {
    if (!email || !EMAIL_REGEX.test(email)) {
        return 'Please enter a valid email address.';
    }
    return null;
}

function validatePassword(password) {
    const passRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (password && !passRegex.test(password)) {
        return 'Password must be at least 8 characters with uppercase, lowercase, a number, and a symbol.';
    }
    return null;
}

function validateInputs(username, password) {
    const userRegex = /^[a-zA-Z0-9]+$/;
    if (username && username.length > 32) {
        return 'Username must be 32 characters or fewer.';
    }
    if (password && password.length > 128) {
        return 'Password must be 128 characters or fewer.';
    }
    if (username && !userRegex.test(username)) {
        return 'Username may only contain letters and numbers.';
    }
    return validatePassword(password);
}

// ── Password Strength ────────────────────────────────────────
const PASSWORD_RULES = [
    { id: 'rule-length',  test: p => p.length >= 8,       label: 'At least 8 characters' },
    { id: 'rule-upper',   test: p => /[A-Z]/.test(p),     label: 'Uppercase letter (A–Z)' },
    { id: 'rule-lower',   test: p => /[a-z]/.test(p),     label: 'Lowercase letter (a–z)' },
    { id: 'rule-number',  test: p => /\d/.test(p),        label: 'Number (0–9)' },
    { id: 'rule-special', test: p => /[@$!%*?&]/.test(p), label: 'Symbol (@$!%*?&)' },
];

function checkPasswordStrength(password) {
    PASSWORD_RULES.forEach(({ id, test, label }) => {
        const el   = document.getElementById(id);
        if (!el) return;
        const icon = el.querySelector('.rule-icon');
        const pass = test(password);
        el.classList.toggle('pass', pass);
        el.setAttribute('aria-label', `${pass ? 'Met' : 'Not met'}: ${label}`);
        if (icon) icon.textContent = pass ? '✓' : '✗';
    });
}

// ── Register ─────────────────────────────────────────────────
async function handleRegister() {
    const username = document.getElementById('username')?.value.trim();
    const email    = document.getElementById('email')?.value.trim();
    const password = document.getElementById('password')?.value;

    if (!username || !email || !password) {
        return updateStatus('danger', 'Please fill in all fields.');
    }
    const inputError = validateInputs(username, password);
    if (inputError) return updateStatus('danger', inputError);

    const emailError = validateEmail(email);
    if (emailError) return updateStatus('danger', emailError);

    updateStatus('loading', 'Creating your account…');
    try {
        const res  = await secureFetch('/api/auth', {
            method: 'POST',
            body: JSON.stringify({ action: 'register', username, email, password })
        });
        const data = await res.json();
        if (res.ok) {
            if (data.email_verification) {
                updateStatus('success', '✅ Account created! Please check your email to verify your address before signing in.');
                const form = document.getElementById('register-form') || document.querySelector('form');
                if (form) form.style.display = 'none';
            } else {
                updateStatus('success', 'Account created! Redirecting to sign in…');
                setTimeout(() => window.location.href = '/login', 1500);
            }
        } else {
            updateStatus('danger', data.error);
        }
    } catch (err) {
        updateStatus('danger', err.name === 'AbortError'
            ? 'Request timed out. Please try again.'
            : 'Something went wrong. Please try again later.');
    }
}

// ── Login ─────────────────────────────────────────────────────
async function preLoginCheck() {
    const username = document.getElementById('username')?.value.trim();
    const password = document.getElementById('password')?.value;
    const remember = document.getElementById('remember-device')?.checked;

    const urlParams = new URLSearchParams(window.location.search);
    const redirect_back = urlParams.get('next') || urlParams.get('redirect_back');

    if (!username || !password) {
        return updateStatus('danger', 'Please enter your username and password.');
    }

    updateStatus('loading', 'Verifying your credentials…');
    try {
        const fingerprint = getSecureFp();
        const device = `Screen:${screen.width}x${screen.height} | CPU:${navigator.hardwareConcurrency}`;

        const riskRes  = await secureFetch('/api/assess', {
            method: 'POST',
            body: JSON.stringify({ username, device, fingerprint })
        });
        const riskData = await riskRes.json();

        if (riskData.risk_level === 'HIGH') {
            startAccountLockdown(60);
            return;
        }
        if (!riskRes.ok) {
            return updateStatus('danger', 'Something went wrong. Please try again later.');
        }
        if (!riskData.logId) {
            return updateStatus('danger', 'Incorrect username or password.');
        }

        const logIdNum = Number(riskData.logId);
        if (!Number.isInteger(logIdNum) || logIdNum <= 0) {
            return updateStatus('danger', 'Incorrect username or password.');
        }
        const safeLogId = String(logIdNum);

        const authRes  = await secureFetch('/api/auth', {
            method: 'POST',
            body: JSON.stringify({
                action: 'login', username, password, fingerprint,
                logId: safeLogId, remember, redirect_back
            })
        });
        const authData = await authRes.json();

        if (authRes.ok) {
            if (authData.mfa_required) {
                const mfaMessage = authData.email_pending
                    ? 'New device detected. If you don\'t receive the email within 1 minute, click "Resend Code".'
                    : 'Please enter the verification code sent to your email.';
                updateStatus('success', mfaMessage);

                sessionStorage.setItem('mfa_logId',       safeLogId);
                sessionStorage.setItem('mfa_username',    username);
                sessionStorage.setItem('mfa_remember',    String(remember));
                sessionStorage.setItem('mfa_fingerprint', fingerprint);

                if (redirect_back) {
                    sessionStorage.setItem('mfa_redirect_back', redirect_back);
                }
                setTimeout(() => window.location.href = '/mfa', 1500);
            } else {
                updateStatus('success', 'Signed in successfully. Redirecting…');
                setTimeout(() => window.location.href = authData.redirectUrl || '/welcome', 1000);
            }
        } else {
            if (authData.email_not_verified) {
                updateStatus('warning', '📧 Please verify your email before signing in. Check your inbox (or spam folder).');
            } else {
                updateStatus('danger', authData.error);
            }
        }
    } catch (err) {
        updateStatus('danger', err.name === 'AbortError'
            ? 'Request timed out. Please try again.'
            : 'Something went wrong. Please try again later.');
    }
}

// ── MFA Verify ───────────────────────────────────────────────
async function verifyMFA() {
    const code        = document.getElementById('mfa-code')?.value.trim();
    const logId       = sessionStorage.getItem('mfa_logId');
    const remember    = sessionStorage.getItem('mfa_remember');
    const username    = sessionStorage.getItem('mfa_username');
    const fingerprint = sessionStorage.getItem('mfa_fingerprint');
    const redirect_back = sessionStorage.getItem('mfa_redirect_back');

    if (!code || !logId || !username) {
        return updateStatus('danger', 'Session data missing. Please sign in again.');
    }

    updateStatus('loading', 'Verifying your code…');
    try {
        const res = await secureFetch('/api/mfa', {
            method: 'POST',
            body: JSON.stringify({ action: 'verify', logId, code, remember: remember === 'true', username, fingerprint, redirect_back })
        });

        if (res.ok) {
            const data = await res.json();
            sessionStorage.removeItem('mfa_logId');
            sessionStorage.removeItem('mfa_username');
            sessionStorage.removeItem('mfa_remember');
            sessionStorage.removeItem('mfa_fingerprint');
            sessionStorage.removeItem('mfa_redirect_back');
            updateStatus('success', 'Identity verified. Redirecting…');
            setTimeout(() => window.location.href = data.redirectUrl || '/welcome', 1000);
        } else {
            const data = await res.json();
            updateStatus('danger', data.error);
        }
    } catch (err) {
        updateStatus('danger', err.name === 'AbortError'
            ? 'Request timed out. Please try again.'
            : 'Something went wrong.');
    }
}

// ── Resend MFA ───────────────────────────────────────────────
async function resendMFA() {
    if (resendCooldown > 0) return;

    const logId    = sessionStorage.getItem('mfa_logId');
    const username = sessionStorage.getItem('mfa_username');

    updateStatus('loading', 'Sending a new code…');
    try {
        const res  = await secureFetch('/api/mfa', {
            method: 'POST',
            body: JSON.stringify({ action: 'resend', logId, username })
        });
        const data = await res.json();
        if (res.ok) {
            startResendCooldown(60);
            updateStatus('success', 'A new code has been sent. Please check your email.');
        } else {
            updateStatus('danger', data.error);
        }
    } catch (err) {
        updateStatus('danger', err.name === 'AbortError'
            ? 'Request timed out. Please try again.'
            : 'Something went wrong.');
    }
}

function startResendCooldown(seconds) {
    const resendBtn = document.getElementById('resend-btn');
    if (!resendBtn) return;

    resendCooldown = seconds;
    resendBtn.disabled = true;

    clearInterval(resendTimerInterval);
    resendTimerInterval = setInterval(() => {
        if (resendCooldown <= 0) {
            clearInterval(resendTimerInterval);
            resendBtn.disabled = false;
            resendBtn.textContent = 'Resend Code';
            return;
        }
        resendBtn.textContent = `Resend Code (${resendCooldown}s)`;
        resendCooldown--;
    }, 1000);
}

// ── Account Lockdown ─────────────────────────────────────────
function startAccountLockdown(seconds) {
    const btn     = document.getElementById('login-btn');
    let remaining = seconds;

    if (btn) btn.disabled = true;

    clearInterval(countdownTimer);
    countdownTimer = setInterval(() => {
        if (remaining <= 0) {
            clearInterval(countdownTimer);
            if (btn) btn.disabled = false;
            updateStatus('success', 'Lockout period ended. You may try again.');
            return;
        }
        updateStatus('danger', `🚨 Account temporarily locked. Please wait ${remaining} seconds.`);
        remaining--;
    }, 1000);
}

// ── Forgot Password ───────────────────────────────────────────
async function requestPasswordReset() {
    const email = document.getElementById('reset-email')?.value.trim();
    if (!email) return updateStatus('danger', 'Please enter your email address.');

    const emailError = validateEmail(email);
    if (emailError) return updateStatus('danger', emailError);

    updateStatus('loading', 'Sending reset link…');
    try {
        const res  = await secureFetch('/api/password', {
            method: 'POST',
            body: JSON.stringify({ action: 'forgot', email })
        });
        const data = await res.json();
        if (res.ok) {
            updateStatus('success', data.message);
        } else {
            updateStatus('danger', data.error || 'An error occurred. Please try again.');
        }
    } catch (err) {
        updateStatus('danger', err.name === 'AbortError'
            ? 'Request timed out. Please try again.'
            : 'Something went wrong.');
    }
}

// ── Reset Password ────────────────────────────────────────────
async function executePasswordReset() {
    const newPassword     = document.getElementById('new-password')?.value;
    const confirmPassword = document.getElementById('confirm-password')?.value;

    if (!newPassword || !confirmPassword) {
        return updateStatus('danger', 'Please fill in both password fields.');
    }
    if (newPassword !== confirmPassword) {
        return updateStatus('danger', 'Passwords do not match.');
    }
    const error = validatePassword(newPassword);
    if (error) return updateStatus('danger', error);

    const token = new URLSearchParams(window.location.search).get('token');
    if (!token) {
        return updateStatus('danger', 'Invalid link. Please request a new reset link.');
    }

    updateStatus('loading', 'Saving your new password…');
    try {
        const res  = await secureFetch('/api/password', {
            method: 'POST',
            body: JSON.stringify({ action: 'reset', token, password: newPassword })
        });
        const data = await res.json();
        if (res.ok) {
            updateStatus('success', 'Password updated. Redirecting to sign in…');
            setTimeout(() => window.location.href = '/login', 2000);
        } else {
            updateStatus('danger', data.error);
        }
    } catch (err) {
        updateStatus('danger', err.name === 'AbortError'
            ? 'Request timed out. Please try again.'
            : 'Something went wrong.');
    }
}

// ── Session Check (welcome.html) ──────────────────────────────
async function checkAuth() {
    try {
        const controller = new AbortController();
        const timeoutId  = setTimeout(() => controller.abort(), 15000);
        let res;
        try {
            res = await fetch('/api/session', { credentials: 'include', signal: controller.signal });
        } finally {
            clearTimeout(timeoutId);
        }
        if (!res.ok) { window.location.replace('/login'); return; }

        const data = await res.json();
        if (!data.authenticated) { window.location.replace('/login'); return; }

        const userDisplay = document.getElementById('user-display');
        if (userDisplay && typeof data.user === 'string' && data.user) {
            userDisplay.textContent = data.user;
        }
        document.body.classList.remove('auth-pending');
    } catch {
        window.location.replace('/login');
    }
}

async function logout() {
    try {
        await secureFetch('/api/logout', { method: 'POST' });
    } catch { /* ignore */ }
    window.location.replace('/login');
}

// ── DOMContentLoaded ──────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {

    if (document.getElementById('user-display')) {
        checkAuth();
    }

    document.getElementById('logout-btn')
        ?.addEventListener('click', e => withGuard(logout, e));

    document.getElementById('dev-portal-btn')
        ?.addEventListener('click', () => { window.location.href = '/developer'; });

    // Login page — show messages from query params
    if (document.getElementById('login-form')) {
        const qp = new URLSearchParams(window.location.search);
        if (qp.get('verified') === '1') {
            updateStatus('success', '✅ Email verified! You can now sign in.');
        } else if (qp.get('error') === 'token_expired') {
            updateStatus('warning', '⏰ Your verification link has expired. Please register again.');
        } else if (qp.get('error') === 'invalid_token') {
            updateStatus('danger', 'Invalid verification link. Please check your email again.');
        }
    }

    document.getElementById('login-form')
        ?.addEventListener('submit', e => { e.preventDefault(); withGuard(preLoginCheck, e); });

    document.getElementById('register-form')
        ?.addEventListener('submit', e => { e.preventDefault(); withGuard(handleRegister, e); });

    document.getElementById('password')
        ?.addEventListener('input', e => checkPasswordStrength(e.target.value));

    if (document.getElementById('mfa-code')) {
        if (!sessionStorage.getItem('mfa_logId') || !sessionStorage.getItem('mfa_username')) {
            window.location.replace('/login');
            return;
        }
    }

    document.getElementById('mfa-form')
        ?.addEventListener('submit', e => { e.preventDefault(); withGuard(verifyMFA, e); });

    document.getElementById('resend-btn')
        ?.addEventListener('click', e => withGuard(resendMFA, e));

    document.getElementById('forgot-form')
        ?.addEventListener('submit', e => { e.preventDefault(); withGuard(requestPasswordReset, e); });

    document.getElementById('reset-form')
        ?.addEventListener('submit', e => { e.preventDefault(); withGuard(executePasswordReset, e); });

    document.getElementById('new-password')
        ?.addEventListener('input', e => checkPasswordStrength(e.target.value));
});
