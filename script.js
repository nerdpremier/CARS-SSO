// ==========================================
// 🛡️ Secure System - Core Frontend Logic
// ==========================================

// ── Module-level state ────────────────────────────────────────────────────────

// ป้องกัน concurrent requests จาก double-click หรือ Enter กด ซ้ำ
let _submitting = false;

// Resend MFA cooldown state
let resendCooldown = 0;
let resendTimerInterval;

// Account lockdown countdown
let countdownTimer;

// ── Guard wrapper ─────────────────────────────────────────────────────────────

/**
 * ป้องกัน handler ถูกเรียกซ้อนกัน (double-click, Enter กดเร็ว)
 * และควบคุมสถานะ Loading ของปุ่มที่กด (เปลี่ยนเป็นสีขาว คงตัวหนังสือไว้)
 */
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

    if (btn) {
        btn.classList.add('btn--loading');
    }

    try {
        await fn();
    } finally {
        _submitting = false;
        if (btn) {
            btn.classList.remove('btn--loading');
        }
    }
}

// ─────────────────────────────────────────
// 🔐 CSRF Token Management
// ─────────────────────────────────────────

let _csrfToken = null;

/**
 * ดึง CSRF token จาก /api/csrf และ cache ไว้ใน module scope
 * throw ถ้า token ไม่ใช่ non-empty string — ป้องกัน X-CSRF-Token: "null" ถูกส่งออกไป
 */
async function getCsrfToken() {
    if (_csrfToken) return _csrfToken;
    const res = await fetch('/api/csrf', { credentials: 'include' });
    if (!res.ok) throw new Error('ไม่สามารถดึง CSRF token ได้');
    const data = await res.json();
    if (typeof data.token !== 'string' || !data.token) {
        throw new Error('CSRF token ที่ได้รับจาก server ไม่ถูกต้อง');
    }
    _csrfToken = data.token;
    return _csrfToken;
}

/**
 * สร้าง headers สำหรับทุก API request
 * รวม Content-Type และ X-CSRF-Token
 */
async function secureHeaders() {
    const token = await getCsrfToken();
    return {
        'Content-Type': 'application/json',
        'X-CSRF-Token': token
    };
}

/**
 * fetch wrapper พร้อม credentials + CSRF header + 15s timeout
 *
 * กรณี 403: CSRF token อาจหมดอายุ → invalidate cache → retry ครั้งเดียว
 * retry สร้าง AbortController ใหม่ (15s เต็ม) ไม่ใช้ signal เดิมที่อาจเกือบ timeout แล้ว
 */
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

// ─────────────────────────────────────────
// 📢 UI Helpers
// ─────────────────────────────────────────

/**
 * แสดง status message ใน #status-box
 * ใช้ textContent (ไม่ใช่ innerHTML) ป้องกัน XSS
 * type: 'danger' | 'success' | 'loading'
 */
function updateStatus(type, msg) {
    const box = document.getElementById('status-box');
    if (!box) return;
    box.className = 'status-box';
    box.style.display = 'block';
    if (type === 'danger')       box.classList.add('danger');
    else if (type === 'success') box.classList.add('success');
    else                         box.classList.add('loading');
    box.textContent = msg;
}

// ─────────────────────────────────────────
// 🔍 Device Fingerprint
// ─────────────────────────────────────────

/**
 * คืน device fingerprint สำหรับ risk assessment
 *
 * ลำดับ fallback:
 * 1. UUID ที่เก็บใน localStorage (persistent across sessions)
 * 2. btoa(encodeURIComponent(hardware info)) — ถ้า localStorage ถูก block
 * encodeURIComponent ก่อน btoa เพราะ btoa รองรับเฉพาะ Latin-1
 * บาง locale ใน navigator.language มี non-Latin-1 chars → btoa throw โดยไม่มี encode
 * 3. random UUID per session — ถ้าทุกอย่างล้มเหลว (risk level จะเป็น MEDIUM เสมอ)
 */
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

// ─────────────────────────────────────────
// ✅ Validation
// ─────────────────────────────────────────

// Regex ตรวจรูปแบบ email เบื้องต้น: local@domain.tld
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * ตรวจรูปแบบ email — คืน error message หรือ null ถ้าผ่าน
 */
function validateEmail(email) {
    if (!email || !EMAIL_REGEX.test(email)) {
        return 'รูปแบบอีเมลไม่ถูกต้อง';
    }
    return null;
}

/**
 * ตรวจรหัสผ่านตาม policy — คืน error message หรือ null ถ้าผ่าน
 * ต้องมีอย่างน้อย 8 ตัว, ตัวใหญ่, ตัวเล็ก, ตัวเลข, สัญลักษณ์
 */
function validatePassword(password) {
    const passRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (password && !passRegex.test(password)) {
        return 'รหัสผ่านต้องมี 8 ตัวอักษรขึ้นไป (ต้องมีตัวใหญ่, ตัวเล็ก, ตัวเลข และสัญลักษณ์)';
    }
    return null;
}

/**
 * ตรวจ username และ password สำหรับ login/register
 * ตรวจ length ก่อน regex เพื่อหยุดเร็วและไม่ส่ง API call ที่ invalid แน่ๆ
 *
 * username maxlength = 32 ตรงกับ server validation ใน auth.js / verify-mfa.js
 * password maxlength = 128 ตรงกับ HTML attribute maxlength="128"
 * [BUG-011 FIX] เดิม maxlength = 30 ไม่ตรงกับ server ที่ allow 32
 * → user ที่มี username 31-32 ตัวอักษร register ผ่าน API โดยตรงได้ แต่ login via UI ไม่ได้
 */
function validateInputs(username, password) {
    const userRegex = /^[a-zA-Z0-9]+$/;
    if (username && username.length > 32) {
        return 'ชื่อผู้ใช้งานต้องไม่เกิน 32 ตัวอักษร';
    }
    if (password && password.length > 128) {
        return 'รหัสผ่านต้องไม่เกิน 128 ตัวอักษร';
    }
    if (username && !userRegex.test(username)) {
        return 'ชื่อผู้ใช้งานต้องเป็นตัวอักษรภาษาอังกฤษและตัวเลขเท่านั้น';
    }
    return validatePassword(password);
}

// ─────────────────────────────────────────
// 🔒 Password Strength Checker
// ─────────────────────────────────────────

// ข้อมูล rule แต่ละข้อ: id, test function, และ label ภาษาไทยสำหรับ aria-label
const PASSWORD_RULES = [
    { id: 'rule-length',  test: p => p.length >= 8,       label: 'อย่างน้อย 8 ตัวอักษร' },
    { id: 'rule-upper',   test: p => /[A-Z]/.test(p),     label: 'ตัวพิมพ์ใหญ่ (A-Z)' },
    { id: 'rule-lower',   test: p => /[a-z]/.test(p),     label: 'ตัวพิมพ์เล็ก (a-z)' },
    { id: 'rule-number',  test: p => /\d/.test(p),        label: 'ตัวเลข (0-9)' },
    { id: 'rule-special', test: p => /[@$!%*?&]/.test(p), label: 'สัญลักษณ์ (@$!%*?&)' },
];

/**
 * อัปเดต visual state และ aria-label ของทุก password rule
 * เรียกทุกครั้งที่ password input เปลี่ยน
 *
 * aria-label format:
 * ผ่าน  → "ผ่าน: อย่างน้อย 8 ตัวอักษร"
 * ไม่ผ่าน → "ไม่ผ่าน: อย่างน้อย 8 ตัวอักษร"
 * ให้ screen reader อ่าน state ได้โดยไม่ต้องอ่านจาก icon ✓/✗
 */
function checkPasswordStrength(password) {
    PASSWORD_RULES.forEach(({ id, test, label }) => {
        const el   = document.getElementById(id);
        if (!el) return;
        const icon = el.querySelector('.rule-icon');
        const pass = test(password);
        el.classList.toggle('pass', pass);
        el.setAttribute('aria-label', `${pass ? 'ผ่าน' : 'ไม่ผ่าน'}: ${label}`);
        if (icon) icon.textContent = pass ? '✓' : '✗';
    });
}

// ─────────────────────────────────────────
// 📝 Register
// ─────────────────────────────────────────

/**
 * ส่งคำขอสมัครสมาชิก
 * ตรวจ username, email format, และ password policy ก่อนส่ง API
 */
async function handleRegister() {
    const username = document.getElementById('username')?.value.trim();
    const email    = document.getElementById('email')?.value.trim();
    const password = document.getElementById('password')?.value;

    if (!username || !email || !password) {
        return updateStatus('danger', 'กรุณาระบุข้อมูลให้ครบถ้วน');
    }

    const inputError = validateInputs(username, password);
    if (inputError) return updateStatus('danger', inputError);

    const emailError = validateEmail(email);
    if (emailError) return updateStatus('danger', emailError);

    updateStatus('loading', 'กำลังสร้างบัญชีผู้ใช้งาน...');
    try {
        const res  = await secureFetch('/api/auth', {
            method: 'POST',
            body: JSON.stringify({ action: 'register', username, email, password })
        });
        const data = await res.json();
        if (res.ok) {
            if (data.email_verification) {
                // แสดงข้อความให้ตรวจสอบ email แทนที่จะ redirect ทันที
                updateStatus('success', '✅ สมัครสมาชิกสำเร็จ! กรุณาตรวจสอบอีเมลของคุณเพื่อยืนยันบัญชีก่อนเข้าสู่ระบบ');
                // ซ่อนฟอร์มและแสดงเฉพาะ message
                const form = document.getElementById('register-form') || document.querySelector('form');
                if (form) form.style.display = 'none';
            } else {
                updateStatus('success', 'สมัครสมาชิกสำเร็จ! ระบบกำลังนำท่านไปหน้าเข้าสู่ระบบ...');
                setTimeout(() => window.location.href = '/login', 1500);
            }
        } else {
            updateStatus('danger', data.error);
        }
    } catch (err) {
        updateStatus('danger', err.name === 'AbortError'
            ? 'หมดเวลาการเชื่อมต่อ กรุณาลองใหม่อีกครั้ง'
            : 'ระบบขัดข้อง กรุณาลองใหม่ภายหลัง');
    }
}

// ─────────────────────────────────────────
// 🔐 Login (Adaptive Authentication)
// ─────────────────────────────────────────

/**
 * ขั้นตอน login แบบ adaptive:
 * 1. POST /api/assess → ประเมิน risk level
 * 2. ถ้า HIGH → lockdown UI 60 วินาที
 * 3. ถ้าไม่ HIGH → POST /api/auth → login จริง
 * 4. ถ้า server ต้องการ MFA → เก็บ logId + username → redirect /mfa
 */
async function preLoginCheck() {
    const username = document.getElementById('username')?.value.trim();
    const password = document.getElementById('password')?.value;
    const remember = document.getElementById('remember-device')?.checked;

    // ดึงค่า redirect_back จาก URL
    const urlParams = new URLSearchParams(window.location.search);
    const redirect_back = urlParams.get('next') || urlParams.get('redirect_back');

    if (!username || !password) {
        return updateStatus('danger', 'กรุณาระบุชื่อผู้ใช้งานและรหัสผ่าน');
    }

    updateStatus('loading', 'กำลังตรวจสอบสิทธิ์การเข้าใช้งาน...');
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
            return updateStatus('danger', 'ระบบขัดข้อง กรุณาลองใหม่ภายหลัง');
        }

        if (!riskData.logId) {
            return updateStatus('danger', 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง');
        }

        const logIdNum = Number(riskData.logId);
        if (!Number.isInteger(logIdNum) || logIdNum <= 0) {
            return updateStatus('danger', 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง');
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
                    ? 'ตรวจพบอุปกรณ์ใหม่ หากไม่ได้รับอีเมลภายใน 1 นาที กรุณากด "ส่งรหัสอีกครั้ง"'
                    : 'กรุณายืนยันรหัส MFA ที่ส่งไปยังอีเมล';
                updateStatus('success', mfaMessage);
                
                sessionStorage.setItem('mfa_logId',       safeLogId);
                sessionStorage.setItem('mfa_username',    username);
                sessionStorage.setItem('mfa_remember',    String(remember));
                sessionStorage.setItem('mfa_fingerprint', fingerprint);
                
                // ฝากพิกัดกลับบ้านไว้ใน Session สำหรับไปหน้า MFA
                if (redirect_back) {
                    sessionStorage.setItem('mfa_redirect_back', redirect_back);
                }

                setTimeout(() => window.location.href = '/mfa', 1500);
            } else {
                updateStatus('success', 'เข้าสู่ระบบสำเร็จ กำลังส่งกลับไปยังแอปพลิเคชัน...');
                setTimeout(() => window.location.href = authData.redirectUrl || '/welcome', 1000);
            }
        } else {
            if (authData.email_not_verified) {
                // แสดงข้อความพิเศษพร้อมลิงก์แจ้งให้ตรวจ email
                updateStatus('warning', '📧 กรุณายืนยันอีเมลของคุณก่อนเข้าสู่ระบบ (ตรวจสอบในกล่องจดหมาย หรือโฟลเดอร์ spam)');
            } else {
                updateStatus('danger', authData.error);
            }
        }
    } catch (err) {
        updateStatus('danger', err.name === 'AbortError'
            ? 'หมดเวลาการเชื่อมต่อ กรุณาลองใหม่อีกครั้ง'
            : 'ระบบขัดข้อง กรุณาลองใหม่ภายหลัง');
    }
}

// ─────────────────────────────────────────
// 🛡️ MFA Verify
// ─────────────────────────────────────────

/**
 * ส่งรหัส OTP ไปยัง /api/verify-mfa
 * ดึง logId + username + remember จาก sessionStorage
 * ล้าง sessionStorage ทุก key เมื่อ verify สำเร็จ
 */
async function verifyMFA() {
    const code        = document.getElementById('mfa-code')?.value.trim();
    const logId       = sessionStorage.getItem('mfa_logId');
    const remember    = sessionStorage.getItem('mfa_remember');
    const username    = sessionStorage.getItem('mfa_username');
    const fingerprint = sessionStorage.getItem('mfa_fingerprint');
    const redirect_back = sessionStorage.getItem('mfa_redirect_back');

    if (!code || !logId || !username) {
        return updateStatus('danger', 'ข้อมูลไม่ถูกต้อง กรุณาเข้าสู่ระบบใหม่');
    }

    updateStatus('loading', 'กำลังยืนยันรหัสตัวตน...');
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
            
            updateStatus('success', 'ยืนยันตัวตนสำเร็จ กำลังส่งกลับไปยังแอปพลิเคชัน...');
            setTimeout(() => window.location.href = data.redirectUrl || '/welcome', 1000);
        } else {
            const data = await res.json();
            updateStatus('danger', data.error);
        }
    } catch (err) {
        updateStatus('danger', err.name === 'AbortError'
            ? 'หมดเวลาการเชื่อมต่อ กรุณาลองใหม่อีกครั้ง'
            : 'ระบบขัดข้อง');
    }
}

// ─────────────────────────────────────────
// 📨 Resend MFA
// ─────────────────────────────────────────

async function resendMFA() {
    if (resendCooldown > 0) return;

    const logId    = sessionStorage.getItem('mfa_logId');
    const username = sessionStorage.getItem('mfa_username');

    updateStatus('loading', 'กำลังจัดส่งรหัสใหม่...');
    try {
        const res  = await secureFetch('/api/mfa', {
            method: 'POST',
            body: JSON.stringify({ action: 'resend', logId, username })
        });
        const data = await res.json();
        if (res.ok) {
            startResendCooldown(60); 
            updateStatus('success', data.message);
        } else {
            updateStatus('danger', data.error);
        }
    } catch (err) {
        updateStatus('danger', err.name === 'AbortError'
            ? 'หมดเวลาการเชื่อมต่อ กรุณาลองใหม่'
            : 'ระบบขัดข้อง');
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
            resendBtn.textContent = 'ส่งรหัสอีกครั้ง';
            return;
        }
        resendBtn.textContent = `ส่งรหัสอีกครั้ง (${resendCooldown}s)`;
        resendCooldown--;
    }, 1000);
}

// ─────────────────────────────────────────
// 🚨 Account Lockdown
// ─────────────────────────────────────────

function startAccountLockdown(seconds) {
    const btn     = document.getElementById('login-btn');
    let remaining = seconds;

    if (btn) btn.disabled = true;

    clearInterval(countdownTimer);
    countdownTimer = setInterval(() => {
        if (remaining <= 0) {
            clearInterval(countdownTimer);
            if (btn) btn.disabled = false;
            updateStatus('success', 'สิ้นสุดระยะเวลาระงับ ท่านสามารถลองใหม่ได้');
            return;
        }
        updateStatus('danger', `🚨 บัญชีถูกระงับชั่วคราว: กรุณารอ ${remaining} วินาที`);
        remaining--;
    }, 1000);
}

// ─────────────────────────────────────────
// 🔑 Forgot Password
// ─────────────────────────────────────────

async function requestPasswordReset() {
    const email = document.getElementById('reset-email')?.value.trim();
    if (!email) return updateStatus('danger', 'กรุณาระบุอีเมล');

    const emailError = validateEmail(email);
    if (emailError) return updateStatus('danger', emailError);

    updateStatus('loading', 'กำลังส่งคำขอตั้งรหัสผ่านใหม่...');
    try {
        const res  = await secureFetch('/api/password', {
            method: 'POST',
            body: JSON.stringify({ action: 'forgot', email })
        });
        const data = await res.json();
        if (res.ok) {
            updateStatus('success', data.message);
        } else {
            updateStatus('danger', data.error || 'เกิดข้อผิดพลาด กรุณาลองใหม่');
        }
    } catch (err) {
        updateStatus('danger', err.name === 'AbortError'
            ? 'หมดเวลาการเชื่อมต่อ กรุณาลองใหม่'
            : 'ระบบขัดข้อง');
    }
}

// ─────────────────────────────────────────
// 🔐 Reset Password
// ─────────────────────────────────────────

async function executePasswordReset() {
    const newPassword     = document.getElementById('new-password')?.value;
    const confirmPassword = document.getElementById('confirm-password')?.value;

    if (!newPassword || !confirmPassword) {
        return updateStatus('danger', 'กรุณาระบุรหัสผ่านให้ครบถ้วน');
    }
    if (newPassword !== confirmPassword) {
        return updateStatus('danger', 'รหัสผ่านทั้งสองช่องไม่ตรงกัน');
    }

    const error = validatePassword(newPassword);
    if (error) return updateStatus('danger', error);

    const token = new URLSearchParams(window.location.search).get('token');
    if (!token) {
        return updateStatus('danger', 'ลิงก์ไม่ถูกต้อง กรุณาขอลิงก์ใหม่อีกครั้ง');
    }

    updateStatus('loading', 'กำลังบันทึกรหัสผ่านใหม่...');
    try {
        const res  = await secureFetch('/api/password', {
            method: 'POST',
            body: JSON.stringify({ action: 'reset', token, password: newPassword })
        });
        const data = await res.json();
        if (res.ok) {
            updateStatus('success', data.message + ' กำลังนำท่านไปหน้าเข้าสู่ระบบ...');
            setTimeout(() => window.location.href = '/login', 2000);
        } else {
            updateStatus('danger', data.error);
        }
    } catch (err) {
        updateStatus('danger', err.name === 'AbortError'
            ? 'หมดเวลาการเชื่อมต่อ กรุณาลองใหม่'
            : 'ระบบขัดข้อง');
    }
}

// ─────────────────────────────────────────
// 🏠 Session Check (welcome.html)
// ─────────────────────────────────────────

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
    } catch { /* ignore — redirect ต่อเสมอ */ }
    window.location.replace('/login');
}

// ─────────────────────────────────────────
// ⌨️ Auto-run on page load
// ─────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {

    if (document.getElementById('user-display')) {
        checkAuth();
    }
    document.getElementById('logout-btn')
        ?.addEventListener('click', e => withGuard(logout, e));

    document.getElementById('dev-portal-btn')
        ?.addEventListener('click', () => { window.location.href = '/developer'; });

    // ── แสดง message จาก query param บน login page ─────────
    if (document.getElementById('login-form')) {
        const qp = new URLSearchParams(window.location.search);
        if (qp.get('verified') === '1') {
            updateStatus('success', '✅ ยืนยันอีเมลสำเร็จ! ท่านสามารถเข้าสู่ระบบได้แล้ว');
        } else if (qp.get('error') === 'token_expired') {
            updateStatus('warning', '⏰ ลิงก์ยืนยันอีเมลหมดอายุแล้ว กรุณาสมัครใหม่');
        } else if (qp.get('error') === 'invalid_token') {
            updateStatus('danger', 'ลิงก์ยืนยันอีเมลไม่ถูกต้อง กรุณาตรวจสอบ email อีกครั้ง');
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