// ============================================================
// 📡 cars-sso-risk-sdk.js — Client Risk Reporting SDK
//
// ฝังใน client web app ที่ใช้ CARS-SSO
// เริ่ม collect behavior และส่งไป SSO ทุก 15 วินาที
//
// การใช้งาน:
//   import { startRiskMonitor, stopRiskMonitor } from './cars-sso-risk-sdk.js';
//
//   // เรียกหลัง login สำเร็จ
//   startRiskMonitor({
//     ssoUrl:    'https://your-sso.vercel.app',  // URL ของ CARS-SSO
//     onWarn:    () => showBanner('กรุณาตรวจสอบกิจกรรมในบัญชีของคุณ'),
//     onStepUp:  () => window.location.href = 'https://your-sso.vercel.app/mfa',
//     onRevoke:  () => { clearSession(); window.location.href = '/login'; },
//   });
//
//   // เรียกตอน logout หรือ unmount
//   stopRiskMonitor();
// ============================================================

let _monitorInterval = null;
let _behaviorState   = null;
let _csrfCache       = null;

// ── Behavior Collector ────────────────────────────────────────
function initCollector() {
    const state = {
        mouseIntervals: [], clickIntervals: [],
        keyIntervals:   [], idleDurations:  [],
        lastMouse: null, lastClick: null, lastKey: null,
        lastActivity: Date.now(),
        startTime: Date.now(),
    };

    const onMouseMove = () => {
        const now = Date.now();
        if (state.lastMouse) state.mouseIntervals.push(now - state.lastMouse);
        state.lastMouse = now; state.lastActivity = now;
    };
    const onMouseDown = () => {
        const now = Date.now();
        if (state.lastClick) state.clickIntervals.push(now - state.lastClick);
        state.lastClick = now; state.lastActivity = now;
    };
    const onKeyDown = () => {
        const now = Date.now();
        if (state.lastKey) state.keyIntervals.push(now - state.lastKey);
        state.lastKey = now; state.lastActivity = now;
    };

    document.addEventListener('mousemove', onMouseMove, { passive: true });
    document.addEventListener('mousedown', onMouseDown, { passive: true });
    document.addEventListener('keydown',   onKeyDown,   { passive: true });

    const idleTimer = setInterval(() => {
        const idle = Date.now() - state.lastActivity;
        if (idle > 1000) { state.idleDurations.push(idle); state.lastActivity = Date.now(); }
    }, 1000);

    state._cleanup = () => {
        document.removeEventListener('mousemove', onMouseMove);
        document.removeEventListener('mousedown', onMouseDown);
        document.removeEventListener('keydown',   onKeyDown);
        clearInterval(idleTimer);
    };

    return state;
}

// ── Stats helpers ─────────────────────────────────────────────
function _pct(arr, p) {
    const s = [...arr].sort((a, b) => a - b);
    if (!s.length) return 0;
    const i = (p / 100) * (s.length - 1);
    const l = Math.floor(i), u = Math.ceil(i);
    return l === u ? s[i] : s[l] + (s[u] - s[l]) * (i - l);
}

function _stats(raw, type) {
    const filters = { click: v => v >= 60, mouse: v => v >= 1 };
    const filtered = filters[type] ? raw.filter(filters[type]) : raw;
    if (filtered.length < 2) return { m: 0, s: 0 };
    const Q1 = _pct(filtered, 25), Q3 = _pct(filtered, 75), IQR = Q3 - Q1;
    const f  = filtered.filter(v => v >= Q1 - 1.5 * IQR && v <= Q3 + 1.5 * IQR);
    if (f.length < 2) return { m: 0, s: 0 };
    const mean = f.reduce((a, b) => a + b, 0) / f.length;
    const std  = Math.sqrt(f.reduce((a, b) => a + (b - mean) ** 2, 0) / f.length);
    const lims = {
        click: { max_m: 2000, max_s: 500  },
        mouse: { max_m: 100,  max_s: 50   },
        key:   { max_m: 1000, max_s: 300  },
        idle:  { max_m: 10000,max_s: 2000 },
    };
    const L = lims[type] || { max_m: 1000, max_s: 300 };
    return {
        m: parseFloat(Math.min(Math.max(mean / L.max_m, 0), 1).toFixed(3)),
        s: parseFloat(Math.min(Math.max(std  / L.max_s, 0), 1).toFixed(3)),
    };
}

function buildPayload(state) {
    const total = state.mouseIntervals.length + state.clickIntervals.length + state.keyIntervals.length;
    if (total < 3) return null; // ข้อมูลน้อยเกินไป

    const sessionSec = Math.max((Date.now() - state.startTime) / 1000, 1);
    const idleSum    = state.idleDurations.reduce((a, b) => a + b, 0) / 1000;
    return {
        mouse:    _stats(state.mouseIntervals, 'mouse'),
        click:    _stats(state.clickIntervals, 'click'),
        key:      _stats(state.keyIntervals,   'key'),
        idle:     _stats(state.idleDurations,  'idle'),
        features: {
            density:    parseFloat(Math.min(total / sessionSec / 100, 1).toFixed(3)),
            idle_ratio: parseFloat(Math.min(idleSum / sessionSec, 1).toFixed(3)),
        },
    };
}

// ── CSRF ──────────────────────────────────────────────────────
async function getCsrf(ssoUrl) {
    if (_csrfCache) return _csrfCache;
    const res  = await fetch(`${ssoUrl}/api/csrf`, { credentials: 'include' });
    const data = await res.json();
    _csrfCache = data.token;
    return _csrfCache;
}

// ── ส่ง checkpoint ────────────────────────────────────────────
async function sendCheckpoint(ssoUrl, callbacks) {
    const behavior = buildPayload(_behaviorState);
    // behavior = null → ส่งแต่ SSO จะใช้ pre_score เป็น fallback

    let csrfToken;
    try {
        csrfToken = await getCsrf(ssoUrl);
    } catch {
        return; // CSRF fail → skip รอบนี้ ลองใหม่รอบหน้า
    }

    let res;
    try {
        res = await fetch(`${ssoUrl}/api/session-risk`, {
            method:      'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken,
            },
            body: JSON.stringify({ behavior }),
        });
    } catch {
        return; // network error → skip
    }

    // CSRF expired → ล้าง cache แล้ว retry รอบหน้า
    if (res.status === 403) { _csrfCache = null; return; }

    // JWT หมดอายุ / ถูก revoke ก่อนหน้านี้ → revoke callback
    if (res.status === 401) {
        callbacks.onRevoke?.();
        stopRiskMonitor();
        return;
    }

    if (!res.ok) return;

    const data = await res.json();

    switch (data.action) {
        case 'warn':
            callbacks.onWarn?.(data.combinedScore);
            break;
        case 'step_up':
            callbacks.onStepUp?.(data.combinedScore);
            stopRiskMonitor();
            break;
        case 'revoke':
            callbacks.onRevoke?.(data.combinedScore);
            stopRiskMonitor();
            break;
        // 'ok' → ไม่ทำอะไร
    }
}

// ── Public API ────────────────────────────────────────────────

/**
 * startRiskMonitor(options)
 *
 * @param {object}   options
 * @param {string}   options.ssoUrl   - URL ของ CARS-SSO (ไม่มี trailing slash)
 * @param {number}   [options.intervalMs=15000] - ส่งทุกกี่ ms (default 15 วินาที)
 * @param {function} [options.onWarn]    - callback เมื่อ action = warn
 * @param {function} [options.onStepUp]  - callback เมื่อ action = step_up
 * @param {function} [options.onRevoke]  - callback เมื่อ action = revoke หรือ session หมดอายุ
 */
export function startRiskMonitor(options = {}) {
    if (_monitorInterval) return; // ป้องกัน double-start

    const {
        ssoUrl,
        intervalMs = 15_000,
        onWarn,
        onStepUp,
        onRevoke,
    } = options;

    if (!ssoUrl) throw new Error('[RiskSDK] ssoUrl is required');

    const callbacks = { onWarn, onStepUp, onRevoke };

    _behaviorState  = initCollector();
    _csrfCache      = null;

    // ส่งครั้งแรกหลัง 15 วินาที (ให้เวลาเก็บข้อมูลพอก่อน)
    _monitorInterval = setInterval(() => {
        sendCheckpoint(ssoUrl, callbacks).catch(err =>
            console.error('[RiskSDK] sendCheckpoint error:', err)
        );
    }, intervalMs);
}

export function stopRiskMonitor() {
    if (_monitorInterval) {
        clearInterval(_monitorInterval);
        _monitorInterval = null;
    }
    if (_behaviorState?._cleanup) {
        _behaviorState._cleanup();
        _behaviorState = null;
    }
    _csrfCache = null;
}
