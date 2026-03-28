(function () {
  if (window.BSSOBehaviorCollector) return;

  const DEFAULT_INTERVAL = 15000;

  function createCollector() {
    let events = [];
    let timer  = null;

    let lastFlushTs    = null;
    let lastEventTs    = null;
    let activeTimeMs   = 0;
    let eventCount     = 0;

    let lastMouse = null; 
    let mouseTotalDist = 0;
    let mouseSamples = 0;
    let mouseDirChanges = 0;
    let lastMouseVec = null; 

    let lastClickTs = null;
    let clickIntervals = []; 

    let lastKeyTs = null;
    let keyIntervals = []; 

    let scrollSamples = 0;
    let scrollTotalAbsDy = 0;
    let scrollDirChanges = 0;
    let lastScrollSign = 0;

    let _mediumPending = false;
    let _mediumPendingSince = null;
    let _autoRedirect = true;

    function record(type, payload) {
      events.push({
        type,
        ts:   Date.now(),
        data: payload || {}
      });

      const now = Date.now();
      if (lastEventTs != null) {

        const delta = now - lastEventTs;
        const capped = delta > 5000 ? 5000 : delta;
        activeTimeMs += capped;
      }
      lastEventTs = now;
      eventCount += 1;
    }

    function setupListeners() {
      window.addEventListener('click', function (e) {
        const now = Date.now();
        if (lastClickTs != null) {
          const dt = now - lastClickTs;
          if (dt > 0 && dt < 60_000) {
            clickIntervals.push(dt);
            if (clickIntervals.length > 120) clickIntervals.shift();
          }
        }
        lastClickTs = now;
        record('click', {
          x: e.clientX,
          y: e.clientY,
          tag: e.target && e.target.tagName,
        });
      }, { passive: true });

      window.addEventListener('mousemove', (function () {
        let last = 0;
        return function (e) {
          const now = Date.now();
          if (now - last < 500) return;
          last = now;

          if (lastMouse) {
            const dt = now - lastMouse.t;
            const dx = e.clientX - lastMouse.x;
            const dy = e.clientY - lastMouse.y;
            if (dt > 0 && dt < 10_000) {
              const dist = Math.sqrt(dx * dx + dy * dy);
              mouseTotalDist += dist;
              mouseSamples += 1;

              if (lastMouseVec) {
                const dot = dx * lastMouseVec.dx + dy * lastMouseVec.dy;

                if (dot < 0) mouseDirChanges += 1;
              }
              lastMouseVec = { dx, dy };
            }
          }
          lastMouse = { x: e.clientX, y: e.clientY, t: now };

          record('mousemove', { x: e.clientX, y: e.clientY });
        };
      })(), { passive: true });

      window.addEventListener('keydown', (function () {
        let count = 0;
        return function () {
          count += 1;
          const now = Date.now();
          if (lastKeyTs != null) {
            const dt = now - lastKeyTs;
            if (dt > 0 && dt < 60_000) {
              keyIntervals.push(dt);
              if (keyIntervals.length > 120) keyIntervals.shift();
            }
          }
          lastKeyTs = now;
          record('keydown_summary', { count });
        };
      })());

      window.addEventListener('scroll', (function () {
        let lastY = window.scrollY;
        return function () {
          const y = window.scrollY;
          const dy = y - lastY;
          lastY = y;

          const absDy = Math.abs(dy);
          if (absDy > 0) {
            scrollSamples += 1;
            scrollTotalAbsDy += absDy;
            const sign = dy > 0 ? 1 : -1;
            if (lastScrollSign !== 0 && sign !== lastScrollSign) scrollDirChanges += 1;
            lastScrollSign = sign;
          }
        };
      })(), { passive: true });

      document.addEventListener('visibilitychange', function () {
        record('visibility', { state: document.visibilityState });
      });
    }

    let _bearerToken = null;

    function setBearerToken(token) {
      _bearerToken = token;
    }

    async function flush() {
      const batch = events;
      events = [];

       const now = Date.now();
       if (lastFlushTs == null) lastFlushTs = now;
       const windowMs = now - lastFlushTs;
       const safeWindowMs = windowMs > 0 ? windowMs : DEFAULT_INTERVAL;

       const idleMs = safeWindowMs - activeTimeMs;
       const idleRatio = safeWindowMs > 0 ? Math.max(0, Math.min(1, idleMs / safeWindowMs)) : 0;
       const interactionDensity = safeWindowMs > 0
         ? eventCount / (safeWindowMs / 1000)
         : 0;

       function mean(arr) {
         if (!arr || arr.length === 0) return 0;
         let s = 0;
         for (let i = 0; i < arr.length; i++) s += arr[i];
         return s / arr.length;
       }
       function std(arr) {
         if (!arr || arr.length < 2) return 0;
         const m = mean(arr);
         let v = 0;
         for (let i = 0; i < arr.length; i++) {
           const d = arr[i] - m;
           v += d * d;
         }
         return Math.sqrt(v / (arr.length - 1));
       }

       const avgMouseSpeed = safeWindowMs > 0
         ? (mouseTotalDist / (safeWindowMs / 1000))
         : 0;
       const mouseDirChangeRate = mouseSamples > 0
         ? mouseDirChanges / mouseSamples
         : 0;

       const avgClickIntervalMs = mean(clickIntervals);
       const stdClickIntervalMs = std(clickIntervals);
       const avgKeyIntervalMs   = mean(keyIntervals);
       const stdKeyIntervalMs   = std(keyIntervals);

       const avgScrollAbsDy = scrollSamples > 0 ? (scrollTotalAbsDy / scrollSamples) : 0;
       const scrollDirChangeRate = scrollSamples > 0 ? (scrollDirChanges / scrollSamples) : 0;

       const features = {
         idle_ratio: idleRatio,
         interaction_density: interactionDensity,
         event_count: eventCount,
         window_ms: safeWindowMs,

         avg_mouse_speed: avgMouseSpeed,
         mouse_dir_change_rate: mouseDirChangeRate,
         avg_click_interval_ms: avgClickIntervalMs,
         std_click_interval_ms: stdClickIntervalMs,
         avg_key_interval_ms: avgKeyIntervalMs,
         std_key_interval_ms: stdKeyIntervalMs,
         avg_scroll_abs_dy: avgScrollAbsDy,
         scroll_dir_change_rate: scrollDirChangeRate
       };

       lastFlushTs  = now;
       lastEventTs  = null;
       activeTimeMs = 0;
       eventCount   = 0;

       lastMouse = null;
       mouseTotalDist = 0;
       mouseSamples = 0;
       mouseDirChanges = 0;
       lastMouseVec = null;

       lastClickTs = null;
       clickIntervals = [];

       lastKeyTs = null;
       keyIntervals = [];

       scrollSamples = 0;
       scrollTotalAbsDy = 0;
       scrollDirChanges = 0;
       lastScrollSign = 0;

      try {
        const payload = {
          events: batch,
          page:   window.location.pathname,
          return_url: window.location.href,
          meta: {
            userAgent: navigator.userAgent,
          },
          features
        };

        const controller = new AbortController();
        const timeoutId  = setTimeout(function () { controller.abort(); }, 8000);

        try {
          const headers = {
            'Content-Type': 'application/json',
          };
          if (_bearerToken) {
            headers['Authorization'] = 'Bearer ' + _bearerToken;
          }

          const res = await fetch('/api/behavior', {
            method:      'POST',
            credentials: 'include',
            headers:     headers,
            body:        JSON.stringify(payload),
            signal:      controller.signal,
          });

          clearTimeout(timeoutId);

          if (!res.ok) return;
          const data = await res.json().catch(function () { return {}; });
          const action = (data.action || 'low').toLowerCase();

          if (action === 'step_up_redirect' && data.stepup_redirect_url && !_mediumPending) {
            _mediumPending = true;
            _mediumPendingSince = Date.now();
            window.dispatchEvent(new CustomEvent('bsso-behavior-stepup-redirect', { detail: data }));

            if (_autoRedirect) {
              window.location.href = data.stepup_redirect_url;
            }
          } else if ((action === 'medium' || action === 'step_up_required') && !_mediumPending) {
            _mediumPending = true;
            _mediumPendingSince = Date.now();
            window.dispatchEvent(new CustomEvent('bsso-behavior-medium', { detail: data }));
          } else if (action === 'revoke') {

            window.dispatchEvent(new CustomEvent('bsso-behavior-revoke', { detail: data }));
          }

          if (_mediumPending && _mediumPendingSince && (Date.now() - _mediumPendingSince > 5 * 60 * 1000)) {
            _mediumPending = false;
            _mediumPendingSince = null;
          }
        } catch (err) {

          console && console.debug && console.debug('[BSSOBehaviorCollector] flush error', err.message || err);
        }
      } catch (outer) {

      }
    }

    function start(options) {
      if (timer) return;
      const interval = (options && typeof options.intervalMs === 'number' && options.intervalMs > 0)
        ? options.intervalMs
        : DEFAULT_INTERVAL;

      setupListeners();
      timer = setInterval(flush, interval);
    }

    function stop() {
      if (timer) {
        clearInterval(timer);
        timer = null;
      }
      events = [];
    }

    function clearMedium() {
      _mediumPending = false;
      _mediumPendingSince = null;
    }

    function setAutoRedirect(enabled) {
      _autoRedirect = !!enabled;
    }

    async function handleStepupCallback() {
      const params = new URLSearchParams(window.location.search);
      const stepupVerified = params.get('stepup_verified');
      const stepupToken = params.get('stepup_token');

      if (stepupVerified !== '1' || !stepupToken) return false;

      const cleanUrl = new URL(window.location.href);
      cleanUrl.searchParams.delete('stepup_verified');
      cleanUrl.searchParams.delete('stepup_token');
      try {
        window.history.replaceState({}, '', cleanUrl.toString());
      } catch { }

      try {
        const headers = {
          'Content-Type': 'application/json',
        };
        if (_bearerToken) {
          headers['Authorization'] = 'Bearer ' + _bearerToken;
        }

        const validateRes = await fetch('/api/stepup', {
          method: 'POST',
          headers: headers,
          body: JSON.stringify({
            action: 'validate-token',
            stepup_token: stepupToken
          }),
        });

        if (validateRes.ok) {
          const data = await validateRes.json();
          if (data.valid) {
            _mediumPending = false;
            _mediumPendingSince = null;
            window.dispatchEvent(new CustomEvent('bsso-stepup-verified', { detail: { token: stepupToken } }));
            return true;
          }
        }
      } catch (err) {
        console && console.debug && console.debug('[BSSOBehaviorCollector] stepup validate error', err.message || err);
      }

      window.dispatchEvent(new CustomEvent('bsso-stepup-failed', { detail: { token: stepupToken } }));
      return false;
    }

    return { start, stop, clearMedium, setBearerToken, setAutoRedirect, handleStepupCallback };
  }

  window.BSSOBehaviorCollector = createCollector();
})();
