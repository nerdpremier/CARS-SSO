/**
 * effects.js — CARS SSO "Meridian"
 * CSP-safe: no element.style assignments, no inline styles.
 * Features:
 *   1. Canvas particle constellation background
 *   2. Page transition system (navigate with fade/slide)
 *   3. Toast notification manager (window.CarsToast)
 *   4. Button ripple (Web Animations API)
 */
(function () {
  'use strict';

  /* ══════════════════════════════════════════════════════════
     1. CANVAS PARTICLE BACKGROUND
     ══════════════════════════════════════════════════════════ */
  var prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  if (!prefersReduced) {
    (function initCanvas() {
      var canvas = document.createElement('canvas');
      canvas.id = 'bg-canvas';
      canvas.setAttribute('aria-hidden', 'true');
      // Insert as first child of body
      if (document.body.firstChild) {
        document.body.insertBefore(canvas, document.body.firstChild);
      } else {
        document.body.appendChild(canvas);
      }

      var ctx = canvas.getContext('2d');
      var W = 0, H = 0;
      var particles = [];
      var mouse = { x: -9999, y: -9999 };

      var DOT_COLOR  = [79, 110, 247];
      var MAX_DIST   = 160;
      var MOUSE_R    = 200;
      var SPEED      = 0.38;
      var DOT_R      = 1.7;
      var DOT_ALPHA  = 0.40;
      var LINE_ALPHA = 0.10;

      function resize() {
        W = canvas.width  = window.innerWidth;
        H = canvas.height = window.innerHeight;
      }

      function Particle() {
        this.x  = Math.random() * W;
        this.y  = Math.random() * H;
        this.vx = (Math.random() - .5) * SPEED;
        this.vy = (Math.random() - .5) * SPEED;
        this.r  = DOT_R * (.65 + Math.random() * .7);
      }
      Particle.prototype.update = function () {
        this.x += this.vx;
        this.y += this.vy;
        if (this.x < -12) this.x = W + 12;
        if (this.x > W+12) this.x = -12;
        if (this.y < -12) this.y = H + 12;
        if (this.y > H+12) this.y = -12;
      };

      function spawn() {
        particles = [];
        var n = Math.min(70, Math.floor(W * H / 12000));
        for (var i = 0; i < n; i++) particles.push(new Particle());
      }

      function draw() {
        ctx.clearRect(0, 0, W, H);
        var len = particles.length;
        // Lines
        for (var i = 0; i < len; i++) {
          for (var j = i + 1; j < len; j++) {
            var dx = particles[i].x - particles[j].x;
            var dy = particles[i].y - particles[j].y;
            var d2 = dx*dx + dy*dy;
            if (d2 < MAX_DIST * MAX_DIST) {
              var a = LINE_ALPHA * (1 - Math.sqrt(d2) / MAX_DIST);
              ctx.beginPath();
              ctx.strokeStyle = 'rgba(' + DOT_COLOR + ',' + a + ')';
              ctx.lineWidth   = 0.7;
              ctx.moveTo(particles[i].x, particles[i].y);
              ctx.lineTo(particles[j].x, particles[j].y);
              ctx.stroke();
            }
          }
        }
        // Dots
        for (var k = 0; k < len; k++) {
          var p  = particles[k];
          var mx = p.x - mouse.x, my = p.y - mouse.y;
          var md = Math.sqrt(mx*mx + my*my);
          var glow = md < MOUSE_R ? (1 - md/MOUSE_R) * .5 : 0;
          ctx.beginPath();
          ctx.arc(p.x, p.y, p.r + glow, 0, Math.PI * 2);
          ctx.fillStyle = 'rgba(' + DOT_COLOR + ',' + (DOT_ALPHA + glow) + ')';
          ctx.fill();
        }
      }

      function loop() {
        for (var i = 0; i < particles.length; i++) particles[i].update();
        draw();
        requestAnimationFrame(loop);
      }

      window.addEventListener('resize', function () { resize(); spawn(); });
      document.addEventListener('mousemove', function (e) { mouse.x = e.clientX; mouse.y = e.clientY; });
      document.addEventListener('mouseleave', function () { mouse.x = -9999; mouse.y = -9999; });

      resize(); spawn(); loop();
    })();
  }


  /* ══════════════════════════════════════════════════════════
     2. PAGE TRANSITION SYSTEM
     ══════════════════════════════════════════════════════════ */
  window.CarsNav = {
    go: function (url, replace) {
      document.body.classList.add('page-exit');
      setTimeout(function () {
        if (replace) window.location.replace(url);
        else         window.location.href = url;
      }, 260);
    }
  };

  // Intercept same-origin anchor clicks
  document.addEventListener('click', function (e) {
    var a = e.target.closest('a[href]');
    if (!a) return;
    var href = a.getAttribute('href');
    if (!href || href.startsWith('#') || href.startsWith('http') || href.startsWith('mailto://') || href.startsWith('tel:')) return;
    if (e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    CarsNav.go(href);
  });


  /* ══════════════════════════════════════════════════════════
     3. TOAST NOTIFICATION SYSTEM
     ══════════════════════════════════════════════════════════ */
  var _toastContainer = null;

  function getToastContainer() {
    if (!_toastContainer) {
      _toastContainer = document.createElement('div');
      _toastContainer.className = 'toast-container';
      _toastContainer.setAttribute('aria-live', 'polite');
      _toastContainer.setAttribute('aria-atomic', 'false');
      document.body.appendChild(_toastContainer);
    }
    return _toastContainer;
  }

  var ICONS = { success:'✅', danger:'⚠️', warning:'🔔', info:'ℹ️', loading:'⏳' };

  /**
   * window.CarsToast({ type, title, msg, duration })
   * type: 'success' | 'danger' | 'warning' | 'info'
   * duration: ms (0 = no auto-close). Default 4000.
   */
  window.CarsToast = function (opts) {
    var container = getToastContainer();
    var type      = opts.type || 'info';
    var duration  = opts.duration != null ? opts.duration : 4000;

    var toast = document.createElement('div');
    toast.className = 'toast toast--' + type;
    toast.setAttribute('role', 'alert');

    var iconEl = document.createElement('span');
    iconEl.className = 'toast-icon';
    iconEl.setAttribute('aria-hidden', 'true');
    iconEl.textContent = ICONS[type] || 'ℹ️';

    var bodyEl = document.createElement('div');
    bodyEl.className = 'toast-body';
    if (opts.title) {
      var t = document.createElement('div');
      t.className = 'toast-title';
      t.textContent = opts.title;
      bodyEl.appendChild(t);
    }
    var m = document.createElement('div');
    m.className = 'toast-msg';
    m.textContent = opts.msg;
    bodyEl.appendChild(m);

    var closeEl = document.createElement('button');
    closeEl.className = 'toast-close';
    closeEl.setAttribute('aria-label', 'Dismiss');
    closeEl.textContent = '×';

    var prog = document.createElement('div');
    prog.className = 'toast-progress';

    toast.appendChild(iconEl);
    toast.appendChild(bodyEl);
    toast.appendChild(closeEl);
    toast.appendChild(prog);
    container.appendChild(toast);

    var timer = null;
    function dismiss() {
      clearTimeout(timer);
      toast.classList.add('toast--exit');
      setTimeout(function () { if (toast.parentNode) toast.parentNode.removeChild(toast); }, 260);
    }

    closeEl.addEventListener('click', dismiss);
    if (duration > 0) {
      timer = setTimeout(dismiss, duration);
      toast.addEventListener('mouseenter', function () {
        clearTimeout(timer);
        // pause animation via JS (CSP-safe: Web Animations API)
        prog.getAnimations().forEach(function(a){ a.pause(); });
      });
      toast.addEventListener('mouseleave', function () {
        timer = setTimeout(dismiss, 1500);
        prog.getAnimations().forEach(function(a){ a.play(); });
      });
    }
    return { dismiss: dismiss };
  };


  /* ══════════════════════════════════════════════════════════
     4. BUTTON RIPPLE
     ══════════════════════════════════════════════════════════ */
  function rippleOn(btn, e) {
    var rect = btn.getBoundingClientRect();
    var size = Math.max(rect.width, rect.height) * 2.6;
    var cx   = e && e.clientX != null ? e.clientX - rect.left : rect.width  / 2;
    var cy   = e && e.clientY != null ? e.clientY - rect.top  : rect.height / 2;
    var el   = document.createElement('span');
    el.setAttribute('aria-hidden', 'true');
    btn.appendChild(el);
    var anim = el.animate([
      { position:'absolute', width:size+'px', height:size+'px', left:(cx-size/2)+'px', top:(cy-size/2)+'px', borderRadius:'50%', background:'rgba(0,0,0,0.14)', transform:'scale(0)', opacity:'1', pointerEvents:'none' },
      { transform:'scale(1)', opacity:'0' }
    ], { duration:560, easing:'ease-out', fill:'forwards' });
    anim.onfinish = function () { el.remove(); };
  }

  document.addEventListener('click', function (e) {
    var btn = e.target.closest('.btn-primary,.btn-portal,.btn-signout');
    if (btn) rippleOn(btn, e);
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') {
      var el = document.activeElement;
      if (el && el.matches('.btn-primary,.btn-portal,.btn-signout')) rippleOn(el, null);
    }
  });

}());
