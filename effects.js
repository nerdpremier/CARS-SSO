/**
 * effects.js — CARS SSO
 * Dark navy background + interactive grid tiles that glow & flip to white near mouse
 */
(function () {
  'use strict';

  /* ══════════════════════════════════════════════════════════
     1.  INTERACTIVE CANVAS
     ══════════════════════════════════════════════════════════ */
  (function initCanvas() {
    var canvas = document.createElement('canvas');
    canvas.id = 'bg-canvas';
    canvas.setAttribute('aria-hidden', 'true');
    document.body.insertBefore(canvas, document.body.firstChild);

    var ctx = canvas.getContext('2d');
    var W = 0, H = 0;

    /* ── Mouse (raw + smoothed) ──────────────────────────── */
    var mx = -9999, my = -9999;   // raw
    var px = -9999, py = -9999;   // smoothed

    /* ── Grid config ─────────────────────────────────────── */
    var CELL   = 44;    // tile size px
    var GAP    = 1.5;   // gap between tiles
    var R_NEAR = 40;    // full-brightness radius
    var R_FAR  = 110;   // falloff edge radius
    var COLS, ROWS;
    var tiles  = [];    // brightness 0..1 per tile

    function buildGrid() {
      COLS  = Math.ceil(W / CELL) + 2;
      ROWS  = Math.ceil(H / CELL) + 2;
      tiles = [];
      for (var r = 0; r < ROWS; r++) {
        tiles[r] = [];
        for (var c = 0; c < COLS; c++) tiles[r][c] = 0;
      }
    }

    /* ── Draw grid ───────────────────────────────────────── */
    function drawGrid() {
      var inner = CELL - GAP;

      for (var r = 0; r < ROWS; r++) {
        for (var c = 0; c < COLS; c++) {
          var tx  = c * CELL;
          var ty  = r * CELL;
          var cx2 = tx + CELL * .5;
          var cy2 = ty + CELL * .5;

          /* distance from tile centre to smoothed mouse */
          var dx   = cx2 - px;
          var dy   = cy2 - py;
          var dist = Math.sqrt(dx * dx + dy * dy);

          /* target brightness */
          var target = 0;
          if (dist < R_FAR) {
            if (dist < R_NEAR) {
              target = 1;
            } else {
              var f = 1 - (dist - R_NEAR) / (R_FAR - R_NEAR);
              target = f * f;
            }
          }

          /* ease toward target */
          var cur = tiles[r][c];
          var spd = target > cur ? 0.18 : 0.055;
          tiles[r][c] = cur + (target - cur) * spd;
          var t = tiles[r][c];

          /* base tile: dark navy → near-white */
          var rC = Math.round(16  + (210 - 16)  * t);
          var gC = Math.round(22  + (220 - 22)  * t);
          var bC = Math.round(54  + (255 - 54)  * t);
          ctx.fillStyle = 'rgb(' + rC + ',' + gC + ',' + bC + ')';
          ctx.fillRect(tx + GAP * .5, ty + GAP * .5, inner, inner);

          /* inner radial glow for lit tiles */
          if (t > 0.04) {
            var grd = ctx.createRadialGradient(cx2, cy2, 0, cx2, cy2, inner * .65);
            grd.addColorStop(0,   'rgba(140,170,255,' + (t * .55) + ')');
            grd.addColorStop(0.5, 'rgba(100,130,255,' + (t * .22) + ')');
            grd.addColorStop(1,   'rgba(80,110,240,0)');
            ctx.fillStyle = grd;
            ctx.fillRect(tx + GAP * .5, ty + GAP * .5, inner, inner);
          }

          /* crisp bright border for very lit tiles */
          if (t > 0.45) {
            ctx.strokeStyle = 'rgba(200,215,255,' + (t * .55) + ')';
            ctx.lineWidth   = 0.7;
            ctx.strokeRect(tx + GAP * .5 + .35, ty + GAP * .5 + .35, inner - .7, inner - .7);
          }
        }
      }
    }

    /* ── Faint floating particles ─────────────────────────── */
    var particles = [];
    function Particle() { this.init(); }
    Particle.prototype.init = function() {
      this.x  = Math.random() * W;
      this.y  = Math.random() * H;
      this.r  = .7 + Math.random() * 1.4;
      this.a  = .06 + Math.random() * .14;
      this.vx = (Math.random() - .5) * .22;
      this.vy = -.12 - Math.random() * .18;
      this.ph = Math.random() * Math.PI * 2;
    };
    Particle.prototype.update = function() {
      this.ph += .010;
      this.x  += this.vx + Math.sin(this.ph * .6) * .25;
      this.y  += this.vy;
      if (this.y < -8) { this.y = H + 4; this.x = Math.random() * W; }
    };
    Particle.prototype.draw = function() {
      var a = this.a + Math.sin(this.ph) * this.a * .3;
      ctx.fillStyle = 'rgba(110,145,255,' + a + ')';
      ctx.beginPath(); ctx.arc(this.x, this.y, this.r, 0, Math.PI * 2); ctx.fill();
    };
    function spawnParticles() {
      particles = [];
      var n = Math.min(55, Math.floor(W * H / 14000));
      for (var i = 0; i < n; i++) particles.push(new Particle());
    }

    /* ── Resize ──────────────────────────────────────────── */
    function resize() {
      W = canvas.width  = window.innerWidth;
      H = canvas.height = window.innerHeight;
      buildGrid();
      spawnParticles();
    }

    /* ── Main loop ───────────────────────────────────────── */
    function loop() {
      px += (mx - px) * .11;
      py += (my - py) * .11;

      ctx.fillStyle = '#0A0E23';
      ctx.fillRect(0, 0, W, H);

      drawGrid();

      for (var i = 0; i < particles.length; i++) {
        particles[i].update();
        particles[i].draw();
      }

      requestAnimationFrame(loop);
    }

    /* ── Events ──────────────────────────────────────────── */
    window.addEventListener('resize', resize);
    document.addEventListener('mousemove', function(e) { mx = e.clientX; my = e.clientY; });
    document.addEventListener('mouseleave', function() { mx = -9999; my = -9999; });

    resize();
    loop();
  })();


  /* ══════════════════════════════════════════════════════════
     2.  PAGE TRANSITIONS
     ══════════════════════════════════════════════════════════ */
  window.CarsNav = {
    go: function(url, replace) {
      document.body.classList.add('page-exit');
      setTimeout(function() {
        if (replace) window.location.replace(url);
        else window.location.href = url;
      }, 260);
    }
  };
  document.addEventListener('click', function(e) {
    var a = e.target.closest('a[href]'); if (!a) return;
    var href = a.getAttribute('href');
    if (!href || href.startsWith('#') || href.startsWith('http') ||
        href.startsWith('mailto:') || href.startsWith('tel:')) return;
    if (e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
    e.preventDefault(); CarsNav.go(href);
  });


  /* ══════════════════════════════════════════════════════════
     3.  TOAST SYSTEM
     ══════════════════════════════════════════════════════════ */
  var _tc = null;
  function getTC() {
    if (!_tc) {
      _tc = document.createElement('div');
      _tc.className = 'toast-container';
      _tc.setAttribute('aria-live', 'polite');
      document.body.appendChild(_tc);
    }
    return _tc;
  }
  var ICONS = { success: '✅', danger: '⚠️', warning: '🔔', info: 'ℹ️' };
  window.CarsToast = function(opts) {
    var type = opts.type || 'info';
    var dur  = opts.duration != null ? opts.duration : 4000;
    var t  = document.createElement('div'); t.className = 'toast toast--' + type; t.setAttribute('role', 'alert');
    var ic = document.createElement('span'); ic.className = 'toast-icon'; ic.setAttribute('aria-hidden', 'true'); ic.textContent = ICONS[type] || 'ℹ️';
    var bd = document.createElement('div'); bd.className = 'toast-body';
    if (opts.title) {
      var tt = document.createElement('div'); tt.className = 'toast-title'; tt.textContent = opts.title; bd.appendChild(tt);
    }
    var mm = document.createElement('div'); mm.className = 'toast-msg'; mm.textContent = opts.msg; bd.appendChild(mm);
    var cl = document.createElement('button'); cl.className = 'toast-close'; cl.setAttribute('aria-label', 'Dismiss'); cl.textContent = '×';
    var pr = document.createElement('div'); pr.className = 'toast-progress';
    t.appendChild(ic); t.appendChild(bd); t.appendChild(cl); t.appendChild(pr);
    getTC().appendChild(t);
    var timer = null;
    function dismiss() {
      clearTimeout(timer);
      t.classList.add('toast--exit');
      setTimeout(function() { if (t.parentNode) t.parentNode.removeChild(t); }, 260);
    }
    cl.addEventListener('click', dismiss);
    if (dur > 0) {
      timer = setTimeout(dismiss, dur);
      t.addEventListener('mouseenter', function() { clearTimeout(timer); });
      t.addEventListener('mouseleave', function() { timer = setTimeout(dismiss, 1500); });
    }
    return { dismiss: dismiss };
  };


  /* ══════════════════════════════════════════════════════════
     4.  BUTTON RIPPLE
     ══════════════════════════════════════════════════════════ */
  function ripple(btn, e) {
    var rect = btn.getBoundingClientRect();
    var size = Math.max(rect.width, rect.height) * 2.6;
    var cx   = e && e.clientX != null ? e.clientX - rect.left : rect.width  / 2;
    var cy   = e && e.clientY != null ? e.clientY - rect.top  : rect.height / 2;
    var el   = document.createElement('span'); el.setAttribute('aria-hidden', 'true'); btn.appendChild(el);
    var anim = el.animate([
      { position: 'absolute', width: size + 'px', height: size + 'px',
        left: (cx - size / 2) + 'px', top: (cy - size / 2) + 'px',
        borderRadius: '50%', background: 'rgba(255,255,255,0.25)',
        transform: 'scale(0)', opacity: '1', pointerEvents: 'none' },
      { transform: 'scale(1)', opacity: '0' }
    ], { duration: 560, easing: 'ease-out', fill: 'forwards' });
    anim.onfinish = function() { el.remove(); };
  }
  document.addEventListener('click', function(e) {
    var b = e.target.closest('.btn-primary,.btn-portal,.btn-signout,.btn-create');
    if (b) ripple(b, e);
  });
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') {
      var el = document.activeElement;
      if (el && el.matches('.btn-primary,.btn-portal,.btn-signout,.btn-create')) ripple(el, null);
    }
  });

}());
