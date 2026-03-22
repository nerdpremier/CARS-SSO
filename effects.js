/**
 * effects.js — B-SSO (Behavioral Risk-Based Single Sign-On)
 * Dark navy background + interactive grid tiles that glow & flip to white near mouse
 */
(function () {
  'use strict';

  /* ══════════════════════════════════════════════════════════
     1.  INTERACTIVE CANVAS (Antigravity Colorful Mouse Trail)
     ══════════════════════════════════════════════════════════ */
  (function initCanvas() {
    var canvas = document.createElement('canvas');
    canvas.id = 'bg-canvas';
    canvas.setAttribute('aria-hidden', 'true');
    document.body.insertBefore(canvas, document.body.firstChild);

    var ctx = canvas.getContext('2d');
    var W = 0, H = 0;

    /* ── Mouse ────────────────────────── */
    var mouse = { x: -9999, y: -9999 };
    var prevMouse = { x: -9999, y: -9999 };
    var isMoving = false;
    var mouseTimeout;

    /* ── Particles ────────────────────── */
    var particles = [];
    var colors = [
      '#3B82F6', /* Blue */
      '#8B5CF6', /* Purple */
      '#EC4899', /* Pink */
      '#F59E0B', /* Orange */
      '#10B981'  /* Green */
    ];

    class Particle {
      constructor(x, y, dx, dy) {
        this.x = x;
        this.y = y;
        this.size = Math.random() * 2 + 1.5;
        this.color = colors[Math.floor(Math.random() * colors.length)];
        
        // Add spread/scatter to the initial movement
        this.vx = (dx * 0.2) + (Math.random() - 0.5) * 4;
        this.vy = (dy * 0.2) + (Math.random() - 0.5) * 4;
        
        this.life = 1.0;
        this.decay = Math.random() * 0.02 + 0.015;
        this.angle = Math.atan2(this.vy, this.vx);
        this.speed = Math.sqrt(this.vx * this.vx + this.vy * this.vy);
        this.length = Math.random() * 15 + 8; // dash length
      }

      update() {
        this.x += this.vx;
        this.y += this.vy;
        
        // Add a bit of drag
        this.vx *= 0.95;
        this.vy *= 0.95;
        
        this.life -= this.decay;
        this.angle = Math.atan2(this.vy, this.vx);
      }

      draw() {
        ctx.save();
        ctx.translate(this.x, this.y);
        ctx.rotate(this.angle);
        ctx.globalAlpha = Math.max(0, this.life);
        ctx.lineCap = 'round';
        ctx.lineWidth = this.size;
        ctx.strokeStyle = this.color;
        
        ctx.beginPath();
        ctx.moveTo(0, 0);
        ctx.lineTo(-this.length * (this.speed * 0.2 + 0.5), 0);
        ctx.stroke();
        ctx.restore();
      }
    }

    /* ── Resize ──────────────────────────────────────────── */
    function resize() {
      W = canvas.width = window.innerWidth;
      H = canvas.height = window.innerHeight;
    }

    /* ── Main loop ───────────────────────────────────────── */
    function loop() {
      // Clear canvas (we use a solid white background in style.css or let the canvas be transparent)
      ctx.clearRect(0, 0, W, H);

      // Interpolate particles if mouse moved fast
      if (isMoving && prevMouse.x !== -9999) {
        var dist = Math.hypot(mouse.x - prevMouse.x, mouse.y - prevMouse.y);
        if (dist > 5) {
          var steps = Math.min(Math.floor(dist / 5), 10);
          for (var i = 0; i < steps; i++) {
            var interpX = prevMouse.x + (mouse.x - prevMouse.x) * (i / steps);
            var interpY = prevMouse.y + (mouse.y - prevMouse.y) * (i / steps);
            if (Math.random() > 0.3) {
              particles.push(new Particle(interpX, interpY, mouse.x - prevMouse.x, mouse.y - prevMouse.y));
            }
          }
        } else {
          if (Math.random() > 0.5) {
             particles.push(new Particle(mouse.x, mouse.y, mouse.x - prevMouse.x, mouse.y - prevMouse.y));
          }
        }
      }

      for (var i = particles.length - 1; i >= 0; i--) {
        particles[i].update();
        particles[i].draw();
        if (particles[i].life <= 0) {
          particles.splice(i, 1);
        }
      }

      prevMouse.x = mouse.x;
      prevMouse.y = mouse.y;

      requestAnimationFrame(loop);
    }

    /* ── Events ──────────────────────────────────────────── */
    window.addEventListener('resize', resize);
    document.addEventListener('mousemove', function(e) { 
      if (prevMouse.x === -9999) {
        prevMouse.x = e.clientX;
        prevMouse.y = e.clientY;
      }
      mouse.x = e.clientX; 
      mouse.y = e.clientY; 
      isMoving = true;
      
      clearTimeout(mouseTimeout);
      mouseTimeout = setTimeout(() => { isMoving = false; }, 50);
    });
    document.addEventListener('mouseleave', function() { 
      mouse.x = -9999; mouse.y = -9999; 
      prevMouse.x = -9999; prevMouse.y = -9999;
      isMoving = false;
    });

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
  var ICONS = { success: 'fas fa-check', danger: 'fas fa-exclamation-triangle', warning: 'fas fa-bell', info: 'fas fa-info-circle' };
  window.CarsToast = function(opts) {
    var type = opts.type || 'info';
    var dur  = opts.duration != null ? opts.duration : 4000;
    var t  = document.createElement('div'); t.className = 'toast toast--' + type; t.setAttribute('role', 'alert');
    var ic = document.createElement('i'); ic.className = 'toast-icon ' + (ICONS[type] || 'fas fa-info-circle'); ic.setAttribute('aria-hidden', 'true');
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
