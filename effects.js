/**
 * effects.js — B-SSO (Behavioral Risk-Based Single Sign-On)
 * Dark navy background + interactive grid tiles that glow & flip to white near mouse
 */
(function () {
  'use strict';

  /* ══════════════════════════════════════════════════════════
     1.  INTERACTIVE CANVAS (Google Antigravity Swirling Particles)
     ══════════════════════════════════════════════════════════ */
  (function initCanvas() {
    var canvas = document.createElement('canvas');
    canvas.id = 'bg-canvas';
    canvas.setAttribute('aria-hidden', 'true');
    // Ensure the canvas sits behind everything but doesn't block clicks
    canvas.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -1; pointer-events: none; opacity: 0.85;';
    document.body.insertBefore(canvas, document.body.firstChild);

    var ctx = canvas.getContext('2d', { alpha: false });
    var W = 0, H = 0, cx = 0, cy = 0;

    /* ── Mouse ────────────────────────── */
    var mouse = { x: -9999, y: -9999 };
    var isMoving = false;
    var mouseTimeout;

    /* ── Particles ────────────────────── */
    var particles = [];
    var NUM_PARTICLES = 1200; // Dense particle field
    
    // Antigravity Brand Colors
    var colors = [
      '#3B82F6', // Blue
      '#8B5CF6', // Purple
      '#EF4444', // Red
      '#F59E0B', // Orange
      '#06B6D4'  // Cyan
    ];

    class Particle {
      constructor() {
        this.reset(true);
      }

      reset(randomizeRadius) {
        // Distribute particles in a swirling orbit around center
        var angle = Math.random() * Math.PI * 2;
        var radius = randomizeRadius ? Math.random() * (Math.max(W, H) * 0.8) : Math.max(W, H) * 0.8 + Math.random() * 100;
        
        this.x = cx + Math.cos(angle) * radius;
        this.y = cy + Math.sin(angle) * radius;
        
        // Base orbit speed
        this.orbitSpeed = (Math.random() * 0.001) + 0.0005;
        this.angle = angle;
        this.radius = radius;
        
        // Radial inward drift
        this.drift = (Math.random() * 0.5) + 0.1;
        
        this.size = Math.random() * 1.5 + 0.5;
        this.length = Math.random() * 20 + 10;
        this.color = colors[Math.floor(Math.random() * colors.length)];
        this.alpha = Math.random() * 0.5 + 0.1;
      }

      update() {
        // Orbit math
        this.angle += this.orbitSpeed;
        this.radius -= this.drift;
        
        // Mouse interaction (repel)
        var dx = this.x - mouse.x;
        var dy = this.y - mouse.y;
        var dist = Math.sqrt(dx * dx + dy * dy);
        
        var targetX = cx + Math.cos(this.angle) * this.radius;
        var targetY = cy + Math.sin(this.angle) * this.radius;

        if (dist < 150 && isMoving) {
          var force = (150 - dist) / 150;
          targetX += (dx / dist) * force * 100;
          targetY += (dy / dist) * force * 100;
        }

        // Smoothly move to target
        this.x += (targetX - this.x) * 0.1;
        this.y += (targetY - this.y) * 0.1;

        // Reset if inhaled into center
        if (this.radius < 20) {
          this.reset(false);
          this.radius = Math.max(W, H) * 0.8; 
          this.alpha = 0; // fade in
        } else if (this.alpha < 0.6) {
          this.alpha += 0.01;
        }
      }

      draw() {
        // Calculate tangent vector for the dash direction (perpendicular to radius)
        var dashAngle = this.angle + Math.PI / 2;
        if (this.radius < 100) {
            // swirl intensely inward
            dashAngle += Math.PI / 4;
        }

        ctx.save();
        ctx.translate(this.x, this.y);
        ctx.rotate(dashAngle);
        ctx.globalAlpha = this.alpha;
        ctx.lineCap = 'round';
        ctx.lineWidth = this.size;
        ctx.strokeStyle = this.color;
        
        ctx.beginPath();
        ctx.moveTo(-this.length / 2, 0);
        ctx.lineTo(this.length / 2, 0);
        ctx.stroke();
        ctx.restore();
      }
    }

    /* ── Init & Resize ───────────────────────────────────── */
    function resize() {
      W = canvas.width = window.innerWidth;
      H = canvas.height = window.innerHeight;
      cx = W / 2;
      cy = H / 2;
      
      // Adjust particle count based on screen size
      var targetParticles = Math.min(2000, Math.floor((W * H) / 1000));
      if (particles.length === 0) {
         for (var i = 0; i < targetParticles; i++) particles.push(new Particle());
      }
    }

    /* ── Main loop ───────────────────────────────────────── */
    function loop() {
      // Draw pristine white/blue background directly on canvas to prevent stacking lag
      var grd = ctx.createRadialGradient(cx, cy, 0, cx, cy, Math.max(W, H));
      grd.addColorStop(0, '#ffffff');
      grd.addColorStop(1, '#e0f2fe'); // Soft blue vignette
      
      ctx.globalAlpha = 1.0;
      ctx.fillStyle = grd;
      ctx.fillRect(0, 0, W, H);

      // Composite operation for vivid colors
      ctx.globalCompositeOperation = 'source-over';

      for (var i = 0; i < particles.length; i++) {
        particles[i].update();
        particles[i].draw();
      }

      requestAnimationFrame(loop);
    }

    /* ── Events ──────────────────────────────────────────── */
    window.addEventListener('resize', resize);
    document.addEventListener('mousemove', function(e) { 
      mouse.x = e.clientX; 
      mouse.y = e.clientY; 
      isMoving = true;
      
      clearTimeout(mouseTimeout);
      mouseTimeout = setTimeout(() => { isMoving = false; }, 200);
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
