/**
 * effects.js — B-SSO (Behavioral Risk-Based Single Sign-On)
 * Dark navy background + interactive grid tiles that glow & flip to white near mouse
 */
(function () {
  'use strict';

  /* ══════════════════════════════════════════════════════════
     1.  INTERACTIVE CANVAS (Exact Antigravity Vector Field)
     ══════════════════════════════════════════════════════════ */
  (function initCanvas() {
    var canvas = document.createElement('canvas');
    canvas.id = 'bg-canvas';
    canvas.setAttribute('aria-hidden', 'true');
    canvas.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -1; pointer-events: none;';
    document.body.insertBefore(canvas, document.body.firstChild);

    var ctx = canvas.getContext('2d', { alpha: false });
    var W = 0, H = 0;

    /* ── Interaction ────────────────────────── */
    var mouse = { x: -1000, y: -1000 };
    var targetMouse = { x: -1000, y: -1000 };
    var time = 0;

    /* ── Particles ────────────────────── */
    var particles = [];
    var NUM_PARTICLES = 1600; 

    // Helper to get color based on position (Warm in bottom-left, Blue elsewhere)
    function getColor(x, y) {
      // Normalize position
      var nx = x / W;
      var ny = y / H;
      var distToBottomLeft = Math.sqrt(Math.pow(nx - 0.2, 2) + Math.pow(ny - 0.8, 2));

      if (distToBottomLeft < 0.35) {
        // Warm burst
        var r = Math.random();
        if (r < 0.3) return '#E54823'; // Red/Orange
        if (r < 0.6) return '#F3A926'; // Yellow
        return '#C52834'; // Dark red
      }
      // Default blue tones
      return Math.random() > 0.5 ? '#2143B8' : '#8B5CF6'; 
    }

    class Particle {
      constructor() {
        this.reset(true);
      }

      reset(randomizeParams) {
        this.x = Math.random() * W;
        this.y = Math.random() * H;
        
        // Save initial origin so they drift around a home spot
        this.ox = this.x;
        this.oy = this.y;

        this.color = getColor(this.x, this.y);
        
        // Random lengths to mimic the screenshot's dots/dashes
        this.length = Math.random() * 8 + 2; 
        this.thickness = Math.random() * 1.5 + 1;
        this.alpha = Math.random() * 0.6 + 0.2;
        
        // Natural flow offset
        this.noiseOffsetX = Math.random() * 1000;
        this.noiseOffsetY = Math.random() * 1000;
        
        this.angle = 0;
      }

      update() {
        // Base fluid motion using faux-perlin (sine waves combined)
        var scale = 0.002;
        var fluidAngle = Math.sin(this.ox * scale + time) * Math.cos(this.oy * scale - time) * Math.PI;
        
        var forceX = Math.cos(fluidAngle);
        var forceY = Math.sin(fluidAngle);

        // Mouse warping / gravity
        var dx = mouse.x - this.x;
        var dy = mouse.y - this.y;
        var dist = Math.sqrt(dx * dx + dy * dy);
        
        if (dist < 250) {
          // Repel slightly and swirl
          var repulsion = (250 - dist) / 250;
          var angleToMouse = Math.atan2(dy, dx);
          // Combine pushing away and swirling perpendicular
          forceX -= Math.cos(angleToMouse) * repulsion * 2;
          forceY -= Math.sin(angleToMouse) * repulsion * 2;
          forceX += Math.cos(angleToMouse + Math.PI/2) * repulsion;
          forceY += Math.sin(angleToMouse + Math.PI/2) * repulsion;
        }

        // Return to home position gently
        var homeDx = this.ox - this.x;
        var homeDy = this.oy - this.y;
        forceX += homeDx * 0.005;
        forceY += homeDy * 0.005;

        this.x += forceX;
        this.y += forceY;

        // Determine drawing angle based on current movement vector
        this.angle = Math.atan2(forceY, forceX);
      }

      draw() {
        ctx.save();
        ctx.translate(this.x, this.y);
        ctx.rotate(this.angle);
        ctx.globalAlpha = this.alpha;
        ctx.lineCap = 'round';
        ctx.lineWidth = this.thickness;
        ctx.strokeStyle = this.color;
        
        ctx.beginPath();
        ctx.moveTo(-this.length / 2, 0);
        ctx.lineTo(this.length / 2, 0);
        ctx.stroke();
        ctx.restore();
      }
    }

    function resize() {
      W = canvas.width = window.innerWidth;
      H = canvas.height = window.innerHeight;
      
      var targetParticles = Math.min(2500, Math.floor((W * H) / 900));
      particles = [];
      for (var i = 0; i < targetParticles; i++) {
        particles.push(new Particle());
      }
    }

    function loop() {
      time += 0.005;
      
      // Draw background + soft vignette
      var grd = ctx.createRadialGradient(W/2, H/2, 0, W/2, H/2, Math.max(W, H));
      grd.addColorStop(0, '#ffffff');
      grd.addColorStop(1, '#e0f2fe'); 
      ctx.fillStyle = grd;
      ctx.fillRect(0, 0, W, H);

      // Smooth mouse interpolation for liquid feel
      mouse.x += (targetMouse.x - mouse.x) * 0.1;
      mouse.y += (targetMouse.y - mouse.y) * 0.1;

      for (var i = 0; i < particles.length; i++) {
        particles[i].update();
        particles[i].draw();
      }

      requestAnimationFrame(loop);
    }

    /* ── Events ──────────────────────────────────────────── */
    window.addEventListener('resize', resize);
    document.addEventListener('mousemove', function(e) { 
      targetMouse.x = e.clientX; 
      targetMouse.y = e.clientY; 
    });
    document.addEventListener('mouseleave', function() { 
      targetMouse.x = -1000;
      targetMouse.y = -1000;
    });

    resize();
    requestAnimationFrame(loop);
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
