/**
 * effects.js — CARS SSO · Obsidian Signal Premium
 * - Particles: layered electric streaks + depth fog
 * - Running light border on .card-glow
 * - Card parallax tilt
 * - Button ripple
 * - Input label focus color
 */
(function () {
  'use strict';

  /* ── Particle System ──────────────────────────────────────── */
  function initParticles() {
    var container = document.getElementById('particles');
    if (!container) return;

    var canvas = document.createElement('canvas');
    canvas.style.cssText = 'position:absolute;inset:0;width:100%;height:100%;';
    container.appendChild(canvas);

    var ctx = canvas.getContext('2d');
    var W, H, pts = [];
    var PARTICLE_COUNT = 88;

    function resize() {
      W = canvas.width  = window.innerWidth;
      H = canvas.height = window.innerHeight;
    }

    function mkParticle(fromBottom) {
      var roll = Math.random();
      // 4 types: signal streak · star dot · fog orb · spark
      var isStreak = roll < .10;
      var isFog    = roll < .25 && roll >= .10;
      var isSpark  = roll < .35 && roll >= .25;

      var depth = Math.random(); // 0 = far, 1 = near
      var speed = depth * .65 + .15;

      return {
        x:    Math.random() * W,
        y:    fromBottom ? H + Math.random() * 80 : Math.random() * H,
        vx:   (Math.random() - .5) * .3 * depth,
        vy:   -(speed * (isStreak ? 1.6 : isFog ? .4 : .9)),
        // size
        r: isStreak ? Math.random() * 1.5 + .5
         : isFog    ? Math.random() * 36 + 16
         : isSpark  ? Math.random() * 2.5 + 1
         :            Math.random() * 1.4 + .35,
        // alpha
        a: isStreak ? Math.random() * .5 + .25
         : isFog    ? Math.random() * .04 + .01
         : isSpark  ? Math.random() * .65 + .3
         :            Math.random() * .3  + .08,
        life: 1,
        dec:  isStreak ? .0008 + Math.random() * .0008
            : isFog    ? .0003 + Math.random() * .0004
            :            .0005 + Math.random() * .001,
        // hue: signal blue 195–215, occasional pure white
        hue:  Math.random() < .08 ? -1 : Math.floor(Math.random() * 22 + 192),
        sat:  Math.floor(Math.random() * 30 + 70),
        type: isStreak ? 'streak' : isFog ? 'fog' : isSpark ? 'spark' : 'dot',
        // streak length
        len:  isStreak ? Math.random() * 18 + 6 : 0,
        depth: depth,
      };
    }

    function init() {
      resize();
      pts = [];
      for (var i = 0; i < PARTICLE_COUNT; i++) pts.push(mkParticle(false));
    }

    function drawDot(p, alpha) {
      var spread = p.r * (p.type === 'spark' ? 3 : 4.5);
      var color0 = p.hue < 0
        ? 'hsla(0,0%,100%,' + alpha + ')'
        : 'hsla(' + p.hue + ',' + p.sat + '%,92%,' + alpha + ')';
      var color1 = p.hue < 0
        ? 'hsla(0,0%,100%,' + (alpha * .35) + ')'
        : 'hsla(' + p.hue + ',' + p.sat + '%,70%,' + (alpha * .35) + ')';

      var g = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, spread);
      g.addColorStop(0,   color0);
      g.addColorStop(.5,  color1);
      g.addColorStop(1,   'hsla(0,0%,0%,0)');
      ctx.beginPath();
      ctx.arc(p.x, p.y, spread, 0, Math.PI * 2);
      ctx.fillStyle = g;
      ctx.fill();
    }

    function drawStreak(p, alpha) {
      var a0 = p.hue < 0
        ? 'hsla(0,0%,100%,' + alpha + ')'
        : 'hsla(' + p.hue + ',' + p.sat + '%,95%,' + alpha + ')';
      var a1 = 'hsla(0,0%,0%,0)';

      var gx = ctx.createLinearGradient(p.x, p.y, p.x + p.vx * p.len, p.y - p.len);
      gx.addColorStop(0,   a1);
      gx.addColorStop(.3,  a0);
      gx.addColorStop(1,   a1);

      ctx.beginPath();
      ctx.moveTo(p.x, p.y);
      ctx.lineTo(p.x - p.vx * p.len * 2, p.y + p.len);
      ctx.strokeStyle = gx;
      ctx.lineWidth = p.r * 1.2;
      ctx.lineCap = 'round';
      ctx.stroke();
    }

    function drawFog(p, alpha) {
      var g = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, p.r);
      var col = p.hue < 0
        ? 'hsla(0,0%,100%,' + alpha + ')'
        : 'hsla(' + p.hue + ',' + (p.sat - 30) + '%,80%,' + alpha + ')';
      g.addColorStop(0, col);
      g.addColorStop(1, 'hsla(0,0%,0%,0)');
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = g;
      ctx.fill();
    }

    function frame() {
      ctx.clearRect(0, 0, W, H);

      for (var i = 0; i < pts.length; i++) {
        var p = pts[i];
        p.x += p.vx; p.y += p.vy;
        p.life -= p.dec;

        if (p.life <= 0 || p.y < -p.r - p.len - 40) {
          pts[i] = mkParticle(true);
          continue;
        }

        var fadeIn  = Math.min(p.life * 5, 1);
        var alpha   = p.a * fadeIn;

        if (p.type === 'fog')    drawFog(p, alpha);
        else if (p.type === 'streak') drawStreak(p, alpha);
        else                     drawDot(p, alpha);
      }
      requestAnimationFrame(frame);
    }

    window.addEventListener('resize', init, { passive: true });
    init(); frame();
  }

  /* ── Running Light Border ──────────────────────────────────── */
  function initRunningLight() {
    var glows = document.querySelectorAll('.card-glow');
    if (!glows.length) return;

    var spinners = [];
    for (var i = 0; i < glows.length; i++) {
      var spinner = document.createElement('div');
      spinner.className = 'card-glow-spinner';
      spinner.style.cssText = [
        'position:absolute',
        'width:200%;height:200%',
        'top:-50%;left:-50%',
        'background:conic-gradient(' +
          'from 0deg,' +
          'transparent 0deg,' +
          'rgba(0,200,255,0) 8deg,' +
          '#00e5ff 55deg,' +
          '#ffffff 90deg,' +
          '#3B82F6 130deg,' +
          'rgba(59,130,246,0) 285deg,' +
          'transparent 360deg)',
        'will-change:transform',
      ].join(';');

      var mask = document.createElement('div');
      mask.className = 'card-glow-mask';

      glows[i].appendChild(spinner);
      glows[i].appendChild(mask);
      spinners.push(spinner);
    }

    var angle = 0;
    function tick() {
      angle = (angle + 0.14) % 360;
      var t = 'rotate(' + angle + 'deg)';
      for (var j = 0; j < spinners.length; j++) {
        spinners[j].style.transform = t;
      }
      requestAnimationFrame(tick);
    }
    tick();
  }

  /* ── Card Parallax Tilt ────────────────────────────────────── */
  function initParallax() {
    var card = document.querySelector('.card');
    if (!card || window.matchMedia('(max-width:600px)').matches) return;

    var raf, bounds;

    window.addEventListener('mousemove', function (e) {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(function () {
        bounds = card.getBoundingClientRect();
        var cx = bounds.left + bounds.width  / 2;
        var cy = bounds.top  + bounds.height / 2;
        var rx = ((e.clientY - cy) / bounds.height) *  8;
        var ry = ((e.clientX - cx) / bounds.width)  * -8;
        card.style.transform = 'perspective(900px) rotateX(' + rx + 'deg) rotateY(' + ry + 'deg)';
      });
    });

    window.addEventListener('mouseleave', function () {
      cancelAnimationFrame(raf);
      card.style.transform = '';
    });
  }

  /* ── Button Ripple ─────────────────────────────────────────── */
  function initRipple() {
    function rippleOn(btn, e) {
      var rect = btn.getBoundingClientRect();
      var size = Math.max(rect.width, rect.height) * 2.5;
      var cx   = e && e.clientX != null ? e.clientX : rect.left + rect.width  / 2;
      var cy   = e && e.clientY != null ? e.clientY : rect.top  + rect.height / 2;
      var el   = document.createElement('span');
      el.className = 'ripple-wave';
      el.style.setProperty('--ripple-size', size + 'px');
      el.style.setProperty('--ripple-x', (cx - rect.left - size / 2) + 'px');
      el.style.setProperty('--ripple-y', (cy - rect.top  - size / 2) + 'px');
      btn.appendChild(el);
      setTimeout(function () { el.remove(); }, 700);
    }

    document.addEventListener('click', function (e) {
      var btn = e.target.closest('.btn-primary, .btn-secondary');
      if (btn) rippleOn(btn, e);
    });

    document.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') {
        var el = document.activeElement;
        if (el && (el.classList.contains('btn-primary') || el.classList.contains('btn-secondary'))) {
          rippleOn(el, null);
        }
      }
    });
  }

  /* ── Label Focus Color ─────────────────────────────────────── */
  function initLabelFocus() {
    document.querySelectorAll('.field').forEach(function (f) {
      var inp = f.querySelector('input, textarea, select');
      var lbl = f.querySelector('label');
      if (!inp || !lbl) return;
      inp.addEventListener('focus', function () { lbl.style.color = 'var(--signal)'; });
      inp.addEventListener('blur',  function () { lbl.style.color = ''; });
    });
  }

  /* ── Boot ──────────────────────────────────────────────────── */
  function boot() {
    initParticles();
    initRunningLight();
    initParallax();
    initRipple();
    initLabelFocus();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
}());
