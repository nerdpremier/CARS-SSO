/**
 * effects.js — Obsidian Signal visual layer
 * Particles: electric blue/cyan streaks drifting upward
 * Parallax: card tilts with mouse
 * Ripple: button click wave
 */
(function () {
  'use strict';

  /* ── Particle canvas ──────────────────────────────────────────── */
  function initParticles() {
    var container = document.getElementById('particles');
    if (!container) return;

    var canvas = document.createElement('canvas');
    canvas.style.cssText = 'position:absolute;inset:0;width:100%;height:100%;';
    container.appendChild(canvas);

    var ctx = canvas.getContext('2d');
    var W, H, pts = [];

    function resize() {
      W = canvas.width  = window.innerWidth;
      H = canvas.height = window.innerHeight;
    }

    function mk() {
      // 3 types: bright signal dots, faint star dots, tiny streaks
      var type = Math.random();
      return {
        x:    Math.random() * W,
        y:    H + 10,
        vx:   (Math.random() - .5) * .35,
        vy:   -(Math.random() * .8 + .25),
        r:    type < .15 ? Math.random() * 2.2 + 1.2      // bright large
            : type < .55 ? Math.random() * 1.2 + .4       // medium
            :              Math.random() * .7  + .2,       // tiny star
        a:    type < .15 ? Math.random() * .55 + .3
            : type < .55 ? Math.random() * .35 + .12
            :              Math.random() * .22 + .06,
        life: 1,
        dec:  Math.random() * .0012 + .0003,
        // Signal blue (195-215 hue), occasional pure white
        h:    Math.random() < .12 ? 0   : Math.floor(Math.random() * 22 + 193),
        s:    Math.random() < .12 ? 0   : Math.floor(Math.random() * 35 + 65),
        white: Math.random() < .12,
      };
    }

    function init() {
      resize();
      pts = [];
      for (var i = 0; i < 72; i++) {
        var p = mk(); p.y = Math.random() * H;
        pts.push(p);
      }
    }

    function frame() {
      ctx.clearRect(0, 0, W, H);
      for (var i = 0; i < pts.length; i++) {
        var p = pts[i];
        p.x += p.vx; p.y += p.vy; p.life -= p.dec;
        if (p.life <= 0 || p.y < -10) { pts[i] = mk(); continue; }

        var alpha = p.a * Math.min(p.life * 3.5, 1);
        var spread = p.r * 4;

        var color0 = p.white
          ? 'hsla(0,0%,100%,'    + alpha + ')'
          : 'hsla(' + p.h + ',' + p.s + '%,92%,' + alpha + ')';
        var color1 = p.white
          ? 'hsla(0,0%,100%,'    + (alpha * .4) + ')'
          : 'hsla(' + p.h + ',' + p.s + '%,70%,' + (alpha * .4) + ')';

        var g = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, spread);
        g.addColorStop(0,   color0);
        g.addColorStop(.45, color1);
        g.addColorStop(1,   'hsla(0,0%,0%,0)');

        ctx.beginPath();
        ctx.arc(p.x, p.y, spread, 0, Math.PI * 2);
        ctx.fillStyle = g;
        ctx.fill();
      }
      requestAnimationFrame(frame);
    }

    window.addEventListener('resize', init);
    init(); frame();
  }
  
  /* ── Button ripple ────────────────────────────────────────────── */
  function initRipple() {
    // @keyframes ripple and .ripple-wave styles are defined in style.css

    document.querySelectorAll('.btn-primary').forEach(function (btn) {
      btn.addEventListener('click', function (e) {
        triggerLoading(btn, e);
      });
    });

    // Enter key on focused button
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') {
        var active = document.activeElement;
        if (active && active.classList.contains('btn-primary')) {
          triggerLoading(active, e);
        }
      }
    });

    // (ลบส่วน Form Submit กับ MutationObserver ออกไปแล้ว ให้ script.js จัดการแทน)
  }

  function setLoading(btn, on) {
    if (on) {
      btn.classList.add('btn--loading');
      btn._origText = btn._origText || btn.textContent;
      btn.textContent = '';           // text hidden behind spinner
    } else {
      btn.classList.remove('btn--loading');
      if (btn._origText) btn.textContent = btn._origText;
    }
  }

  function triggerLoading(btn, e) {
    // ripple wave
    var rect = btn.getBoundingClientRect();
    var size = Math.max(rect.width, rect.height) * 2.4;
    var el   = document.createElement('span');
    el.className = 'ripple-wave';
    el.style.setProperty('--ripple-size', size + 'px');
    var cx = (e && e.clientX != null) ? e.clientX : rect.left + rect.width / 2;
    var cy = (e && e.clientY != null) ? e.clientY : rect.top  + rect.height / 2;
    el.style.setProperty('--ripple-x', (cx - rect.left - size / 2) + 'px');
    el.style.setProperty('--ripple-y', (cy - rect.top  - size / 2) + 'px');
    btn.appendChild(el);
    setTimeout(function () { el.remove(); }, 700);
  }

  /* ── Card parallax tilt ───────────────────────────────────────── */
  function initParallax() {
    var card = document.querySelector('.card');
    if (!card) return;
    var bounds, cx, cy;

    function update(x, y) {
      var rx = ((y - cy) / bounds.height) * 10;
      var ry = ((x - cx) / bounds.width)  * -10;
      card.style.transform = 'perspective(800px) rotateX(' + rx + 'deg) rotateY(' + ry + 'deg)';
    }

    window.addEventListener('mousemove', function (e) {
      bounds = card.getBoundingClientRect();
      cx = bounds.left + bounds.width  / 2;
      cy = bounds.top  + bounds.height / 2;
      update(e.clientX, e.clientY);
    });

    window.addEventListener('mouseleave', function () {
      card.style.transform = '';
    });
  }

  /* ── Running light border ─────────────────────────────────────── */
  function initRunningLight() {
    var glows = document.querySelectorAll('.card-glow');
    if (!glows.length) return;

    var spinners = [];
    for (var i = 0; i < glows.length; i++) {
      // spinner — the rotating gradient div
      var spinner = document.createElement('div');
      spinner.className = 'card-glow-spinner';
      glows[i].appendChild(spinner);

      // mask — white fill that hides the interior
      var mask = document.createElement('div');
      mask.className = 'card-glow-mask';
      glows[i].appendChild(mask);

      spinners.push(spinner);
    }

    var angle = 0;
    // 0.072 deg/frame @ 60fps ≈ 360deg / 5s
    function tick() {
      angle = (angle + 0.12) % 360;
      var t = 'rotate(' + angle + 'deg)';
      for (var i = 0; i < spinners.length; i++) {
        spinners[i].style.transform = t;
      }
      requestAnimationFrame(tick);
    }
    tick();
  }


  function initLabelFocus() {
    document.querySelectorAll('.field').forEach(function (f) {
      var inp = f.querySelector('input');
      var lbl = f.querySelector('label');
      if (!inp || !lbl) return;
      inp.addEventListener('focus', function () { lbl.style.color = 'var(--signal)'; });
      inp.addEventListener('blur',  function () { lbl.style.color = ''; });
    });
  }

  function boot() {
    initParticles();
    initParallax();
    initRipple();
    initLabelFocus();
    initRunningLight();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
}());