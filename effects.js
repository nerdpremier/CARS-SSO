/**
 * effects.js — CARS SSO
 * Lightweight effects: button ripple + label focus color
 * No particle system — keeping it clean and fast.
 */
(function () {
  'use strict';

  /* ── Button Ripple ──────────────────────────────────────── */
  function initRipple() {
    function rippleOn(btn, e) {
      var rect = btn.getBoundingClientRect();
      var size = Math.max(rect.width, rect.height) * 2.4;
      var cx   = e && e.clientX != null ? e.clientX : rect.left + rect.width  / 2;
      var cy   = e && e.clientY != null ? e.clientY : rect.top  + rect.height / 2;
      var el   = document.createElement('span');
      el.className = 'ripple-wave';
      el.style.setProperty('--ripple-size', size + 'px');
      el.style.setProperty('--ripple-x', (cx - rect.left - size / 2) + 'px');
      el.style.setProperty('--ripple-y', (cy - rect.top  - size / 2) + 'px');
      btn.appendChild(el);
      setTimeout(function () { el.remove(); }, 600);
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

  /* ── Label Focus Color ──────────────────────────────────── */
  function initLabelFocus() {
    document.querySelectorAll('.field').forEach(function (f) {
      var inp = f.querySelector('input, textarea, select');
      var lbl = f.querySelector('label');
      if (!inp || !lbl) return;
      inp.addEventListener('focus', function () { lbl.style.color = 'var(--accent)'; });
      inp.addEventListener('blur',  function () { lbl.style.color = ''; });
    });
  }

  /* ── Stagger reveal for list items ─────────────────────── */
  function initReveal() {
    var items = document.querySelectorAll('[data-reveal]');
    items.forEach(function (el, i) {
      el.style.animationDelay = (i * 60) + 'ms';
    });
  }

  /* ── Boot ───────────────────────────────────────────────── */
  function boot() {
    initRipple();
    initLabelFocus();
    initReveal();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
}());
