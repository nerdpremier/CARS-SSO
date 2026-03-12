/**
 * effects.js — CARS SSO "Vault"
 * CSP-safe: no element.style assignments, no inline styles.
 * Ripple uses Web Animations API (governed by script-src, not style-src).
 * Stagger delays are handled entirely by CSS nth-child in style.css.
 */
(function () {
  'use strict';

  /* ── Button Ripple (Web Animations API) ─────────────────── */
  function rippleOn(btn, e) {
    var rect = btn.getBoundingClientRect();
    var size = Math.max(rect.width, rect.height) * 2.6;
    var cx   = e && e.clientX != null ? e.clientX - rect.left : rect.width  / 2;
    var cy   = e && e.clientY != null ? e.clientY - rect.top  : rect.height / 2;

    var el = document.createElement('span');
    el.setAttribute('aria-hidden', 'true');
    btn.appendChild(el);

    // Web Animations API is governed by script-src, not style-src — CSP safe
    var anim = el.animate([
      {
        position: 'absolute',
        width:  size + 'px', height: size + 'px',
        left:   (cx - size / 2) + 'px', top: (cy - size / 2) + 'px',
        borderRadius: '50%',
        background: 'rgba(0,0,0,0.18)',
        transform: 'scale(0)', opacity: '1',
        pointerEvents: 'none'
      },
      { transform: 'scale(1)', opacity: '0' }
    ], { duration: 550, easing: 'ease-out', fill: 'forwards' });

    anim.onfinish = function () { el.remove(); };
  }

  document.addEventListener('click', function (e) {
    var btn = e.target.closest('.btn-primary,.btn-secondary,.btn-portal,.btn-signout');
    if (btn) rippleOn(btn, e);
  });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') {
      var el = document.activeElement;
      if (el && el.matches('.btn-primary,.btn-secondary,.btn-portal,.btn-signout')) {
        rippleOn(el, null);
      }
    }
  });

  // Stagger: handled by CSS nth-child in style.css — no JS needed.

}());
