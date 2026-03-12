/**
 * effects.js — CARS SSO (Light Theme)
 * Background: soft gradient orbs + mouse-driven ripple waves + SSO node network
 * No dot grid — replaced with fluid concentric wave rings on mouse move
 */
(function () {
  'use strict';

  /* ══════════════════════════════════════════════════════════
     1. INTERACTIVE CANVAS
     ══════════════════════════════════════════════════════════ */
  (function initCanvas() {
    var canvas = document.createElement('canvas');
    canvas.id = 'bg-canvas';
    canvas.setAttribute('aria-hidden', 'true');
    document.body.insertBefore(canvas, document.body.firstChild);

    var ctx = canvas.getContext('2d');
    var W = 0, H = 0, tick = 0;

    /* ── Smoothed mouse ──────────────────────────────────── */
    var mouse  = { rx: -9999, ry: -9999, x: -9999, y: -9999 };
    //  rx/ry = raw,  x/y = smoothed

    /* ── Click / mouse-stop ripples ─────────────────────── */
    var ripples = [];   // { x, y, r, maxR, born, type:'click'|'idle' }
    var idleTimer = null;
    var lastMoveTime = 0;

    function spawnRipple(x, y, type) {
      ripples.push({ x: x, y: y, r: 0, maxR: type === 'click' ? 260 : 180,
                     born: Date.now(), type: type });
    }

    /* ── Colour palette ──────────────────────────────────── */
    var C = {
      blue:   [79,  110, 247],
      indigo: [109,  68, 234],
      teal:   [ 14, 164, 114],
      violet: [155,  48, 220],
    };

    /* ═══════════════════════════════════════════════════════
       SOFT BACKGROUND ORBS (parallax)
       ═══════════════════════════════════════════════════════ */
    var ORB_DEFS = [
      { rx:.10, ry:.14, r:480, c:C.blue,   a:.075, spd:.00016, ang:1.2, orR:34, px:.022 },
      { rx:.88, ry:.16, r:400, c:C.indigo, a:.060, spd:.00012, ang:3.0, orR:28, px:.016 },
      { rx:.52, ry:.90, r:440, c:C.teal,   a:.060, spd:.00019, ang:5.1, orR:30, px:.018 },
      { rx:.18, ry:.74, r:300, c:C.violet, a:.048, spd:.00014, ang:2.4, orR:22, px:.011 },
      { rx:.80, ry:.56, r:260, c:C.blue,   a:.042, spd:.00021, ang:4.0, orR:20, px:.009 },
    ];
    var orbs = [];
    function buildOrbs() {
      orbs = ORB_DEFS.map(function(d) {
        return { bx:d.rx*W, by:d.ry*H, x:0, y:0, r:d.r, c:d.c, a:d.a,
                 spd:d.spd, ang:d.ang, orR:d.orR, px:d.px };
      });
    }
    function updateOrbs() {
      var mx = (mouse.x - W*.5) / (W || 1);
      var my = (mouse.y - H*.5) / (H || 1);
      orbs.forEach(function(o) {
        o.ang += o.spd;
        o.x = o.bx + Math.cos(o.ang)*o.orR - mx*W*o.px;
        o.y = o.by + Math.sin(o.ang)*o.orR*.7 - my*H*o.px*.5;
      });
    }
    function drawOrbs() {
      orbs.forEach(function(o) {
        var g = ctx.createRadialGradient(o.x, o.y, 0, o.x, o.y, o.r);
        var col = o.c.join(',');
        g.addColorStop(0,   'rgba('+col+','+o.a+')');
        g.addColorStop(.45, 'rgba('+col+','+(o.a*.42)+')');
        g.addColorStop(1,   'rgba('+col+',0)');
        ctx.fillStyle = g;
        ctx.beginPath(); ctx.arc(o.x, o.y, o.r, 0, Math.PI*2); ctx.fill();
      });
    }

    /* ═══════════════════════════════════════════════════════
       WAVE RIPPLE RINGS — core visual effect
       Each ripple is a set of concentric rings that fade out.
       Mouse movement continuously spawns them; clicks spawn larger ones.
       ═══════════════════════════════════════════════════════ */
    var WAVE_SPEED     = 1.8;   // px per frame expansion
    var WAVE_SPACING   = 38;    // px between rings in one ripple
    var WAVE_RINGS     = 4;     // rings per ripple
    var WAVE_DURATION  = 2200;  // ms total life

    function drawRipples() {
      var now = Date.now();
      for (var i = ripples.length - 1; i >= 0; i--) {
        var rp  = ripples[i];
        var age = (now - rp.born) / WAVE_DURATION;  // 0..1
        if (age >= 1) { ripples.splice(i, 1); continue; }

        // outer radius expands linearly
        rp.r = age * rp.maxR;

        var isClick = rp.type === 'click';
        var rings   = isClick ? 5 : WAVE_RINGS;
        var col     = isClick ? C.indigo : C.blue;
        var colStr  = col.join(',');

        for (var k = 0; k < rings; k++) {
          var ringR = rp.r - k * WAVE_SPACING;
          if (ringR <= 0) continue;

          // alpha: fade in quickly, fade out slowly, also fade per ring index
          var ringAge   = 1 - k / rings;
          var fadeIn    = Math.min(1, age * 8);
          var fadeOut   = 1 - age;
          var baseAlpha = isClick ? .18 : .12;
          var alpha     = baseAlpha * ringAge * fadeIn * fadeOut * fadeOut;

          ctx.beginPath();
          ctx.arc(rp.x, rp.y, ringR, 0, Math.PI * 2);
          ctx.strokeStyle = 'rgba(' + colStr + ',' + alpha + ')';
          ctx.lineWidth   = isClick ? 1.6 - k * .22 : 1.1 - k * .18;
          ctx.stroke();
        }

        // soft filled glow at origin
        if (age < .4) {
          var glowR = rp.r * .45;
          var g = ctx.createRadialGradient(rp.x, rp.y, 0, rp.x, rp.y, glowR);
          var ga = (isClick ? .06 : .04) * (1 - age/.4);
          g.addColorStop(0, 'rgba('+col.join(',')+','+ga+')');
          g.addColorStop(1, 'rgba('+col.join(',')+',0)');
          ctx.fillStyle = g;
          ctx.beginPath(); ctx.arc(rp.x, rp.y, glowR, 0, Math.PI*2); ctx.fill();
        }
      }
    }

    /* Mouse-move continuous ripple: spawn one every ~90ms while moving */
    var lastRippleTime = 0;
    var lastRippleX = -999, lastRippleY = -999;

    function maybeSpawnMoveRipple() {
      if (mouse.rx < 0) return;
      var now  = Date.now();
      var dist = Math.hypot(mouse.rx - lastRippleX, mouse.ry - lastRippleY);
      if (now - lastRippleTime > 90 && dist > 20) {
        spawnRipple(mouse.rx, mouse.ry, 'move');
        lastRippleTime = now;
        lastRippleX = mouse.rx;
        lastRippleY = mouse.ry;
      }
      // idle: if mouse hasn't moved for 2s, spawn a pulse where it sits
      if (now - lastMoveTime > 2000 && now - lastRippleTime > 1800 && mouse.rx > 0) {
        spawnRipple(mouse.rx, mouse.ry, 'idle');
        lastRippleTime = now;
      }
    }

    /* ═══════════════════════════════════════════════════════
       SSO NODE NETWORK — nodes drift and connect with lines
       ═══════════════════════════════════════════════════════ */
    function Node() { this.reset(true); }
    Node.prototype.reset = function(anywhere) {
      this.x     = Math.random() * W;
      this.y     = anywhere ? Math.random() * H : -20;
      this.vx    = (Math.random() - .5) * .35;
      this.vy    = anywhere ? (Math.random() - .5) * .35 : .24 + Math.random() * .32;
      this.r     = 3 + Math.random() * 5;
      this.baseA = .20 + Math.random() * .38;
      this.alpha = this.baseA;
      this.phase = Math.random() * Math.PI * 2;
      this.spd   = .006 + Math.random() * .011;
      var t = Math.random();
      this.c   = t < .45 ? C.blue : t < .72 ? C.indigo : C.teal;
      this.col = this.c.join(',');
    };
    Node.prototype.update = function() {
      this.phase += this.spd;
      this.alpha  = this.baseA + Math.sin(this.phase) * this.baseA * .22;

      // gentle attraction toward mouse
      var dx = mouse.x - this.x, dy = mouse.y - this.y;
      var d  = Math.sqrt(dx*dx + dy*dy);
      if (d < 180 && d > 1) {
        var f = (180 - d) / 180 * .010;
        this.vx += (dx/d) * f;
        this.vy += (dy/d) * f;
      }

      // push away from ripple wavefronts
      for (var i = 0; i < ripples.length; i++) {
        var rp  = ripples[i]; if (rp.type !== 'click') continue;
        var ndx = this.x - rp.x, ndy = this.y - rp.y;
        var nd  = Math.sqrt(ndx*ndx + ndy*ndy);
        if (Math.abs(nd - rp.r) < 50 && nd > 1) {
          var push = (1 - Math.abs(nd - rp.r)/50) * 1.8;
          this.vx += (ndx/nd) * push;
          this.vy += (ndy/nd) * push;
        }
      }

      this.vx += (Math.random() - .5) * .03;
      this.vy += (Math.random() - .5) * .03;
      this.vx *= .96; this.vy *= .96;
      var spd = Math.hypot(this.vx, this.vy);
      if (spd > 3) { this.vx = this.vx/spd*3; this.vy = this.vy/spd*3; }

      this.x += this.vx; this.y += this.vy;

      if (this.x < -30) this.x = W + 10;
      if (this.x > W+30) this.x = -10;
      if (this.y < -30) this.y = H + 10;
      if (this.y > H+30) this.y = -10;
    };
    Node.prototype.draw = function() {
      var g = ctx.createRadialGradient(this.x, this.y, 0, this.x, this.y, this.r*4);
      g.addColorStop(0, 'rgba('+this.col+','+(this.alpha*.18)+')');
      g.addColorStop(1, 'rgba('+this.col+',0)');
      ctx.fillStyle = g;
      ctx.beginPath(); ctx.arc(this.x, this.y, this.r*4, 0, Math.PI*2); ctx.fill();
      ctx.fillStyle = 'rgba('+this.col+','+this.alpha+')';
      ctx.beginPath(); ctx.arc(this.x, this.y, this.r, 0, Math.PI*2); ctx.fill();
    };

    var CONNECT_DIST = 125;
    function drawConnections(nodes) {
      for (var i = 0; i < nodes.length; i++) {
        for (var j = i+1; j < nodes.length; j++) {
          var dx = nodes[i].x - nodes[j].x, dy = nodes[i].y - nodes[j].y;
          var d  = Math.sqrt(dx*dx + dy*dy);
          if (d < CONNECT_DIST) {
            var mx2 = (nodes[i].x + nodes[j].x)*.5;
            var my2 = (nodes[i].y + nodes[j].y)*.5;
            var md  = Math.hypot(mx2 - mouse.x, my2 - mouse.y);
            var mb  = md < 150 ? (1 - md/150) * .22 : 0;
            var a   = (.11 + mb) * (1 - d/CONNECT_DIST) * Math.min(nodes[i].alpha, nodes[j].alpha);
            ctx.strokeStyle = 'rgba(79,110,247,'+a+')';
            ctx.lineWidth   = .75 + mb;
            ctx.beginPath();
            ctx.moveTo(nodes[i].x, nodes[i].y);
            ctx.lineTo(nodes[j].x, nodes[j].y);
            ctx.stroke();
          }
        }
      }
    }

    /* ── Mouse glow ──────────────────────────────────────── */
    function drawMouseGlow() {
      if (mouse.x < 0) return;
      var g = ctx.createRadialGradient(mouse.x, mouse.y, 0, mouse.x, mouse.y, 190);
      g.addColorStop(0,  'rgba(79,110,247,.048)');
      g.addColorStop(.5, 'rgba(109,68,234,.020)');
      g.addColorStop(1,  'rgba(79,110,247,0)');
      ctx.fillStyle = g;
      ctx.beginPath(); ctx.arc(mouse.x, mouse.y, 190, 0, Math.PI*2); ctx.fill();
    }

    /* ── Spawn & resize ──────────────────────────────────── */
    var nodes = [];
    function spawnNodes() {
      nodes = [];
      var count = Math.min(55, Math.floor(W * H / 15000));
      for (var i = 0; i < count; i++) nodes.push(new Node());
    }
    function resize() {
      W = canvas.width  = window.innerWidth;
      H = canvas.height = window.innerHeight;
      mouse.x = W*.5; mouse.y = H*.5;
      buildOrbs(); spawnNodes();
    }

    /* ── Main loop ───────────────────────────────────────── */
    function loop() {
      tick++;
      // smooth mouse
      mouse.x += (mouse.rx - mouse.x) * .09;
      mouse.y += (mouse.ry - mouse.y) * .09;

      maybeSpawnMoveRipple();

      ctx.clearRect(0, 0, W, H);
      // Base gradient
      var bg = ctx.createLinearGradient(0, 0, W*.6, H);
      bg.addColorStop(0,  '#F5F8FE');
      bg.addColorStop(.5, '#EEF3FF');
      bg.addColorStop(1,  '#F2F6FB');
      ctx.fillStyle = bg; ctx.fillRect(0, 0, W, H);

      updateOrbs();
      drawOrbs();
      drawMouseGlow();
      drawRipples();
      drawConnections(nodes);
      for (var i = 0; i < nodes.length; i++) nodes[i].update(), nodes[i].draw();

      requestAnimationFrame(loop);
    }

    /* ── Events ──────────────────────────────────────────── */
    window.addEventListener('resize', resize);

    document.addEventListener('mousemove', function(e) {
      mouse.rx = e.clientX; mouse.ry = e.clientY;
      lastMoveTime = Date.now();
    });
    document.addEventListener('mouseleave', function() {
      mouse.rx = W*.5; mouse.ry = H*.5;
    });
    document.addEventListener('click', function(e) {
      if (e.target.closest('a,button,input,select,textarea,label')) return;
      spawnRipple(e.clientX, e.clientY, 'click');
    });

    resize(); loop();
  })();


  /* ══════════════════════════════════════════════════════════
     2. PAGE TRANSITIONS
     ══════════════════════════════════════════════════════════ */
  window.CarsNav = {
    go: function(url, replace) {
      document.body.classList.add('page-exit');
      setTimeout(function(){ if(replace) window.location.replace(url); else window.location.href=url; }, 260);
    }
  };
  document.addEventListener('click', function(e) {
    var a = e.target.closest('a[href]'); if(!a) return;
    var href = a.getAttribute('href');
    if(!href||href.startsWith('#')||href.startsWith('http')||href.startsWith('mailto:')||href.startsWith('tel:')) return;
    if(e.ctrlKey||e.metaKey||e.shiftKey||e.altKey) return;
    e.preventDefault(); CarsNav.go(href);
  });


  /* ══════════════════════════════════════════════════════════
     3. TOAST SYSTEM
     ══════════════════════════════════════════════════════════ */
  var _tc = null;
  function getTC() {
    if(!_tc){ _tc=document.createElement('div'); _tc.className='toast-container'; _tc.setAttribute('aria-live','polite'); document.body.appendChild(_tc); }
    return _tc;
  }
  var ICONS = { success:'✅', danger:'⚠️', warning:'🔔', info:'ℹ️' };
  window.CarsToast = function(opts) {
    var type=opts.type||'info', dur=opts.duration!=null?opts.duration:4000;
    var t=document.createElement('div'); t.className='toast toast--'+type; t.setAttribute('role','alert');
    var ic=document.createElement('span'); ic.className='toast-icon'; ic.setAttribute('aria-hidden','true'); ic.textContent=ICONS[type]||'ℹ️';
    var bd=document.createElement('div'); bd.className='toast-body';
    if(opts.title){var tt=document.createElement('div');tt.className='toast-title';tt.textContent=opts.title;bd.appendChild(tt);}
    var mm=document.createElement('div'); mm.className='toast-msg'; mm.textContent=opts.msg; bd.appendChild(mm);
    var cl=document.createElement('button'); cl.className='toast-close'; cl.setAttribute('aria-label','Dismiss'); cl.textContent='×';
    var pr=document.createElement('div'); pr.className='toast-progress';
    t.appendChild(ic); t.appendChild(bd); t.appendChild(cl); t.appendChild(pr); getTC().appendChild(t);
    var timer=null;
    function dismiss(){ clearTimeout(timer); t.classList.add('toast--exit'); setTimeout(function(){if(t.parentNode)t.parentNode.removeChild(t);},260); }
    cl.addEventListener('click',dismiss);
    if(dur>0){ timer=setTimeout(dismiss,dur); t.addEventListener('mouseenter',function(){clearTimeout(timer);}); t.addEventListener('mouseleave',function(){timer=setTimeout(dismiss,1500);}); }
    return {dismiss:dismiss};
  };


  /* ══════════════════════════════════════════════════════════
     4. BUTTON RIPPLE
     ══════════════════════════════════════════════════════════ */
  function ripple(btn, e) {
    var rect=btn.getBoundingClientRect(), size=Math.max(rect.width,rect.height)*2.6;
    var cx=e&&e.clientX!=null?e.clientX-rect.left:rect.width/2, cy=e&&e.clientY!=null?e.clientY-rect.top:rect.height/2;
    var el=document.createElement('span'); el.setAttribute('aria-hidden','true'); btn.appendChild(el);
    var anim=el.animate([
      {position:'absolute',width:size+'px',height:size+'px',left:(cx-size/2)+'px',top:(cy-size/2)+'px',
       borderRadius:'50%',background:'rgba(255,255,255,0.28)',transform:'scale(0)',opacity:'1',pointerEvents:'none'},
      {transform:'scale(1)',opacity:'0'}
    ],{duration:560,easing:'ease-out',fill:'forwards'});
    anim.onfinish=function(){el.remove();};
  }
  document.addEventListener('click',function(e){var b=e.target.closest('.btn-primary,.btn-portal,.btn-signout,.btn-create');if(b)ripple(b,e);});
  document.addEventListener('keydown',function(e){if(e.key==='Enter'){var el=document.activeElement;if(el&&el.matches('.btn-primary,.btn-portal,.btn-signout,.btn-create'))ripple(el,null);}});

}());
