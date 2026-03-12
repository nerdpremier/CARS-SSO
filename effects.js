/**
 * effects.js — CARS SSO
 * 1. Space background: drifting nebulae, parallax star layers, shooting stars, constellations
 * 2. CarsNav page transitions
 * 3. CarsToast notifications
 * 4. Button ripple
 */
(function () {
  'use strict';

  /* ══════════════════════════════════════════════════════════
     1. SPACE CANVAS
     ══════════════════════════════════════════════════════════ */
  (function initCanvas() {
    var canvas = document.createElement('canvas');
    canvas.id = 'bg-canvas';
    canvas.setAttribute('aria-hidden', 'true');
    if (document.body.firstChild) document.body.insertBefore(canvas, document.body.firstChild);
    else document.body.appendChild(canvas);

    var ctx = canvas.getContext('2d');
    var W = 0, H = 0;
    var tick = 0;
    var mouse = { x: W / 2, y: H / 2, tx: W / 2, ty: H / 2 }; // tx/ty = smoothed target

    /* ── Nebulae (drift slowly, parallax with mouse) ─── */
    var NEBULA_DEFS = [
      { rx:.15, ry:.20, r:460, c:[110,60,230],  a:.18, spd:.00016, ang:0.9,  pax:.018 },
      { rx:.80, ry:.18, r:360, c:[30,160,200],  a:.14, spd:.00013, ang:2.1,  pax:.012 },
      { rx:.50, ry:.80, r:400, c:[160,30,200],  a:.13, spd:.00019, ang:4.4,  pax:.015 },
      { rx:.22, ry:.65, r:280, c:[20,100,200],  a:.10, spd:.00015, ang:1.5,  pax:.010 },
      { rx:.72, ry:.50, r:240, c:[60,200,180],  a:.09, spd:.00021, ang:3.3,  pax:.008 },
      { rx:.40, ry:.35, r:200, c:[200,80,150],  a:.07, spd:.00024, ang:5.1,  pax:.006 },
    ];
    var nebulae = [];
    function buildNebulae() {
      nebulae = NEBULA_DEFS.map(function(d) {
        return {
          bx: d.rx * W, by: d.ry * H,  // base position
          x: d.rx * W,  y: d.ry * H,
          r: d.r, c: d.c, a: d.a,
          spd: d.spd, ang: d.ang,       // drift orbit
          orbitR: 18 + Math.random()*24,
          pax: d.pax,                   // parallax strength
        };
      });
    }
    function updateNebulae() {
      var mx = (mouse.x / W - .5), my = (mouse.y / H - .5); // -0.5..0.5
      nebulae.forEach(function(n) {
        n.ang += n.spd;
        n.x = n.bx + Math.cos(n.ang) * n.orbitR - mx * W * n.pax;
        n.y = n.by + Math.sin(n.ang) * n.orbitR * .6 - my * H * n.pax;
      });
    }
    function drawNebulae() {
      nebulae.forEach(function(n) {
        var g = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, n.r);
        var col = n.c[0]+','+n.c[1]+','+n.c[2];
        g.addColorStop(0,  'rgba('+col+','+n.a+')');
        g.addColorStop(.45,'rgba('+col+','+(n.a*.55)+')');
        g.addColorStop(1,  'rgba('+col+',0)');
        ctx.fillStyle = g;
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r, 0, Math.PI*2);
        ctx.fill();
      });
    }

    /* ── Star layers (3 depths, different parallax) ─── */
    function Star(layer) {
      this.layer = layer;
      this.reset();
      this.y = Math.random() * H; // start anywhere
    }
    Star.prototype.reset = function() {
      this.x     = Math.random() * W;
      this.y     = -4;
      // layer 0 = far/tiny, layer 2 = close/big
      var layerT  = this.layer / 2;
      this.size   = .35 + layerT * 1.4 + Math.random() * (.4 + layerT * .6);
      this.baseA  = .2 + layerT * .45 + Math.random() * .25;
      this.alpha  = this.baseA;
      this.twinkSpd = .006 + Math.random() * .014;
      this.phase  = Math.random() * Math.PI * 2;
      this.vy     = .04 + layerT * .16 + Math.random() * .08; // slow drift down
      this.pax    = .004 + layerT * .018;   // parallax depth
      var t = Math.random();
      this.r = t<.3?200:t<.6?230:255;
      this.g = t<.3?210:t<.6?240:255;
      this.b = t<.3?255:t<.6?255:230;
    };
    Star.prototype.update = function(mx, my) {
      this.phase += this.twinkSpd;
      this.alpha  = Math.max(0, this.baseA + Math.sin(this.phase) * this.baseA * .5);
      this.y     += this.vy;
      // parallax offset (near stars move more)
      this.px = this.x - (mx - .5) * W * this.pax;
      this.py = this.y - (my - .5) * H * this.pax * .5;
      if (this.py > H + 4) this.reset();
    };
    Star.prototype.draw = function() {
      ctx.beginPath();
      ctx.arc(this.px, this.py, this.size, 0, Math.PI*2);
      ctx.fillStyle = 'rgba('+this.r+','+this.g+','+this.b+','+this.alpha+')';
      ctx.fill();
      if (this.size > 1.4) {
        var g = ctx.createRadialGradient(this.px, this.py, 0, this.px, this.py, this.size*4);
        g.addColorStop(0, 'rgba('+this.r+','+this.g+','+this.b+','+(this.alpha*.3)+')');
        g.addColorStop(1, 'rgba('+this.r+','+this.g+','+this.b+',0)');
        ctx.fillStyle = g;
        ctx.beginPath();
        ctx.arc(this.px, this.py, this.size*4, 0, Math.PI*2);
        ctx.fill();
      }
    };

    var stars = [];
    function spawnStars() {
      stars = [];
      var total = Math.min(320, Math.floor(W * H / 3800));
      for (var i = 0; i < total; i++) {
        var layer = i < total*.55 ? 0 : i < total*.82 ? 1 : 2;
        stars.push(new Star(layer));
      }
    }

    /* ── Constellation lines ────────────────────────── */
    var CONST_DIST = 85;
    function drawConstellations() {
      var bright = stars.filter(function(s){ return s.size > 1.2 && s.alpha > .3; });
      ctx.lineWidth = .35;
      for (var i = 0; i < bright.length; i++) {
        for (var j = i+1; j < bright.length; j++) {
          var dx = bright[i].px - bright[j].px, dy = bright[i].py - bright[j].py;
          var d = dx*dx + dy*dy;
          if (d < CONST_DIST*CONST_DIST) {
            var a = .065 * (1 - Math.sqrt(d)/CONST_DIST) * Math.min(bright[i].alpha, bright[j].alpha);
            ctx.strokeStyle = 'rgba(160,190,255,'+a+')';
            ctx.beginPath();
            ctx.moveTo(bright[i].px, bright[i].py);
            ctx.lineTo(bright[j].px, bright[j].py);
            ctx.stroke();
          }
        }
      }
    }

    /* ── Shooting stars ─────────────────────────────── */
    var shooters = [];
    function Shooter() {
      this.x    = Math.random() * W * 1.3;
      this.y    = Math.random() * H * .35;
      var ang   = .38 + Math.random() * .32;
      var spd   = 9 + Math.random() * 11;
      this.vx   = Math.cos(ang) * spd;
      this.vy   = Math.sin(ang) * spd;
      this.len  = 70 + Math.random() * 110;
      this.life = 1.0;
      this.fade = .022 + Math.random() * .016;
      this.w    = .7 + Math.random() * 1.1;
    }
    Shooter.prototype.update = function() { this.x+=this.vx; this.y+=this.vy; this.life-=this.fade; };
    Shooter.prototype.draw = function() {
      if (this.life<=0) return;
      var hyp = Math.hypot(this.vx, this.vy);
      var tx = this.x - (this.vx/hyp)*this.len, ty = this.y - (this.vy/hyp)*this.len;
      var g = ctx.createLinearGradient(tx, ty, this.x, this.y);
      g.addColorStop(0,  'rgba(255,255,255,0)');
      g.addColorStop(.6, 'rgba(200,220,255,'+(this.life*.45)+')');
      g.addColorStop(1,  'rgba(255,255,255,'+(this.life*.9)+')');
      ctx.strokeStyle = g; ctx.lineWidth = this.w;
      ctx.beginPath(); ctx.moveTo(tx, ty); ctx.lineTo(this.x, this.y); ctx.stroke();
    };

    /* ── Mouse glow ─────────────────────────────────── */
    function drawMouseGlow() {
      if (mouse.x <= 0) return;
      var g = ctx.createRadialGradient(mouse.x, mouse.y, 0, mouse.x, mouse.y, 260);
      g.addColorStop(0,  'rgba(120,100,255,.09)');
      g.addColorStop(1,  'rgba(100,130,255,0)');
      ctx.fillStyle = g;
      ctx.beginPath(); ctx.arc(mouse.x, mouse.y, 260, 0, Math.PI*2); ctx.fill();
    }

    /* ── Main loop ──────────────────────────────────── */
    function resize() {
      W = canvas.width  = window.innerWidth;
      H = canvas.height = window.innerHeight;
      mouse.x = mouse.tx = W/2; mouse.y = mouse.ty = H/2;
      buildNebulae(); spawnStars();
    }

    function loop() {
      tick++;
      // Smooth mouse
      mouse.x += (mouse.tx - mouse.x) * .06;
      mouse.y += (mouse.ty - mouse.y) * .06;
      var mx = mouse.x / W, my = mouse.y / H;

      ctx.clearRect(0, 0, W, H);
      // soft base gradient: deep indigo at top, near-black at bottom
      var bgGrad = ctx.createLinearGradient(0, 0, 0, H);
      bgGrad.addColorStop(0, '#0d0f26');
      bgGrad.addColorStop(1, '#06080f');
      ctx.fillStyle = bgGrad;
      ctx.fillRect(0, 0, W, H);

      updateNebulae();
      drawNebulae();
      drawMouseGlow();
      drawConstellations();

      for (var i = 0; i < stars.length; i++) { stars[i].update(mx, my); stars[i].draw(); }

      if (Math.random() < .005) shooters.push(new Shooter());
      shooters = shooters.filter(function(s){ s.update(); if(s.life>0){s.draw();return true;}return false; });

      requestAnimationFrame(loop);
    }

    window.addEventListener('resize', resize);
    document.addEventListener('mousemove', function(e){ mouse.tx = e.clientX; mouse.ty = e.clientY; });
    document.addEventListener('mouseleave', function(){ mouse.tx = W/2; mouse.ty = H/2; });

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
    var anim=el.animate([{position:'absolute',width:size+'px',height:size+'px',left:(cx-size/2)+'px',top:(cy-size/2)+'px',borderRadius:'50%',background:'rgba(255,255,255,0.2)',transform:'scale(0)',opacity:'1',pointerEvents:'none'},{transform:'scale(1)',opacity:'0'}],{duration:560,easing:'ease-out',fill:'forwards'});
    anim.onfinish=function(){el.remove();};
  }
  document.addEventListener('click',function(e){var b=e.target.closest('.btn-primary,.btn-portal,.btn-signout,.btn-create');if(b)ripple(b,e);});
  document.addEventListener('keydown',function(e){if(e.key==='Enter'){var el=document.activeElement;if(el&&el.matches('.btn-primary,.btn-portal,.btn-signout,.btn-create'))ripple(el,null);}});

}());
