/**
 * effects.js — CARS SSO (Light Theme)
 * 1. Light background: soft gradient orbs, dot grid, floating SSO node network
 * 2. CarsNav page transitions
 * 3. CarsToast notifications
 * 4. Button ripple
 */
(function () {
  'use strict';

  /* ══════════════════════════════════════════════════════════
     1. LIGHT CANVAS — soft orbs + dot grid + SSO node network
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
    var mouse = { x: -999, y: -999, tx: -999, ty: -999 };

    /* ── Palette ─────────────────────────────────────────── */
    var BLUE   = [79, 110, 247];
    var INDIGO = [120, 80, 240];
    var TEAL   = [14, 164, 114];
    var VIOLET = [150, 60, 220];

    /* ── Soft background orbs ────────────────────────────── */
    var ORB_DEFS = [
      { rx: .12, ry: .18, r: 400, c: BLUE,   a: .08, spd: .00018, ang: 1.2, orbitR: 30 },
      { rx: .86, ry: .20, r: 340, c: INDIGO, a: .07, spd: .00013, ang: 3.0, orbitR: 24 },
      { rx: .50, ry: .88, r: 360, c: TEAL,   a: .07, spd: .00020, ang: 5.1, orbitR: 28 },
      { rx: .22, ry: .68, r: 250, c: VIOLET, a: .05, spd: .00015, ang: 2.4, orbitR: 20 },
      { rx: .80, ry: .62, r: 210, c: BLUE,   a: .05, spd: .00022, ang: 4.0, orbitR: 18 },
    ];
    var orbs = [];
    function buildOrbs() {
      orbs = ORB_DEFS.map(function(d) {
        return { bx: d.rx*W, by: d.ry*H, x: d.rx*W, y: d.ry*H, r: d.r, c: d.c, a: d.a, spd: d.spd, ang: d.ang, orbitR: d.orbitR };
      });
    }
    function updateOrbs() {
      orbs.forEach(function(o) {
        o.ang += o.spd;
        o.x = o.bx + Math.cos(o.ang) * o.orbitR;
        o.y = o.by + Math.sin(o.ang) * o.orbitR * .7;
      });
    }
    function drawOrbs() {
      orbs.forEach(function(o) {
        var g = ctx.createRadialGradient(o.x, o.y, 0, o.x, o.y, o.r);
        var col = o.c[0]+','+o.c[1]+','+o.c[2];
        g.addColorStop(0,   'rgba('+col+','+o.a+')');
        g.addColorStop(.5,  'rgba('+col+','+(o.a*.45)+')');
        g.addColorStop(1,   'rgba('+col+',0)');
        ctx.fillStyle = g;
        ctx.beginPath(); ctx.arc(o.x, o.y, o.r, 0, Math.PI*2); ctx.fill();
      });
    }

    /* ── Subtle dot grid ─────────────────────────────────── */
    var DOT_GAP = 38;
    function drawDotGrid() {
      var cols = Math.ceil(W / DOT_GAP) + 1;
      var rows = Math.ceil(H / DOT_GAP) + 1;
      for (var r = 0; r < rows; r++) {
        for (var c = 0; c < cols; c++) {
          var x = c * DOT_GAP, y = r * DOT_GAP;
          var dx = x - mouse.x, dy = y - mouse.y;
          var dist = Math.sqrt(dx*dx + dy*dy);
          var boost = dist < 100 ? (1 - dist/100) * .10 : 0;
          ctx.fillStyle = 'rgba(79,110,247,' + (.07 + boost) + ')';
          ctx.beginPath(); ctx.arc(x, y, 1.3, 0, Math.PI*2); ctx.fill();
        }
      }
    }

    /* ── SSO Nodes ───────────────────────────────────────── */
    function Node() { this.reset(); this.y = Math.random() * H; }
    Node.prototype.reset = function() {
      this.x     = Math.random() * W;
      this.y     = -20;
      this.r     = 3.5 + Math.random() * 5.5;
      this.vx    = (Math.random() - .5) * .28;
      this.vy    = .22 + Math.random() * .32;
      this.baseA = .28 + Math.random() * .38;
      this.alpha = this.baseA;
      this.phase = Math.random() * Math.PI * 2;
      this.spd   = .007 + Math.random() * .011;
      var t = Math.random();
      this.c = t < .45 ? BLUE : t < .72 ? INDIGO : TEAL;
    };
    Node.prototype.update = function() {
      this.phase += this.spd;
      this.x += this.vx + Math.sin(this.phase * .6) * .35;
      this.y += this.vy;
      this.alpha = this.baseA + Math.sin(this.phase) * this.baseA * .28;
      if (this.y > H + 20) this.reset();
    };
    Node.prototype.draw = function() {
      var col = this.c[0]+','+this.c[1]+','+this.c[2];
      var g = ctx.createRadialGradient(this.x, this.y, 0, this.x, this.y, this.r * 3.5);
      g.addColorStop(0, 'rgba('+col+','+(this.alpha * .22)+')');
      g.addColorStop(1, 'rgba('+col+',0)');
      ctx.fillStyle = g;
      ctx.beginPath(); ctx.arc(this.x, this.y, this.r * 3.5, 0, Math.PI*2); ctx.fill();
      ctx.fillStyle = 'rgba('+col+','+this.alpha+')';
      ctx.beginPath(); ctx.arc(this.x, this.y, this.r, 0, Math.PI*2); ctx.fill();
    };

    var CONNECT_DIST = 120;
    function drawConnections(nodes) {
      for (var i = 0; i < nodes.length; i++) {
        for (var j = i + 1; j < nodes.length; j++) {
          var dx = nodes[i].x - nodes[j].x, dy = nodes[i].y - nodes[j].y;
          var d  = Math.sqrt(dx*dx + dy*dy);
          if (d < CONNECT_DIST) {
            var a = .15 * (1 - d / CONNECT_DIST) * Math.min(nodes[i].alpha, nodes[j].alpha);
            ctx.strokeStyle = 'rgba(79,110,247,' + a + ')';
            ctx.lineWidth   = .7;
            ctx.beginPath();
            ctx.moveTo(nodes[i].x, nodes[i].y);
            ctx.lineTo(nodes[j].x, nodes[j].y);
            ctx.stroke();
          }
        }
      }
    }

    function drawMouseHighlight() {
      if (mouse.x < 0) return;
      var g = ctx.createRadialGradient(mouse.x, mouse.y, 0, mouse.x, mouse.y, 160);
      g.addColorStop(0, 'rgba(79,110,247,.05)');
      g.addColorStop(1, 'rgba(79,110,247,0)');
      ctx.fillStyle = g;
      ctx.beginPath(); ctx.arc(mouse.x, mouse.y, 160, 0, Math.PI*2); ctx.fill();
    }

    var nodes = [];
    function spawnNodes() {
      nodes = [];
      var count = Math.min(55, Math.floor(W * H / 16000));
      for (var i = 0; i < count; i++) nodes.push(new Node());
    }

    function resize() {
      W = canvas.width  = window.innerWidth;
      H = canvas.height = window.innerHeight;
      buildOrbs(); spawnNodes();
    }

    function loop() {
      tick++;
      mouse.x += (mouse.tx - mouse.x) * .07;
      mouse.y += (mouse.ty - mouse.y) * .07;

      ctx.clearRect(0, 0, W, H);
      var bg = ctx.createLinearGradient(0, 0, W * .6, H);
      bg.addColorStop(0,  '#F5F7FD');
      bg.addColorStop(.5, '#EFF3FF');
      bg.addColorStop(1,  '#F3F6FC');
      ctx.fillStyle = bg; ctx.fillRect(0, 0, W, H);

      updateOrbs();
      drawOrbs();
      drawDotGrid();
      drawMouseHighlight();
      drawConnections(nodes);
      for (var i = 0; i < nodes.length; i++) { nodes[i].update(); nodes[i].draw(); }

      requestAnimationFrame(loop);
    }

    window.addEventListener('resize', resize);
    document.addEventListener('mousemove', function(e) { mouse.tx = e.clientX; mouse.ty = e.clientY; });
    document.addEventListener('mouseleave', function() { mouse.tx = -999; mouse.ty = -999; });

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
    var anim=el.animate([{position:'absolute',width:size+'px',height:size+'px',left:(cx-size/2)+'px',top:(cy-size/2)+'px',borderRadius:'50%',background:'rgba(255,255,255,0.25)',transform:'scale(0)',opacity:'1',pointerEvents:'none'},{transform:'scale(1)',opacity:'0'}],{duration:560,easing:'ease-out',fill:'forwards'});
    anim.onfinish=function(){el.remove();};
  }
  document.addEventListener('click',function(e){var b=e.target.closest('.btn-primary,.btn-portal,.btn-signout,.btn-create');if(b)ripple(b,e);});
  document.addEventListener('keydown',function(e){if(e.key==='Enter'){var el=document.activeElement;if(el&&el.matches('.btn-primary,.btn-portal,.btn-signout,.btn-create'))ripple(el,null);}});

}());
