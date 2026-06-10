# -*- coding: utf-8 -*-
"""
Visitor intelligence beacon for the honeypot.

When anyone loads a decoy page, this JavaScript runs in *their* browser, harvests
everything the browser is willing to expose about the device, and beacons it back
to /_collect. It is passive reconnaissance of whoever pokes the trap — no exploit,
no payload — exactly the threat-intel a honeypot exists to gather:

  * OS / browser / engine (from UA + UA-Client-Hints when available)
  * exact screen + window geometry, pixel ratio, colour depth
  * timezone + locale  (a strong location signal with zero permission prompts)
  * GPU vendor/renderer via WebGL, and a canvas fingerprint hash
  * CPU cores, device memory, touch points, battery, network type
  * LOCAL/private IPs via WebRTC  (leaks the real address behind a VPN/NAT)
  * automation tells (navigator.webdriver, headless markers)  -> bot scoring
  * optional precise GPS  (only if the visitor grants it; never forced)

All of this is browser-exposed data; it never touches the device beyond the
sandbox. Server-side, /_collect stamps it with the source IP, headers and time.
"""

# Served at /_intel.js and injected before </body> on every decoy page.
BEACON_JS = r"""
(function(){
  if (window.__hp_intel) return; window.__hp_intel = 1;
  var N = navigator, S = screen, D = document, W = window;
  function safe(f){ try { return f(); } catch(e){ return null; } }
  function hash(s){ var h=2166136261; for(var i=0;i<s.length;i++){ h^=s.charCodeAt(i); h=Math.imul(h,16777619);} return (h>>>0).toString(16); }

  function canvasFP(){
    var c=D.createElement('canvas'); c.width=260; c.height=60; var x=c.getContext('2d');
    x.textBaseline='top'; x.font="16px 'Arial'";
    x.fillStyle='#f60'; x.fillRect(0,0,110,30);
    x.fillStyle='#069'; x.fillText('Honeypot fp ⚓ 0123',2,15);
    x.fillStyle='rgba(102,204,0,0.7)'; x.fillText('Honeypot fp ⚓ 0123',4,17);
    return hash(c.toDataURL());
  }
  function webgl(){
    var c=D.createElement('canvas'); var gl=c.getContext('webgl')||c.getContext('experimental-webgl');
    if(!gl) return null; var dbg=gl.getExtension('WEBGL_debug_renderer_info');
    return { vendor: dbg?gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL):gl.getParameter(gl.VENDOR),
             renderer: dbg?gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL):gl.getParameter(gl.RENDERER) };
  }
  function fonts(){
    var base=['monospace','sans-serif','serif'], test=['Arial','Calibri','Tahoma','Times New Roman',
      'Courier New','Georgia','Verdana','Segoe UI','Cambria','Consolas','Noto Sans Arabic','Traditional Arabic'];
    var span=D.createElement('span'); span.style.cssText='position:absolute;left:-9999px;font-size:72px';
    span.textContent='mmmmmmmmmlli AaQ أبجد';
    D.body.appendChild(span); var def={};
    base.forEach(function(b){ span.style.fontFamily=b; def[b]={w:span.offsetWidth,h:span.offsetHeight}; });
    var found=[]; test.forEach(function(f){ var hit=false;
      base.forEach(function(b){ span.style.fontFamily="'"+f+"',"+b;
        if(span.offsetWidth!==def[b].w||span.offsetHeight!==def[b].h) hit=true; });
      if(hit) found.push(f); });
    D.body.removeChild(span); return found;
  }
  function webrtc(cb){
    var ips={}, done=false; var RT=W.RTCPeerConnection||W.webkitRTCPeerConnection||W.mozRTCPeerConnection;
    if(!RT){ return cb([]); }
    try{
      var pc=new RT({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});
      pc.createDataChannel('x');
      pc.onicecandidate=function(e){
        if(!e||!e.candidate||!e.candidate.candidate){ return; }
        var m=/([0-9]{1,3}(\.[0-9]{1,3}){3})|([a-f0-9]{1,4}(:[a-f0-9]{1,4}){2,7})/i.exec(e.candidate.candidate);
        if(m && m[0]) ips[m[0]]=1;
      };
      pc.createOffer().then(function(o){ return pc.setLocalDescription(o); });
      setTimeout(function(){ if(!done){ done=true; try{pc.close();}catch(_){} cb(Object.keys(ips)); } }, 1400);
    }catch(_){ cb([]); }
  }

  var d = {
    page: location.href, referrer: D.referrer, title: D.title,
    ua: N.userAgent, platform: N.platform, vendor: N.vendor,
    language: N.language, languages: safe(function(){return N.languages;}),
    cores: N.hardwareConcurrency, memory: N.deviceMemory, touch: N.maxTouchPoints,
    cookieEnabled: N.cookieEnabled, dnt: N.doNotTrack, pdf: N.pdfViewerEnabled,
    webdriver: N.webdriver === true,
    uaHints: safe(function(){ return N.userAgentData ? {brands:N.userAgentData.brands,
              mobile:N.userAgentData.mobile, platform:N.userAgentData.platform} : null; }),
    screen: { w:S.width, h:S.height, availW:S.availWidth, availH:S.availHeight,
              colorDepth:S.colorDepth, pixelRatio:W.devicePixelRatio,
              orientation: safe(function(){return S.orientation && S.orientation.type;}) },
    window: { innerW:W.innerWidth, innerH:W.innerHeight, outerW:W.outerWidth, outerH:W.outerHeight },
    timezone: safe(function(){ return Intl.DateTimeFormat().resolvedOptions().timeZone; }),
    tzOffsetMin: new Date().getTimezoneOffset(),
    locale: safe(function(){ return Intl.DateTimeFormat().resolvedOptions().locale; }),
    localTime: new Date().toString(),
    connection: safe(function(){ var c=N.connection||{}; return {type:c.effectiveType, downlink:c.downlink,
              rtt:c.rtt, saveData:c.saveData}; }),
    plugins: safe(function(){ return Array.prototype.map.call(N.plugins||[], function(p){return p.name;}); }),
    webgl: safe(webgl), canvas: safe(canvasFP), fonts: safe(fonts),
    // automation / headless tells -> a quick bot score
    botMarks: safe(function(){ var m=[];
      if(N.webdriver) m.push('webdriver');
      if(!N.languages || !N.languages.length) m.push('no-languages');
      if(/HeadlessChrome/i.test(N.userAgent)) m.push('headless-ua');
      if(W.callPhantom||W._phantom) m.push('phantom');
      if(W.outerWidth===0||W.outerHeight===0) m.push('zero-outer');
      if(!W.chrome && /Chrome/.test(N.userAgent)) m.push('no-chrome-obj');
      return m; }),
  };
  d.fpId = hash([d.ua,d.platform,d.timezone,d.screen.w,d.screen.h,d.cores,d.canvas,
                 (d.webgl&&d.webgl.renderer)||'',(d.fonts||[]).join(',')].join('|'));

  function send(){
    try{
      var body = JSON.stringify(d);
      if(N.sendBeacon){ N.sendBeacon('/_collect', new Blob([body],{type:'application/json'})); }
      else { fetch('/_collect',{method:'POST',headers:{'Content-Type':'application/json'},body:body,keepalive:true}); }
    }catch(_){}
  }

  // best-effort battery + private IPs, then ship it
  var pending = 2;
  function done(){ if(--pending<=0) send(); }
  webrtc(function(ips){ d.localIPs = ips; done(); });
  if(N.getBattery){ N.getBattery().then(function(b){ d.battery={level:b.level,charging:b.charging}; done(); }, done); } else { done(); }
  // never block on it; ship after 1.6s no matter what
  setTimeout(function(){ if(pending>0){ pending=0; send(); } }, 1600);

  // optional precise GPS — only if already granted (no nagging prompt loop)
  safe(function(){ if(N.permissions){ N.permissions.query({name:'geolocation'}).then(function(p){
    if(p.state==='granted'){ N.geolocation.getCurrentPosition(function(pos){
      try{ N.sendBeacon('/_collect', new Blob([JSON.stringify({fpId:d.fpId,geo:{
        lat:pos.coords.latitude,lon:pos.coords.longitude,acc:pos.coords.accuracy}})],
        {type:'application/json'})); }catch(_){}
    }, function(){}, {timeout:4000}); } }); } });
})();
"""
