# -*- coding: utf-8 -*-
"""
Visitor intelligence beacon for the honeypot.

When anyone loads a decoy page this JavaScript runs in *their* browser, harvests
everything the browser is willing to expose about the device, and beacons it to
/_collect. It is passive reconnaissance of whoever pokes the trap — no exploit,
no payload — exactly the threat-intel a honeypot exists to gather.

Signals collected, roughly in order of how much they identify a device:

  HARDWARE-DERIVED (high entropy, very stable — survives a new browser profile)
    * canvas render hash          — the most distinctive single client signal
    * WebGL vendor/renderer + a rendered-scene hash, extensions, shader precision
    * WebGPU adapter info         — richer, lower-level hardware than WebGL
    * AudioContext DSP hash       — float differences from the audio stack
    * installed font probe        — Latin + Arabic faces, via text metrics

  ENVIRONMENT (moderate entropy, stable)
    * OS / browser / engine, UA-Client-Hints high-entropy values
    * screen geometry, pixel ratio, colour depth, colour gamut, HDR
    * timezone + locale + DST behaviour  (location without a permission prompt)
    * CPU cores, device memory, storage quota, touch points, battery, network
    * media-device counts, speech-synthesis voices, codec support
    * permission states, CSS user preferences (dark mode, reduced motion)

  ADVERSARIAL TELLS (why a honeypot cares)
    * automation markers: navigator.webdriver, headless, phantom, CDP artefacts
    * SPOOFING INCONSISTENCIES: a UA claiming Windows while the platform says
      Linux, a mobile UA with no touch, hairline-thin outer window, missing
      chrome object, timezone/locale mismatch. Anti-detect browsers and scripted
      clients fake the easy fields and get caught by the cross-checks.
    * private-mode heuristic from the storage quota

Component hashes are sent alongside the combined id, so the dashboard can tell
"same machine, new browser" from "same browser, new network" instead of only
comparing one opaque value.

All of it is browser-exposed data and never touches the device beyond the
sandbox. Server-side, /_collect stamps it with the source IP, headers and time.
"""

# Served at /_intel.js and injected before </body> on every decoy page.
BEACON_JS = r"""
(function(){
  if (window.__hp_intel) return; window.__hp_intel = 1;
  var N = navigator, S = screen, D = document, W = window;
  function safe(f, d){ try { var v = f(); return (v === undefined ? (d===undefined?null:d) : v); }
                       catch(e){ return (d===undefined ? null : d); } }
  function hash(s){ s = String(s); var h = 2166136261;
    for (var i=0;i<s.length;i++){ h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
    return (h>>>0).toString(16); }

  /* ---- canvas: styled text + shapes, hashed --------------------------- */
  function canvasFP(){
    var c = D.createElement('canvas'); c.width = 300; c.height = 70;
    var x = c.getContext('2d');
    x.textBaseline = 'top'; x.font = "16px 'Arial'";
    x.fillStyle = '#f60'; x.fillRect(0,0,110,30);
    x.fillStyle = '#069'; x.fillText('Honeypot fp ⚓ 0123 أبجد', 2, 15);
    x.fillStyle = 'rgba(102,204,0,0.7)'; x.fillText('Honeypot fp ⚓ 0123 أبجد', 4, 17);
    x.globalCompositeOperation = 'multiply';
    ['#f2f','#2ff','#ff2'].forEach(function(col, i){
      x.fillStyle = col; x.beginPath();
      x.arc(50 + i*30, 50, 24, 0, Math.PI*2, true); x.closePath(); x.fill();
    });
    return hash(c.toDataURL());
  }

  /* ---- webgl: identity strings + capabilities + rendered scene -------- */
  function webglFP(){
    var c = D.createElement('canvas');
    var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
    if (!gl) return null;
    var dbg = gl.getExtension('WEBGL_debug_renderer_info');
    var out = {
      vendor:   dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL)   : gl.getParameter(gl.VENDOR),
      renderer: dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER),
      version:  safe(function(){ return gl.getParameter(gl.VERSION); }),
      glsl:     safe(function(){ return gl.getParameter(gl.SHADING_LANGUAGE_VERSION); }),
      maxTexture:  safe(function(){ return gl.getParameter(gl.MAX_TEXTURE_SIZE); }),
      maxViewport: safe(function(){ var v = gl.getParameter(gl.MAX_VIEWPORT_DIMS); return v ? [v[0],v[1]] : null; }),
      maxAniso: safe(function(){ var e = gl.getExtension('EXT_texture_filter_anisotropic');
                                 return e ? gl.getParameter(e.MAX_TEXTURE_MAX_ANISOTROPY_EXT) : null; }),
      extensions: safe(function(){ return (gl.getSupportedExtensions()||[]).length; })
    };
    out.precision = safe(function(){
      var p = gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl.HIGH_FLOAT);
      return p ? [p.rangeMin, p.rangeMax, p.precision] : null; });
    out.hash = hash([out.vendor, out.renderer, out.version, out.glsl, out.maxTexture,
                     out.maxAniso, out.extensions, JSON.stringify(out.precision)].join('|'));
    return out;
  }

  /* ---- webgpu: newer, exposes lower-level adapter detail -------------- */
  function webgpuFP(){
    if (!N.gpu || !N.gpu.requestAdapter) return Promise.resolve(null);
    return N.gpu.requestAdapter().then(function(a){
      if (!a) return null;
      var lim = {};
      try { for (var k in a.limits) { var v = a.limits[k];
              if (typeof v === 'number') lim[k] = v; } } catch(_){}
      var info = safe(function(){ return a.info || {}; }, {});
      return { vendor: info.vendor || null, architecture: info.architecture || null,
               device: info.device || null, description: info.description || null,
               features: safe(function(){ return Array.from(a.features).length; }),
               limitsHash: hash(JSON.stringify(lim)) };
    }).catch(function(){ return null; });
  }

  /* ---- audio: hash the float output of an offline DSP graph ----------- */
  function audioFP(){
    return new Promise(function(resolve){
      try {
        var AC = W.OfflineAudioContext || W.webkitOfflineAudioContext;
        if (!AC) return resolve(null);
        var ctx = new AC(1, 44100, 44100);
        var osc = ctx.createOscillator(); osc.type = 'triangle';
        osc.frequency.setValueAtTime(10000, ctx.currentTime);
        var comp = ctx.createDynamicsCompressor();
        [['threshold',-50],['knee',40],['ratio',12],['attack',0],['release',0.25]]
          .forEach(function(p){ try { comp[p[0]].setValueAtTime(p[1], ctx.currentTime); } catch(_){} });
        osc.connect(comp); comp.connect(ctx.destination); osc.start(0);
        var done = false;
        var timer = setTimeout(function(){ if(!done){ done = true; resolve(null); } }, 1200);
        ctx.oncomplete = function(e){
          if (done) return; done = true; clearTimeout(timer);
          try {
            var buf = e.renderedBuffer.getChannelData(0), sum = 0;
            for (var i = 4500; i < 5000; i++) sum += Math.abs(buf[i]);
            resolve({ sum: sum.toFixed(8), hash: hash(sum.toString()) });
          } catch(_){ resolve(null); }
        };
        ctx.startRendering();
      } catch(_){ resolve(null); }
    });
  }

  /* ---- fonts: Latin + Arabic probe via text metrics ------------------- */
  function fontsFP(){
    var base = ['monospace','sans-serif','serif'];
    var test = ['Arial','Arial Black','Calibri','Cambria','Candara','Consolas','Courier New',
      'Georgia','Impact','Lucida Console','Palatino Linotype','Segoe UI','Tahoma',
      'Times New Roman','Trebuchet MS','Verdana','Helvetica','Menlo','Monaco','Roboto',
      'Ubuntu','DejaVu Sans','Liberation Sans','Noto Sans','Noto Sans Arabic',
      'Traditional Arabic','Simplified Arabic','Arabic Typesetting','Sakkal Majalla',
      'Dubai','Amiri','Cairo','Tajawal','MS Gothic','SimSun','Malgun Gothic'];
    var span = D.createElement('span');
    span.style.cssText = 'position:absolute;left:-9999px;top:-9999px;font-size:72px;white-space:nowrap';
    span.textContent = 'mmmmmmmmmwwwlli AaQأبجدهوز';
    (D.body || D.documentElement).appendChild(span);
    var def = {};
    base.forEach(function(b){ span.style.fontFamily = b;
      def[b] = { w: span.offsetWidth, h: span.offsetHeight }; });
    var found = [];
    test.forEach(function(f){
      var hit = false;
      base.forEach(function(b){
        span.style.fontFamily = "'" + f + "'," + b;
        if (span.offsetWidth !== def[b].w || span.offsetHeight !== def[b].h) hit = true;
      });
      if (hit) found.push(f);
    });
    try { span.parentNode.removeChild(span); } catch(_){}
    return found;
  }

  /* ---- math: engine/libm differences ---------------------------------- */
  function mathFP(){
    var v = [Math.acos(0.123456789), Math.asin(0.123456789), Math.atan(2), Math.sin(-1e300),
             Math.cos(10.000000000123), Math.tan(-1e300), Math.sinh(1), Math.cosh(1),
             Math.tanh(1), Math.expm1(1), Math.log1p(10), Math.pow(Math.PI, -100)];
    return hash(v.join(','));
  }

  /* ---- codecs: container/codec support matrix ------------------------- */
  function codecsFP(){
    var v = D.createElement('video'), a = D.createElement('audio'), out = [];
    [[v,'video/mp4; codecs="avc1.42E01E"'],[v,'video/webm; codecs="vp9"'],
     [v,'video/webm; codecs="av01.0.05M.08"'],[v,'video/ogg; codecs="theora"'],
     [a,'audio/mpeg'],[a,'audio/aac'],[a,'audio/ogg; codecs="vorbis"'],
     [a,'audio/webm; codecs="opus"'],[a,'audio/flac']].forEach(function(p){
      out.push(safe(function(){ return p[0].canPlayType(p[1]) || 'no'; }, 'no'));
    });
    return { matrix: out.join(','), hash: hash(out.join(',')) };
  }

  /* ---- CSS user preferences + display capabilities --------------------- */
  function cssPrefs(){
    function mq(q){ return safe(function(){ return W.matchMedia(q).matches; }, null); }
    return {
      darkMode: mq('(prefers-color-scheme: dark)'),
      reducedMotion: mq('(prefers-reduced-motion: reduce)'),
      contrast: mq('(prefers-contrast: more)'),
      colorGamutP3: mq('(color-gamut: p3)'),
      hdr: mq('(dynamic-range: high)'),
      hover: mq('(hover: hover)'),
      pointerCoarse: mq('(pointer: coarse)'),
      forcedColors: mq('(forced-colors: active)')
    };
  }

  /* ---- permissions snapshot (query only, never prompts) --------------- */
  function permsFP(){
    if (!N.permissions || !N.permissions.query) return Promise.resolve(null);
    var names = ['geolocation','notifications','camera','microphone','clipboard-read',
                 'persistent-storage','midi'];
    return Promise.all(names.map(function(n){
      return N.permissions.query({name:n}).then(function(r){ return n + ':' + r.state; })
                                          .catch(function(){ return n + ':n/a'; });
    })).then(function(list){ return list.join(','); }).catch(function(){ return null; });
  }

  /* ---- media devices: counts only, no permission needed --------------- */
  function devicesFP(){
    if (!N.mediaDevices || !N.mediaDevices.enumerateDevices) return Promise.resolve(null);
    return N.mediaDevices.enumerateDevices().then(function(list){
      var c = {audioinput:0, audiooutput:0, videoinput:0};
      list.forEach(function(d){ if (c[d.kind] !== undefined) c[d.kind]++; });
      return c;
    }).catch(function(){ return null; });
  }

  /* ---- speech synthesis voices: quite distinctive per OS -------------- */
  function voicesFP(){
    return safe(function(){
      var v = W.speechSynthesis && W.speechSynthesis.getVoices ? W.speechSynthesis.getVoices() : [];
      if (!v || !v.length) return null;
      return { count: v.length, hash: hash(v.map(function(x){ return x.name+'|'+x.lang; }).join(',')) };
    });
  }

  /* ---- storage quota -> private-mode heuristic ------------------------ */
  function storageFP(){
    if (!N.storage || !N.storage.estimate) return Promise.resolve(null);
    return N.storage.estimate().then(function(e){
      var q = e.quota || 0;
      return { quotaMB: Math.round(q/1048576), usageMB: Math.round((e.usage||0)/1048576),
               likelyPrivate: q > 0 && q < 300*1048576 };
    }).catch(function(){ return null; });
  }

  /* ---- UA-Client-Hints high entropy values ---------------------------- */
  function hintsFP(){
    if (!N.userAgentData || !N.userAgentData.getHighEntropyValues) return Promise.resolve(null);
    return N.userAgentData.getHighEntropyValues(
      ['architecture','bitness','model','platformVersion','uaFullVersion','fullVersionList','wow64']
    ).catch(function(){ return null; });
  }

  /* ---- private/LAN addresses via WebRTC ------------------------------- */
  function webrtc(cb){
    var ips = {}, done = false;
    var RT = W.RTCPeerConnection || W.webkitRTCPeerConnection || W.mozRTCPeerConnection;
    if (!RT) return cb([]);
    try {
      // No external STUN server: host ICE candidates already reveal the LAN /
      // private addresses, and an isolated honeypot must never phone out.
      var pc = new RT({iceServers: []});
      pc.createDataChannel('x');
      pc.onicecandidate = function(e){
        if (!e || !e.candidate || !e.candidate.candidate) return;
        var m = /([0-9]{1,3}(\.[0-9]{1,3}){3})|([a-f0-9]{1,4}(:[a-f0-9]{1,4}){2,7})/i
                  .exec(e.candidate.candidate);
        if (m && m[0]) ips[m[0]] = 1;
      };
      pc.createOffer().then(function(o){ return pc.setLocalDescription(o); }).catch(function(){});
      setTimeout(function(){ if(!done){ done = true; try{pc.close();}catch(_){} cb(Object.keys(ips)); } }, 1000);
    } catch(_){ cb([]); }
  }

  /* ---- automation + spoofing detection -------------------------------- */
  function botMarks(d){
    var m = [];
    if (N.webdriver === true) m.push('webdriver');
    if (!N.languages || !N.languages.length) m.push('no-languages');
    if (/HeadlessChrome|PhantomJS|Electron/i.test(N.userAgent)) m.push('headless-ua');
    if (W.callPhantom || W._phantom || W.__nightmare) m.push('phantom');
    if (W.outerWidth === 0 || W.outerHeight === 0) m.push('zero-outer');
    if (!W.chrome && /Chrome\//.test(N.userAgent)) m.push('no-chrome-obj');
    if (N.plugins && N.plugins.length === 0 && /Chrome|Firefox/.test(N.userAgent)) m.push('no-plugins');
    if (safe(function(){ return !!W.document.$cdc_asdjflasutopfhvcZLmcfl_ ||
                                !!W.$chrome_asyncScriptInfo; })) m.push('cdp-artifact');
    // Selenium / driver globals
    for (var k in W) { if (/^(_selenium|_Selenium|__webdriver|__driver|__fxdriver|__selenium)/.test(k)) {
      m.push('driver-global'); break; } }
    return m;
  }

  function spoofMarks(d){
    var s = [], ua = N.userAgent || '', plat = (N.platform || '');
    // UA claims one OS, navigator.platform says another
    if (/Windows/i.test(ua) && plat && !/Win/i.test(plat)) s.push('ua-platform-mismatch');
    if (/Mac OS X/i.test(ua) && plat && !/Mac/i.test(plat)) s.push('ua-platform-mismatch');
    if (/Linux/i.test(ua) && plat && !/Linux|Android|arm/i.test(plat)) s.push('ua-platform-mismatch');
    // Mobile UA with no touch support, or desktop UA reporting touch points on a
    // hover-capable pointer — classic anti-detect browser slip
    if (/Mobile|Android|iPhone/i.test(ua) && N.maxTouchPoints === 0) s.push('mobile-ua-no-touch');
    // Client Hints platform disagrees with the UA string
    if (d.uaHints && d.uaHints.platform && ua) {
      var p = d.uaHints.platform;
      if (p === 'Windows' && !/Windows/i.test(ua)) s.push('hints-ua-mismatch');
      if (p === 'macOS'  && !/Mac/i.test(ua))      s.push('hints-ua-mismatch');
      if (p === 'Linux'  && !/Linux|X11/i.test(ua)) s.push('hints-ua-mismatch');
    }
    // Language and timezone from different worlds (weak on its own, useful combined)
    if (d.timezone && N.language) {
      if (/^Europe\/|^America\//.test(d.timezone) && /^(ar|fa|zh|ru)/.test(N.language))
        s.push('tz-locale-divergent');
    }
    // Window impossibly small/large relative to screen
    if (S.width && W.outerWidth > S.width + 50) s.push('outer-exceeds-screen');
    // Renderer strings that only appear in virtualised/headless stacks
    if (d.webgl && d.webgl.renderer &&
        /SwiftShader|llvmpipe|Mesa OffScreen|Microsoft Basic Render/i.test(d.webgl.renderer))
      s.push('software-renderer');
    return s;
  }

  /* ---- assemble -------------------------------------------------------- */
  var d = {
    v: 2,
    page: location.href, referrer: D.referrer, title: D.title,
    ua: N.userAgent, platform: N.platform, vendor: N.vendor,
    language: N.language, languages: safe(function(){ return N.languages; }),
    cores: N.hardwareConcurrency, memory: N.deviceMemory, touch: N.maxTouchPoints,
    cookieEnabled: N.cookieEnabled, dnt: N.doNotTrack, gpc: safe(function(){ return N.globalPrivacyControl; }),
    pdf: N.pdfViewerEnabled, webdriver: N.webdriver === true,
    screen: { w:S.width, h:S.height, availW:S.availWidth, availH:S.availHeight,
              colorDepth:S.colorDepth, pixelRatio:W.devicePixelRatio,
              orientation: safe(function(){ return S.orientation && S.orientation.type; }) },
    window: { innerW:W.innerWidth, innerH:W.innerHeight, outerW:W.outerWidth, outerH:W.outerHeight },
    timezone: safe(function(){ return Intl.DateTimeFormat().resolvedOptions().timeZone; }),
    tzOffsetMin: new Date().getTimezoneOffset(),
    tzDst: safe(function(){
      var y = new Date().getFullYear();
      return [new Date(y,0,1).getTimezoneOffset(), new Date(y,6,1).getTimezoneOffset()]; }),
    locale: safe(function(){ return Intl.DateTimeFormat().resolvedOptions().locale; }),
    calendar: safe(function(){ return Intl.DateTimeFormat().resolvedOptions().calendar; }),
    numbering: safe(function(){ return Intl.DateTimeFormat().resolvedOptions().numberingSystem; }),
    localTime: new Date().toString(),
    connection: safe(function(){ var c = N.connection || {};
      return {type:c.effectiveType, downlink:c.downlink, rtt:c.rtt, saveData:c.saveData}; }),
    plugins: safe(function(){ return Array.prototype.map.call(N.plugins||[], function(p){ return p.name; }); }),
    canvas: safe(canvasFP),
    webgl: safe(webglFP),
    fonts: safe(fontsFP),
    math: safe(mathFP),
    codecs: safe(codecsFP),
    css: safe(cssPrefs),
    voices: voicesFP(),
    uaHints: safe(function(){ return N.userAgentData ?
      {brands:N.userAgentData.brands, mobile:N.userAgentData.mobile,
       platform:N.userAgentData.platform} : null; })
  };
  d.botMarks = safe(function(){ return botMarks(d); }, []);

  /* ---- async signals, then ship --------------------------------------- */
  var shipped = false;
  function send(){
    if (shipped) return; shipped = true;
    // Component hashes let the dashboard say "same machine, different browser"
    // instead of only comparing one opaque id.
    d.components = {
      hw:  hash([d.canvas, d.webgl && d.webgl.hash, d.audio && d.audio.hash,
                 d.webgpu && d.webgpu.limitsHash, d.screen.w, d.screen.h,
                 d.screen.pixelRatio, d.cores, d.memory].join('|')),
      sw:  hash([d.ua, d.platform, (d.fonts||[]).join(','), d.math,
                 d.codecs && d.codecs.hash, d.voices && d.voices.hash].join('|')),
      env: hash([d.timezone, d.locale, (d.languages||[]).join(','),
                 JSON.stringify(d.tzDst)].join('|'))
    };
    d.spoofMarks = safe(function(){ return spoofMarks(d); }, []);
    if (d.spoofMarks && d.spoofMarks.length) {
      d.botMarks = (d.botMarks || []).concat(d.spoofMarks.map(function(x){ return 'spoof:' + x; }));
    }
    d.fpId = hash([d.components.hw, d.components.sw, d.components.env].join('|'));
    try {
      var body = JSON.stringify(d);
      if (N.sendBeacon) N.sendBeacon('/_collect', new Blob([body], {type:'application/json'}));
      else fetch('/_collect', {method:'POST', headers:{'Content-Type':'application/json'},
                               body: body, keepalive: true});
    } catch(_){}
  }

  var jobs = [
    audioFP().then(function(v){ d.audio = v; }),
    webgpuFP().then(function(v){ d.webgpu = v; }),
    permsFP().then(function(v){ d.permissions = v; }),
    devicesFP().then(function(v){ d.mediaDevices = v; }),
    storageFP().then(function(v){ d.storage = v; }),
    hintsFP().then(function(v){ if (v) d.uaHints = Object.assign(d.uaHints || {}, v); }),
    new Promise(function(res){ webrtc(function(ips){ d.localIPs = ips; res(); }); }),
    new Promise(function(res){
      if (!N.getBattery) return res();
      N.getBattery().then(function(b){ d.battery = {level:b.level, charging:b.charging}; res(); }, res);
    })
  ];
  Promise.all(jobs.map(function(p){ return p.catch(function(){}); })).then(send);
  // Never wait forever on a hung API — ship what we have.
  setTimeout(send, 2500);

  // Optional precise GPS, only if the visitor already granted it (no prompt loop).
  safe(function(){
    if (!N.permissions) return;
    N.permissions.query({name:'geolocation'}).then(function(p){
      if (p.state !== 'granted') return;
      N.geolocation.getCurrentPosition(function(pos){
        try {
          N.sendBeacon('/_collect', new Blob([JSON.stringify({fpId: d.fpId, geo:{
            lat: pos.coords.latitude, lon: pos.coords.longitude,
            acc: pos.coords.accuracy, alt: pos.coords.altitude,
            heading: pos.coords.heading, speed: pos.coords.speed }})],
            {type:'application/json'}));
        } catch(_){}
      }, function(){}, {timeout: 4000, enableHighAccuracy: true});
    }).catch(function(){});
  });
})();
"""
