// Fingerprint Detector - Page-level injection script
// Runs in the actual page context to intercept fingerprinting API calls
// Supports three modes: detect (monitor only), ghost (block/empty), spoof (uniform fakes)
(function () {
  'use strict';

  const EVENT_NAME = '__fp_detect__';

  // ─── Mode detection (cached, updated via MutationObserver) ─────────
  let _cachedMode = document.documentElement?.dataset?.fpMode || 'detect';

  // Watch for mode changes on <html data-fp-mode="...">
  try {
    const observer = new MutationObserver((mutations) => {
      for (const m of mutations) {
        if (m.type === 'attributes' && m.attributeName === 'data-fp-mode') {
          _cachedMode = document.documentElement?.dataset?.fpMode || 'detect';
        }
      }
    });
    if (document.documentElement) {
      observer.observe(document.documentElement, {
        attributes: true,
        attributeFilter: ['data-fp-mode'],
      });
    }
  } catch (_) {}

  function getMode() {
    return _cachedMode;
  }

  // ─── Caller stack capture ──────────���────────────────────────────────
  const SELF_URL = (function getSelfUrl() {
    try {
      throw new Error();
    } catch (e) {
      const match = (e.stack || '').match(/(?:at\s+.*?\(|@)(.*?inject\.js[^:)]*)/);
      return match ? match[1] : 'inject.js';
    }
  })();

  // Extension ID for filtering stack frames from this script
  // Chrome extension IDs are 32 chars of [a-p], but some browsers use UUID format
  const EXT_UUID = (function () {
    try {
      const match = SELF_URL.match(/[a-p]{32}|[a-f0-9-]{36}/);
      return match ? match[0] : '';
    } catch (_) { return ''; }
  })();

  function getCallerStack() {
    const err = new Error();
    const lines = (err.stack || '').split('\n').slice(2);
    for (const line of lines) {
      const trimmed = line.trim();
      if (
        trimmed &&
        !trimmed.includes(SELF_URL) &&
        !trimmed.includes('inject.js') &&
        !(EXT_UUID && trimmed.includes(EXT_UUID))
      ) {
        return trimmed;
      }
    }
    return lines[0]?.trim() || 'unknown';
  }

  // ─── Return value summarization ─────────────────────────────────────
  const MAX_VALUE_LENGTH = 200;
  let _insideSummarize = false;

  function truncateStr(str) {
    return str.length > MAX_VALUE_LENGTH
      ? str.substring(0, MAX_VALUE_LENGTH) + '...'
      : str;
  }

  function summarizeValue(val) {
    if (_insideSummarize) return '[recursive]';
    _insideSummarize = true;
    try {
      return _summarizeValueInner(val);
    } finally {
      _insideSummarize = false;
    }
  }

  function _summarizeValueInner(val) {
    if (val === undefined) return undefined;
    if (val === null) return 'null';
    const t = typeof val;
    if (t === 'string') return truncateStr(val);
    if (t === 'number' || t === 'boolean') return String(val);
    if (t === 'function') return `[Function: ${val.name || 'anonymous'}]`;
    if (t !== 'object') return truncateStr(String(val));
    if (val instanceof ArrayBuffer || (typeof SharedArrayBuffer !== 'undefined' && val instanceof SharedArrayBuffer)) {
      return `ArrayBuffer(${val.byteLength})`;
    }
    if (ArrayBuffer.isView(val)) return `${val.constructor.name}(${val.length})`;
    if (val instanceof Blob) return `Blob(${val.size}, ${val.type || 'unknown'})`;
    if (val instanceof Promise) return 'Promise';
    if (val instanceof ImageData) return `ImageData(${val.width}x${val.height})`;
    if (typeof PluginArray !== 'undefined' && val instanceof PluginArray) return `PluginArray(${val.length})`;
    if (typeof MimeTypeArray !== 'undefined' && val instanceof MimeTypeArray) return `MimeTypeArray(${val.length})`;
    if (typeof MediaDeviceInfo !== 'undefined' && val instanceof MediaDeviceInfo) return `MediaDeviceInfo(${val.kind}, ${val.label || 'unlabeled'})`;
    if (val instanceof DOMTokenList || val instanceof NodeList || val instanceof HTMLCollection) return `[${val.constructor.name}(${val.length})]`;
    if (Array.isArray(val)) {
      try { return truncateStr(JSON.stringify(val)); } catch (_) { return `[Array(${val.length})]`; }
    }
    const proto = Object.getPrototypeOf(val);
    if (proto === null || proto === Object.prototype) {
      try { return truncateStr(JSON.stringify(val)); } catch (_) { return '[Object]'; }
    }
    const name = val.constructor?.name || 'Object';
    return `[${name}]`;
  }

  // ─── Reporting ───────────���───────────────────────���──────────────────
  function report(category, api, returnValue, blocked) {
    try {
      window.postMessage({
        type: EVENT_NAME,
        category,
        api,
        timestamp: Date.now(),
        stack: getCallerStack(),
        returnValue: summarizeValue(returnValue),
        blocked: !!blocked,
      }, '*');
    } catch (_) {}
  }

  // ══════���══════════════════════════════════���═════════════════════════════
  // GHOST & SPOOF VALUE MAPS
  // ════════════��══════════════════════════════���═══════════════════════════

  const SPOOF_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

  // ─── Common values shared by ghost and spoof ──────────────────────
  // Ghost mode philosophy: return the most COMMON values to blend in.
  // Empty/blocked values are MORE fingerprintable because they're unique.
  function makeStandardPlugins() {
    const pdfPlugin = {
      name: 'PDF Viewer', filename: 'internal-pdf-viewer',
      description: 'Portable Document Format', length: 1,
      0: { type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format' },
      item: (i) => i === 0 ? pdfPlugin[0] : null,
      namedItem: () => null,
    };
    const chromePdf = {
      name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer',
      description: 'Portable Document Format', length: 1,
      0: { type: 'application/x-google-chrome-pdf', suffixes: 'pdf', description: 'Portable Document Format' },
      item: (i) => i === 0 ? chromePdf[0] : null,
      namedItem: () => null,
    };
    const chromiumPdf = {
      name: 'Chromium PDF Plugin', filename: 'internal-pdf-viewer',
      description: 'Portable Document Format', length: 1,
      0: { type: 'application/x-google-chrome-pdf', suffixes: 'pdf', description: 'Portable Document Format' },
      item: (i) => i === 0 ? chromiumPdf[0] : null,
      namedItem: () => null,
    };
    const chromePdfViewer = {
      name: 'Chrome PDF Viewer', filename: 'internal-pdf-viewer',
      description: 'Portable Document Format', length: 1,
      0: { type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format' },
      item: (i) => i === 0 ? chromePdfViewer[0] : null,
      namedItem: () => null,
    };
    const nativeClient = {
      name: 'Native Client', filename: 'internal-nacl-plugin',
      description: '', length: 2,
      0: { type: 'application/x-nacl', suffixes: '', description: 'Native Client Executable' },
      1: { type: 'application/x-pnacl', suffixes: '', description: 'Portable Native Client Executable' },
      item: (i) => nativeClient[i] || null,
      namedItem: () => null,
    };
    const arr = [pdfPlugin, chromePdf, chromiumPdf, chromePdfViewer, nativeClient];
    arr.item = (i) => arr[i] || null;
    arr.namedItem = (name) => arr.find(p => p.name === name) || null;
    arr.refresh = () => {};
    return arr;
  }

  function makeStandardMimeTypes() {
    const types = [
      { type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format' },
      { type: 'application/x-google-chrome-pdf', suffixes: 'pdf', description: 'Portable Document Format' },
      { type: 'application/x-nacl', suffixes: '', description: 'Native Client Executable' },
      { type: 'application/x-pnacl', suffixes: '', description: 'Portable Native Client Executable' },
    ];
    const arr = types.slice();
    arr.item = (i) => arr[i] || null;
    arr.namedItem = (name) => arr.find(m => m.type === name) || null;
    return arr;
  }

  // Ghost: blocks data extraction but returns common metadata to blend in.
  // Key insight: returning empty/blocked values is MORE fingerprintable than
  // returning common values, because almost no real browsers return "blocked".
  const GHOST = {
    // Canvas — block pixel data extraction
    'canvas.toDataURL': () => 'data:,',
    'canvas.getImageData': (orig, ctx, args) => new ImageData(args[2] || 1, args[3] || 1),
    // WebGL — values set after SPOOF is defined (see below)
    'webgl.getParameter': null, // handled specially in custom wrapper
    // Hardware — most common Chrome values
    'navigator.hardwareConcurrency': () => 8,
    'navigator.deviceMemory': () => 8,
    'navigator.maxTouchPoints': () => 0,
    // Screen — most common desktop resolution
    'screen.width': () => 1920,
    'screen.height': () => 1080,
    'screen.colorDepth': () => 24,
    'screen.pixelDepth': () => 24,
    'screen.availWidth': () => 1920,
    'screen.availHeight': () => 1040,
    'window.devicePixelRatio': () => 1,
    // UA / Platform — standard Chrome on Windows
    'navigator.userAgent': () => SPOOF_UA,
    'navigator.platform': () => 'Win32',
    'navigator.language': () => 'en-US',
    'navigator.languages': () => Object.freeze(['en-US', 'en']),
    'navigator.vendor': () => 'Google Inc.',
    // Audio — let construction through, block data extraction separately
    'audio.createOscillator': null,
    'audio.createDynamicsCompressor': null,
    'audio.createAnalyser': null,
    // Connection — common values instead of undefined
    'connection.type': () => 'wifi',
    'connection.effectiveType': () => '4g',
    'connection.downlink': () => 10,
    'connection.rtt': () => 50,
    'connection.saveData': () => false,
    // Plugins — standard Chrome plugin set (NOT empty — empty is more unique)
    'navigator.plugins': makeStandardPlugins,
    'navigator.mimeTypes': makeStandardMimeTypes,
  };

  // Ghost async values
  const GHOST_ASYNC = {
    'navigator.getBattery': () => Promise.resolve({
      charging: true, chargingTime: 0, dischargingTime: Infinity, level: 1,
      addEventListener: () => {}, removeEventListener: () => {},
      dispatchEvent: () => false,
      onchargingchange: null, onchargingtimechange: null,
      ondischargingtimechange: null, onlevelchange: null,
    }),
    'storage.estimate': () => Promise.resolve({ quota: 0, usage: 0 }),
    'mediaDevices.enumerateDevices': () => Promise.resolve([]),
    'userAgentData.getHighEntropyValues': () => Promise.resolve({}),
  };

  // Ghost callback values
  const GHOST_CALLBACK = {
    'canvas.toBlob': () => new Blob([]),
  };

  // Ghost constructors that should throw
  const GHOST_BLOCK_CONSTRUCT = new Set(['RTCPeerConnection', 'webkitRTCPeerConnection']);

  // Spoof: common Chrome/Windows values to blend in
  const SPOOF = {
    // Hardware
    'navigator.hardwareConcurrency': () => 8,
    'navigator.deviceMemory': () => 8,
    'navigator.maxTouchPoints': () => 0,
    // Screen
    'screen.width': () => 1920,
    'screen.height': () => 1080,
    'screen.colorDepth': () => 24,
    'screen.pixelDepth': () => 24,
    'screen.availWidth': () => 1920,
    'screen.availHeight': () => 1040,
    'window.devicePixelRatio': () => 1,
    // UA / Platform
    'navigator.userAgent': () => SPOOF_UA,
    'navigator.platform': () => 'Win32',
    'navigator.language': () => 'en-US',
    'navigator.languages': () => Object.freeze(['en-US', 'en']),
    'navigator.vendor': () => 'Google Inc.',
    // Connection
    'connection.type': () => 'wifi',
    'connection.effectiveType': () => '4g',
    'connection.downlink': () => 10,
    'connection.rtt': () => 50,
    'connection.saveData': () => false,
    // Plugins — same standard set as ghost (must match to avoid fingerprint divergence)
    'navigator.plugins': makeStandardPlugins,
    'navigator.mimeTypes': makeStandardMimeTypes,
    // Audio (let through — spoof mode allows functionality)
    'audio.createOscillator': null,
    'audio.createDynamicsCompressor': null,
    'audio.createAnalyser': null,
  };

  const SPOOF_ASYNC = {
    'navigator.getBattery': () => Promise.resolve({
      charging: true, chargingTime: 0, dischargingTime: Infinity, level: 0.85,
      addEventListener: () => {}, removeEventListener: () => {},
      dispatchEvent: () => false,
      onchargingchange: null, onchargingtimechange: null,
      ondischargingtimechange: null, onlevelchange: null,
    }),
    'storage.estimate': () => Promise.resolve({ quota: 2147483648, usage: 0 }),
    'mediaDevices.enumerateDevices': () => Promise.resolve([
      { deviceId: '', kind: 'audioinput', label: '', groupId: 'default' },
      { deviceId: '', kind: 'videoinput', label: '', groupId: 'default' },
    ]),
    'userAgentData.getHighEntropyValues': () => Promise.resolve({
      architecture: 'x86',
      bitness: '64',
      brands: [{ brand: 'Not_A Brand', version: '8' }, { brand: 'Chromium', version: '120' }, { brand: 'Google Chrome', version: '120' }],
      fullVersionList: [{ brand: 'Not_A Brand', version: '8.0.0.0' }, { brand: 'Chromium', version: '120.0.6099.130' }, { brand: 'Google Chrome', version: '120.0.6099.130' }],
      mobile: false,
      model: '',
      platform: 'Windows',
      platformVersion: '15.0.0',
      uaFullVersion: '120.0.6099.130',
    }),
  };

  // WebGL spoof extension list (common Intel UHD 630 on Chrome)
  const WEBGL_SPOOF_EXTENSIONS = [
    'ANGLE_instanced_arrays', 'EXT_blend_minmax', 'EXT_color_buffer_half_float',
    'EXT_float_blend', 'EXT_frag_depth', 'EXT_shader_texture_lod',
    'EXT_texture_compression_rgtc', 'EXT_texture_filter_anisotropic',
    'EXT_sRGB', 'KHR_parallel_shader_compile', 'OES_element_index_uint',
    'OES_fbo_render_mipmap', 'OES_standard_derivatives', 'OES_texture_float',
    'OES_texture_float_linear', 'OES_texture_half_float',
    'OES_texture_half_float_linear', 'OES_vertex_array_object',
    'WEBGL_color_buffer_float', 'WEBGL_compressed_texture_s3tc',
    'WEBGL_compressed_texture_s3tc_srgb', 'WEBGL_debug_renderer_info',
    'WEBGL_debug_shaders', 'WEBGL_depth_texture', 'WEBGL_draw_buffers',
    'WEBGL_lose_context', 'WEBGL_multi_draw',
  ];

  // Spoof entries for WebGL methods (used by wrapMethod lookup)
  SPOOF['webgl.getSupportedExtensions'] = () => WEBGL_SPOOF_EXTENSIONS.slice();
  SPOOF['webgl.getExtension'] = (original, ctx, args) => {
    const name = args[0];
    if (WEBGL_SPOOF_EXTENSIONS.includes(name)) {
      // Return the real extension if available (needed for functionality)
      return original.call(ctx, name);
    }
    return null;
  };
  SPOOF['webgl.getShaderPrecisionFormat'] = (original, ctx, args) => {
    // Return the real precision format — these are mostly uniform across GPUs
    return original.apply(ctx, args);
  };

  // Ghost shares the same WebGL spoofing as SPOOF
  GHOST['webgl.getSupportedExtensions'] = SPOOF['webgl.getSupportedExtensions'];
  GHOST['webgl.getExtension'] = SPOOF['webgl.getExtension'];
  GHOST['webgl.getShaderPrecisionFormat'] = SPOOF['webgl.getShaderPrecisionFormat'];

  // WebGL spoof parameter map (common Intel UHD 630 values)
  const WEBGL_SPOOF_PARAMS = {
    7936: 'WebKit',                          // VENDOR
    7937: 'WebKit WebGL',                    // RENDERER
    37445: 'Google Inc. (Intel)',             // UNMASKED_VENDOR_WEBGL
    37446: 'ANGLE (Intel, Intel(R) UHD Graphics 630, OpenGL 4.5)', // UNMASKED_RENDERER_WEBGL
    7938: 'WebGL 1.0 (OpenGL ES 2.0 Chromium)',  // VERSION
    35724: 'WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)', // SHADING_LANGUAGE_VERSION
    3379: 16384,                             // MAX_TEXTURE_SIZE
    34076: 16384,                            // MAX_CUBE_MAP_TEXTURE_SIZE
    34024: 16384,                            // MAX_RENDERBUFFER_SIZE
    36347: 1024,                             // MAX_VARYING_VECTORS
    36348: 4096,                             // MAX_VERTEX_UNIFORM_VECTORS
    36349: 1024,                             // MAX_FRAGMENT_UNIFORM_VECTORS
    34921: 16,                               // MAX_VERTEX_ATTRIBS
    35660: 16,                               // MAX_VERTEX_TEXTURE_IMAGE_UNITS
    34930: 16,                               // MAX_TEXTURE_IMAGE_UNITS
    35661: 32,                               // MAX_COMBINED_TEXTURE_IMAGE_UNITS
  };

  // ─── Deterministic PRNG seeded by domain ─────────────────────────────
  // Canvas noise must be consistent per-domain so every visit produces
  // the same fingerprint (blending in) rather than a unique one each call.
  const _domainSeed = (function () {
    let h = 0x811c9dc5;
    const domain = window.location.hostname || 'localhost';
    for (let i = 0; i < domain.length; i++) {
      h ^= domain.charCodeAt(i);
      h = Math.imul(h, 0x01000193);
    }
    return h >>> 0;
  })();

  let _prngState = _domainSeed;
  function seededRandom() {
    _prngState = (_prngState * 1664525 + 1013904223) & 0xffffffff;
    return (_prngState >>> 0) / 0x100000000;
  }

  // ─── Canvas noise helper for spoof mode ─────────────────────────────
  function addCanvasNoise(canvas) {
    try {
      const ctx = canvas.getContext('2d');
      if (!ctx) return;
      const w = canvas.width, h = canvas.height;
      if (w === 0 || h === 0) return;
      // Modify a few pixels deterministically per domain
      for (let i = 0; i < 5; i++) {
        const x = Math.floor(seededRandom() * w);
        const y = Math.floor(seededRandom() * h);
        const r = Math.floor(seededRandom() * 256);
        const g = Math.floor(seededRandom() * 256);
        const b = Math.floor(seededRandom() * 256);
        ctx.fillStyle = `rgba(${r},${g},${b},0.01)`;
        ctx.fillRect(x, y, 1, 1);
      }
    } catch (_) {}
  }

  function addImageDataNoise(imageData) {
    const data = imageData.data;
    // Flip the LSB of a few pixels deterministically
    for (let i = 0; i < 10; i++) {
      const idx = Math.floor(seededRandom() * data.length);
      data[idx] ^= 1;
    }
    return imageData;
  }

  // ══════���═══════════════════════════���════════════════════════════════════
  // MODE-AWARE WRAPPER HELPERS
  // ═══════════════════════════════════════════════════════════════════════

  function wrapMethod(obj, prop, category, apiLabel) {
    const original = obj[prop];
    if (typeof original !== 'function') return;
    obj[prop] = function (...args) {
      const mode = getMode();
      const label = apiLabel || prop;

      if (mode === 'ghost') {
        const ghostFn = GHOST[label];
        if (ghostFn !== undefined) {
          if (ghostFn === null) {
            // null = let through (needed for functionality)
            const result = original.apply(this, args);
            report(category, label, result, false);
            return result;
          }
          const fakeResult = ghostFn(original, this, args);
          report(category, label, fakeResult, true);
          return fakeResult;
        }
      }

      if (mode === 'spoof') {
        const spoofFn = SPOOF[label];
        if (spoofFn !== undefined) {
          if (spoofFn === null) {
            const result = original.apply(this, args);
            report(category, label, result, false);
            return result;
          }
          const fakeResult = spoofFn(original, this, args);
          report(category, label, fakeResult, true);
          return fakeResult;
        }
      }

      // Detect mode or no override defined
      const result = original.apply(this, args);
      report(category, label, result, false);
      return result;
    };
    obj[prop].toString = () => original.toString();
    Object.defineProperties(obj[prop], {
      length: { value: original.length },
      name: { value: original.name },
    });
  }

  function wrapAsyncMethod(obj, prop, category, apiLabel) {
    const original = obj[prop];
    if (typeof original !== 'function') return;
    obj[prop] = function (...args) {
      const mode = getMode();
      const label = apiLabel || prop;

      if (mode === 'ghost' && GHOST_ASYNC[label]) {
        const fakePromise = GHOST_ASYNC[label]();
        report(category, label, 'Promise', true);
        fakePromise.then((resolved) => report(category, label + ' [resolved]', resolved, true));
        return fakePromise;
      }

      if (mode === 'spoof' && SPOOF_ASYNC[label]) {
        const fakePromise = SPOOF_ASYNC[label]();
        report(category, label, 'Promise', true);
        fakePromise.then((resolved) => report(category, label + ' [resolved]', resolved, true));
        return fakePromise;
      }

      // Detect mode
      const promise = original.apply(this, args);
      report(category, label, promise, false);
      if (promise && typeof promise.then === 'function') {
        promise.then(
          (resolved) => report(category, label + ' [resolved]', resolved, false),
          () => {}
        );
      }
      return promise;
    };
    obj[prop].toString = () => original.toString();
    Object.defineProperties(obj[prop], {
      length: { value: original.length },
      name: { value: original.name },
    });
  }

  function wrapCallbackMethod(obj, prop, category, apiLabel, callbackArgIndex) {
    const original = obj[prop];
    if (typeof original !== 'function') return;
    obj[prop] = function (...args) {
      const mode = getMode();
      const label = apiLabel || prop;

      if (mode === 'ghost' && GHOST_CALLBACK[label]) {
        const fakeResult = GHOST_CALLBACK[label]();
        report(category, label, fakeResult, true);
        const origCallback = args[callbackArgIndex];
        if (typeof origCallback === 'function') {
          setTimeout(() => origCallback.call(this, fakeResult), 0);
        }
        return;
      }

      // Spoof canvas.toBlob — call real but with noise
      if (mode === 'spoof' && label === 'canvas.toBlob') {
        addCanvasNoise(this);
        const origCallback = args[callbackArgIndex];
        if (typeof origCallback === 'function') {
          args[callbackArgIndex] = function (result) {
            report(category, label, result, true);
            return origCallback.call(this, result);
          };
        }
        return original.apply(this, args);
      }

      // Detect mode
      const origCallback = args[callbackArgIndex];
      if (typeof origCallback === 'function') {
        args[callbackArgIndex] = function (result) {
          report(category, label, result, false);
          return origCallback.call(this, result);
        };
      } else {
        report(category, label, undefined, false);
      }
      return original.apply(this, args);
    };
    obj[prop].toString = () => original.toString();
    Object.defineProperties(obj[prop], {
      length: { value: original.length },
      name: { value: original.name },
    });
  }

  function wrapGetter(obj, prop, category, apiLabel) {
    const descriptor = Object.getOwnPropertyDescriptor(obj, prop);
    if (!descriptor || !descriptor.get) return;
    const originalGet = descriptor.get;
    Object.defineProperty(obj, prop, {
      ...descriptor,
      get() {
        const mode = getMode();
        const label = apiLabel || prop;

        if (mode === 'ghost') {
          const ghostFn = GHOST[label];
          if (ghostFn !== undefined) {
            if (ghostFn === null) {
              const result = originalGet.call(this);
              report(category, label, result, false);
              return result;
            }
            const fakeResult = ghostFn();
            report(category, label, fakeResult, true);
            return fakeResult;
          }
        }

        if (mode === 'spoof') {
          const spoofFn = SPOOF[label];
          if (spoofFn !== undefined) {
            if (spoofFn === null) {
              const result = originalGet.call(this);
              report(category, label, result, false);
              return result;
            }
            const fakeResult = spoofFn();
            report(category, label, fakeResult, true);
            return fakeResult;
          }
        }

        // Detect mode
        const result = originalGet.call(this);
        report(category, label, result, false);
        return result;
      },
    });
  }

  function wrapConstructor(parent, name, category, apiLabel) {
    const Original = parent[name];
    if (!Original) return;
    parent[name] = new Proxy(Original, {
      construct(target, args, newTarget) {
        const mode = getMode();
        const label = apiLabel || name;

        if (mode === 'ghost' && GHOST_BLOCK_CONSTRUCT.has(label)) {
          report(category, label, '[blocked]', true);
          throw new DOMException(
            `Failed to construct '${name}': Ghost mode is active.`,
            'NotAllowedError'
          );
        }

        report(category, label, undefined, false);
        return Reflect.construct(target, args, newTarget);
      },
      apply(target, thisArg, args) {
        const mode = getMode();
        const label = apiLabel || name;

        if (mode === 'ghost' && GHOST_BLOCK_CONSTRUCT.has(label)) {
          report(category, label, '[blocked]', true);
          throw new DOMException(
            `Failed to construct '${name}': Ghost mode is active.`,
            'NotAllowedError'
          );
        }

        report(category, label, undefined, false);
        return Reflect.apply(target, thisArg, args);
      },
    });
  }

  // ══════════════════════════════════════════���════════════════════════════
  // CANVAS FINGERPRINTING
  // ════════════════════��══════════════════════════════════���═══════════════

  // canvas.toDataURL — special handling for spoof noise
  (function () {
    const original = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function (...args) {
      const mode = getMode();
      if (mode === 'ghost') {
        const fake = 'data:,';
        report('canvas', 'canvas.toDataURL', fake, true);
        return fake;
      }
      if (mode === 'spoof') {
        addCanvasNoise(this);
        const result = original.apply(this, args);
        report('canvas', 'canvas.toDataURL', result, true);
        return result;
      }
      const result = original.apply(this, args);
      report('canvas', 'canvas.toDataURL', result, false);
      return result;
    };
    HTMLCanvasElement.prototype.toDataURL.toString = () => original.toString();
    Object.defineProperties(HTMLCanvasElement.prototype.toDataURL, {
      length: { value: original.length },
      name: { value: original.name },
    });
  })();

  wrapCallbackMethod(
    HTMLCanvasElement.prototype,
    'toBlob',
    'canvas',
    'canvas.toBlob',
    0
  );

  // canvas.getImageData — special handling for spoof noise
  if (typeof CanvasRenderingContext2D !== 'undefined') {
    const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function (...args) {
      const mode = getMode();
      if (mode === 'ghost') {
        const fake = new ImageData(args[2] || 1, args[3] || 1);
        report('canvas', 'canvas.getImageData', fake, true);
        return fake;
      }
      const result = origGetImageData.apply(this, args);
      if (mode === 'spoof') {
        addImageDataNoise(result);
        report('canvas', 'canvas.getImageData', result, true);
        return result;
      }
      report('canvas', 'canvas.getImageData', result, false);
      return result;
    };
    CanvasRenderingContext2D.prototype.getImageData.toString = () => origGetImageData.toString();
    Object.defineProperties(CanvasRenderingContext2D.prototype.getImageData, {
      length: { value: origGetImageData.length },
      name: { value: origGetImageData.name },
    });
  }

  // ═══��════════════��═══════════════════════════════════��══════════════════
  // WEBGL FINGERPRINTING — special handling for spoof parameter map
  // ════════════════════════��════════════════════════��═════════════════════
  const webglProtos = [];
  if (typeof WebGLRenderingContext !== 'undefined') {
    webglProtos.push(WebGLRenderingContext.prototype);
  }
  if (typeof WebGL2RenderingContext !== 'undefined') {
    webglProtos.push(WebGL2RenderingContext.prototype);
  }

  for (const proto of webglProtos) {
    // getParameter — needs special spoof logic for the parameter map
    (function (origGetParam) {
      proto.getParameter = function (pname) {
        const mode = getMode();
        if ((mode === 'ghost' || mode === 'spoof') && pname in WEBGL_SPOOF_PARAMS) {
          const fake = WEBGL_SPOOF_PARAMS[pname];
          report('webgl', 'webgl.getParameter', fake, true);
          return fake;
        }
        if (mode === 'ghost') {
          // For unmapped params, return real values (they're mostly non-identifying)
          const result = origGetParam.call(this, pname);
          report('webgl', 'webgl.getParameter', result, false);
          return result;
        }
        const result = origGetParam.call(this, pname);
        report('webgl', 'webgl.getParameter', result, false);
        return result;
      };
      proto.getParameter.toString = () => origGetParam.toString();
      Object.defineProperties(proto.getParameter, {
        length: { value: origGetParam.length },
        name: { value: origGetParam.name },
      });
    })(proto.getParameter);

    wrapMethod(proto, 'getExtension', 'webgl', 'webgl.getExtension');
    wrapMethod(proto, 'getSupportedExtensions', 'webgl', 'webgl.getSupportedExtensions');
    wrapMethod(proto, 'getShaderPrecisionFormat', 'webgl', 'webgl.getShaderPrecisionFormat');
  }

  // ══════════════��════════════════════════════════════════════════════════
  // AUDIO FINGERPRINTING
  // ══════��═══════════════════════════��════════════════════════════════════
  wrapConstructor(window, 'AudioContext', 'audio', 'AudioContext');
  wrapConstructor(window, 'OfflineAudioContext', 'audio', 'OfflineAudioContext');

  if (typeof AudioContext !== 'undefined') {
    const audioProto = AudioContext.prototype;
    if (audioProto) {
      wrapMethod(audioProto, 'createOscillator', 'audio', 'audio.createOscillator');
      wrapMethod(audioProto, 'createDynamicsCompressor', 'audio', 'audio.createDynamicsCompressor');
      wrapMethod(audioProto, 'createAnalyser', 'audio', 'audio.createAnalyser');
    }
  }

  // Intercept AudioBuffer.getChannelData — the key audio fingerprint vector.
  // Audio fingerprinting renders audio via OfflineAudioContext, then reads
  // the output samples. Noising or zeroing getChannelData defeats this.
  if (typeof AudioBuffer !== 'undefined') {
    const origGetChannelData = AudioBuffer.prototype.getChannelData;
    AudioBuffer.prototype.getChannelData = function (channel) {
      const mode = getMode();
      const result = origGetChannelData.call(this, channel);
      if (mode === 'ghost') {
        // Return a zeroed copy so original buffer isn't affected
        const zeroed = new Float32Array(result.length);
        report('audio', 'audio.getChannelData', zeroed, true);
        return zeroed;
      }
      if (mode === 'spoof') {
        // Add deterministic noise to the samples to alter the fingerprint
        for (let i = 0; i < result.length; i += 100) {
          result[i] = result[i] + (result[i] * 0.0001);
        }
        report('audio', 'audio.getChannelData', result, true);
        return result;
      }
      report('audio', 'audio.getChannelData', result, false);
      return result;
    };
    AudioBuffer.prototype.getChannelData.toString = () => origGetChannelData.toString();
    Object.defineProperties(AudioBuffer.prototype.getChannelData, {
      length: { value: origGetChannelData.length },
      name: { value: origGetChannelData.name },
    });

    // Also intercept copyFromChannel
    if (AudioBuffer.prototype.copyFromChannel) {
      const origCopyFromChannel = AudioBuffer.prototype.copyFromChannel;
      AudioBuffer.prototype.copyFromChannel = function (dest, channelNumber, startInChannel) {
        const mode = getMode();
        origCopyFromChannel.call(this, dest, channelNumber, startInChannel || 0);
        if (mode === 'ghost') {
          dest.fill(0);
          report('audio', 'audio.copyFromChannel', dest, true);
          return;
        }
        if (mode === 'spoof') {
          for (let i = 0; i < dest.length; i += 100) {
            dest[i] = dest[i] + (dest[i] * 0.0001);
          }
          report('audio', 'audio.copyFromChannel', dest, true);
          return;
        }
        report('audio', 'audio.copyFromChannel', dest, false);
      };
      AudioBuffer.prototype.copyFromChannel.toString = () => origCopyFromChannel.toString();
      Object.defineProperties(AudioBuffer.prototype.copyFromChannel, {
        length: { value: origCopyFromChannel.length },
        name: { value: origCopyFromChannel.name },
      });
    }
  }

  // Also intercept AnalyserNode.getFloatFrequencyData / getByteFrequencyData
  if (typeof AnalyserNode !== 'undefined') {
    const analyserMethods = ['getFloatFrequencyData', 'getByteFrequencyData', 'getFloatTimeDomainData', 'getByteTimeDomainData'];
    for (const method of analyserMethods) {
      if (!AnalyserNode.prototype[method]) continue;
      const orig = AnalyserNode.prototype[method];
      AnalyserNode.prototype[method] = function (array) {
        const mode = getMode();
        orig.call(this, array);
        if (mode === 'ghost') {
          if (array instanceof Float32Array) array.fill(-Infinity);
          else array.fill(0);
          report('audio', `audio.${method}`, array, true);
          return;
        }
        if (mode === 'spoof') {
          for (let i = 0; i < array.length; i += 100) {
            if (array instanceof Float32Array) {
              array[i] = array[i] + (array[i] * 0.0001);
            } else {
              array[i] = array[i] ^ 1;
            }
          }
          report('audio', `audio.${method}`, array, true);
          return;
        }
        report('audio', `audio.${method}`, array, false);
      };
      AnalyserNode.prototype[method].toString = () => orig.toString();
      Object.defineProperties(AnalyserNode.prototype[method], {
        length: { value: orig.length },
        name: { value: orig.name },
      });
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // PLUGINS / MIMETYPES
  // ════════════��═════════════════════════════��════════════════════════════
  wrapGetter(Navigator.prototype, 'plugins', 'plugins', 'navigator.plugins');
  wrapGetter(Navigator.prototype, 'mimeTypes', 'plugins', 'navigator.mimeTypes');

  // ══════════════════���════════════════════════════���═══════════════════════
  // HARDWARE
  // ═══════════════════════════��═══════════════════════════════════════════
  wrapGetter(Navigator.prototype, 'hardwareConcurrency', 'hardware', 'navigator.hardwareConcurrency');
  wrapGetter(Navigator.prototype, 'deviceMemory', 'hardware', 'navigator.deviceMemory');
  wrapGetter(Navigator.prototype, 'maxTouchPoints', 'hardware', 'navigator.maxTouchPoints');

  // ═══���═══════════════════════════════════════════════════════════════════
  // SCREEN
  // ════════════��════════════════════════��═════════════════════════════════
  const screenProps = ['width', 'height', 'colorDepth', 'pixelDepth', 'availWidth', 'availHeight'];
  for (const prop of screenProps) {
    wrapGetter(Screen.prototype, prop, 'screen', `screen.${prop}`);
  }
  wrapGetter(Window.prototype, 'devicePixelRatio', 'screen', 'window.devicePixelRatio');

  // ══════════════════════════════════════════════��════════════════════════
  // FONTS (detect rapid measureText calls)
  // ═══════════════���════════════════════════════���══════════════════════════
  if (typeof CanvasRenderingContext2D !== 'undefined') {
    const measureTextState = new WeakMap();
    const origMeasureText = CanvasRenderingContext2D.prototype.measureText;

    CanvasRenderingContext2D.prototype.measureText = function (...args) {
      const mode = getMode();
      const canvas = this.canvas;
      let state = measureTextState.get(canvas);
      if (!state) {
        state = { count: 0, timer: null };
        measureTextState.set(canvas, state);
      }
      state.count++;

      if (state.timer) clearTimeout(state.timer);
      state.timer = setTimeout(() => {
        if (state.count > 20) {
          report('fonts', `fonts.measureText (${state.count} calls)`, undefined, mode !== 'detect');
        }
        state.count = 0;
      }, 500);

      if (mode === 'ghost') {
        // Return a fixed-width measurement to prevent font enumeration
        return origMeasureText.call(this, 'X');
      }

      return origMeasureText.apply(this, args);
    };
    CanvasRenderingContext2D.prototype.measureText.toString = () => origMeasureText.toString();
    Object.defineProperties(CanvasRenderingContext2D.prototype.measureText, {
      length: { value: origMeasureText.length },
      name: { value: origMeasureText.name },
    });
  }

  // ═══════════════════════════════════════════════════════════════════════
  // CSS FONT ENUMERATION PROTECTION
  // ═══════════════════════════════════════════════════════════════════════
  // Font fingerprinting works by creating a hidden <span>, setting its
  // font-family to "TestFont, fallback", and checking if offsetWidth
  // differs from the fallback-only width. If a font is installed, the
  // width changes. We intercept offsetWidth/offsetHeight to return
  // consistent values when rapid font probing is detected.
  (function () {
    const fontProbeTracker = { count: 0, timer: null, active: false };
    const FONT_PROBE_THRESHOLD = 10; // >10 rapid offset reads = likely font enumeration
    const FONT_PROBE_WINDOW = 500;   // ms

    function trackFontProbe() {
      fontProbeTracker.count++;
      if (fontProbeTracker.timer) clearTimeout(fontProbeTracker.timer);
      fontProbeTracker.timer = setTimeout(() => {
        if (fontProbeTracker.count > FONT_PROBE_THRESHOLD) {
          fontProbeTracker.active = true;
          report('fonts', `fonts.cssProbe (${fontProbeTracker.count} reads)`, undefined, getMode() !== 'detect');
          // Keep active for a while to catch continued probing
          setTimeout(() => { fontProbeTracker.active = false; }, 2000);
        }
        fontProbeTracker.count = 0;
      }, FONT_PROBE_WINDOW);
    }

    // Intercept offsetWidth and offsetHeight on HTMLElement
    for (const prop of ['offsetWidth', 'offsetHeight']) {
      const desc = Object.getOwnPropertyDescriptor(HTMLElement.prototype, prop);
      if (!desc || !desc.get) continue;
      const originalGet = desc.get;
      Object.defineProperty(HTMLElement.prototype, prop, {
        ...desc,
        get() {
          const mode = getMode();
          const realValue = originalGet.call(this);
          if (mode !== 'detect') {
            trackFontProbe();
            if (fontProbeTracker.active) {
              // Return a fixed value so all fonts appear the same
              return prop === 'offsetWidth' ? 60 : 18;
            }
          }
          return realValue;
        },
      });
    }
  })();

  // ═══════════════════════════════════════════════════════════════════════
  // WEBRTC (IP leak fingerprinting)
  // ═══════════════════════════════════════════════════════════════════════
  wrapConstructor(window, 'RTCPeerConnection', 'webrtc', 'RTCPeerConnection');
  if (window.webkitRTCPeerConnection) {
    wrapConstructor(window, 'webkitRTCPeerConnection', 'webrtc', 'webkitRTCPeerConnection');
  }

  // ══════════���══════════════════���═════════════════════════════════════════
  // BATTERY
  // ══���════════════════════════════════════════════════════════════════════
  if (Navigator.prototype.getBattery) {
    wrapAsyncMethod(Navigator.prototype, 'getBattery', 'battery', 'navigator.getBattery');
  }

  // ══��══════════════════════════════════���═════════════════════════════════
  // USER AGENT / PLATFORM
  // ═══════════════���══════════════════════════��════════════════════════════
  wrapGetter(Navigator.prototype, 'userAgent', 'ua_platform', 'navigator.userAgent');
  wrapGetter(Navigator.prototype, 'platform', 'ua_platform', 'navigator.platform');
  wrapGetter(Navigator.prototype, 'language', 'ua_platform', 'navigator.language');
  wrapGetter(Navigator.prototype, 'languages', 'ua_platform', 'navigator.languages');
  wrapGetter(Navigator.prototype, 'vendor', 'ua_platform', 'navigator.vendor');

  // ═══���════════════════════════════════════════════════════════��══════════
  // STORAGE ESTIMATION
  // ═══════════════════���═════════════════════════════��═════════════════════
  if (typeof StorageManager !== 'undefined' && StorageManager.prototype.estimate) {
    wrapAsyncMethod(StorageManager.prototype, 'estimate', 'storage', 'storage.estimate');
  }

  // ══════════════════════════════��════════════════════════════���═══════════
  // NETWORK / CONNECTION
  // ══════���════════════════════════════════════════════���═══════════════════
  if (typeof NetworkInformation !== 'undefined') {
    const connProps = ['type', 'effectiveType', 'downlink', 'rtt', 'saveData'];
    for (const prop of connProps) {
      wrapGetter(NetworkInformation.prototype, prop, 'connection', `connection.${prop}`);
    }
  }

  // ═════════���═══════════════════════════════════════════════���═════════════
  // MEDIA DEVICES
  // ═══════════════════��════════════════════════════���══════════════════════
  if (typeof MediaDevices !== 'undefined' && MediaDevices.prototype.enumerateDevices) {
    wrapAsyncMethod(MediaDevices.prototype, 'enumerateDevices', 'hardware', 'mediaDevices.enumerateDevices');
  }

  // ═══════���═══════════════════════════════════════════════════════════════
  // CLIENT HINTS / HIGH ENTROPY VALUES
  // ══════��════════════════════════════════════════════��═══════════════════
  if (typeof NavigatorUAData !== 'undefined' && NavigatorUAData.prototype.getHighEntropyValues) {
    wrapAsyncMethod(NavigatorUAData.prototype, 'getHighEntropyValues', 'ua_platform', 'userAgentData.getHighEntropyValues');
  }

  // ═══════════════════════════════════════════════════════════════════════
  // ADDITIONAL FINGERPRINT VECTORS
  // ═══════════════════════════════════════════════════════════════════════

  // navigator.doNotTrack
  if ('doNotTrack' in Navigator.prototype || 'doNotTrack' in navigator) {
    const dntDescriptor = Object.getOwnPropertyDescriptor(Navigator.prototype, 'doNotTrack')
      || Object.getOwnPropertyDescriptor(navigator, 'doNotTrack');
    if (dntDescriptor && dntDescriptor.get) {
      wrapGetter(Navigator.prototype, 'doNotTrack', 'ua_platform', 'navigator.doNotTrack');
      GHOST['navigator.doNotTrack'] = () => null;
      SPOOF['navigator.doNotTrack'] = () => null;
    }
  }

  // navigator.cookieEnabled
  if ('cookieEnabled' in Navigator.prototype) {
    wrapGetter(Navigator.prototype, 'cookieEnabled', 'ua_platform', 'navigator.cookieEnabled');
    GHOST['navigator.cookieEnabled'] = () => true;
    SPOOF['navigator.cookieEnabled'] = () => true;
  }

  // Intl.DateTimeFormat timezone spoofing
  if (typeof Intl !== 'undefined' && Intl.DateTimeFormat) {
    const origResolvedOptions = Intl.DateTimeFormat.prototype.resolvedOptions;
    Intl.DateTimeFormat.prototype.resolvedOptions = function () {
      const mode = getMode();
      const result = origResolvedOptions.call(this);
      if (mode === 'ghost' || mode === 'spoof') {
        // Override timezone to a common default
        const spoofed = Object.assign({}, result, { timeZone: 'America/New_York' });
        report('ua_platform', 'Intl.DateTimeFormat.timeZone', spoofed.timeZone, true);
        return spoofed;
      }
      report('ua_platform', 'Intl.DateTimeFormat.timeZone', result.timeZone, false);
      return result;
    };
    Intl.DateTimeFormat.prototype.resolvedOptions.toString = () => origResolvedOptions.toString();
    Object.defineProperties(Intl.DateTimeFormat.prototype.resolvedOptions, {
      length: { value: origResolvedOptions.length },
      name: { value: origResolvedOptions.name },
    });
  }

  // Date.getTimezoneOffset — spoof to match America/New_York
  const origGetTimezoneOffset = Date.prototype.getTimezoneOffset;
  Date.prototype.getTimezoneOffset = function () {
    const mode = getMode();
    if (mode === 'ghost' || mode === 'spoof') {
      // EST = +300 (5 hours behind UTC), EDT = +240
      // Use +300 (standard time) for consistency
      report('ua_platform', 'Date.getTimezoneOffset', 300, true);
      return 300;
    }
    const result = origGetTimezoneOffset.call(this);
    report('ua_platform', 'Date.getTimezoneOffset', result, false);
    return result;
  };
  Date.prototype.getTimezoneOffset.toString = () => origGetTimezoneOffset.toString();
  Object.defineProperties(Date.prototype.getTimezoneOffset, {
    length: { value: origGetTimezoneOffset.length },
    name: { value: origGetTimezoneOffset.name },
  });

  // ═══════════════════════════════════════════════════════════════════════
  // EXTENSION ENUMERATION DETECTION
  // ═══════════════════════════════════════════════════════════════════════
  // Websites probe chrome-extension://<guid>/<resource> URLs to detect
  // which extensions are installed. We intercept fetch, XHR, and element
  // src/href setters to catch these probes and log the GUIDs targeted.

  const EXT_URL_RE = /^chrome-extension:\/\/([a-p]{32}|[a-f0-9-]{36})\/?/i;
  const SELF_EXT_ID = document.documentElement?.dataset?.fpExtId || '';

  function extractExtensionId(url) {
    if (!url || typeof url !== 'string') return null;
    const match = url.match(EXT_URL_RE);
    return match ? match[1] : null;
  }

  function reportExtensionProbe(method, url) {
    const extId = extractExtensionId(url);
    if (!extId) return;
    // Don't report probes for our own extension
    if (SELF_EXT_ID && extId.toLowerCase() === SELF_EXT_ID.toLowerCase()) return;
    report('extensions', `ext.probe.${method}`, extId, false);
  }

  // ─── fetch() ────────────────────────────────────────────────────────
  const origFetch = window.fetch;
  window.fetch = function (input, init) {
    const url = (typeof input === 'string') ? input : (input && input.url) || '';
    reportExtensionProbe('fetch', url);
    return origFetch.apply(this, arguments);
  };
  window.fetch.toString = () => origFetch.toString();
  Object.defineProperties(window.fetch, {
    length: { value: origFetch.length },
    name: { value: origFetch.name },
  });

  // ─── XMLHttpRequest.open() ──────────────────────────────────────────
  const origXHROpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url) {
    reportExtensionProbe('xhr', url);
    return origXHROpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.open.toString = () => origXHROpen.toString();
  Object.defineProperties(XMLHttpRequest.prototype.open, {
    length: { value: origXHROpen.length },
    name: { value: origXHROpen.name },
  });

  // ─── Element src/href setters (Image, script, link, iframe) ─────────
  const elementsToWatch = [
    [HTMLImageElement, 'src'],
    [HTMLScriptElement, 'src'],
    [HTMLLinkElement, 'href'],
    [HTMLIFrameElement, 'src'],
  ];

  for (const [Ctor, prop] of elementsToWatch) {
    const desc = Object.getOwnPropertyDescriptor(Ctor.prototype, prop);
    if (!desc || !desc.set) continue;
    const originalSet = desc.set;
    Object.defineProperty(Ctor.prototype, prop, {
      ...desc,
      set(value) {
        reportExtensionProbe(`element.${Ctor.name}.${prop}`, value);
        return originalSet.call(this, value);
      },
    });
  }

  // ─── document.createElement + setAttribute interception ─────────────
  // Some probes set src/href via setAttribute instead of the property
  const origSetAttribute = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (name, value) {
    if ((name === 'src' || name === 'href') && typeof value === 'string') {
      reportExtensionProbe('setAttribute', value);
    }
    return origSetAttribute.call(this, name, value);
  };
  Element.prototype.setAttribute.toString = () => origSetAttribute.toString();
  Object.defineProperties(Element.prototype.setAttribute, {
    length: { value: origSetAttribute.length },
    name: { value: origSetAttribute.name },
  });
})();
