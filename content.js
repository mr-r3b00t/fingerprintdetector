// Fingerprint Detector - Content Script
// Bridges between page-level inject.js and the background service worker
// Also bridges mode state from extension storage to page context via data attribute
(function () {
  'use strict';

  function isExtensionAlive() {
    try {
      return !!chrome.runtime?.id;
    } catch (_) {
      return false;
    }
  }

  if (!isExtensionAlive()) return;

  const frameDomain = window.location.hostname;

  // ─── Set mode on <html> for inject.js to read ───────────────────
  // Content scripts share the DOM with the page, so setting a dataset
  // attribute is visible to inject.js without any inline script (CSP-safe).
  function setMode(mode) {
    if (document.documentElement) {
      document.documentElement.dataset.fpMode = mode || 'detect';
    }
  }

  // Pass our own extension ID to inject.js so it can exclude self-probes
  if (document.documentElement) {
    document.documentElement.dataset.fpExtId = chrome.runtime.id;
  }

  // Ask background for the mode based on the TAB's primary URL
  // (not the iframe URL) so all frames in a tab share one mode.
  // This message round-trip is faster than the inject.js file fetch,
  // so the mode is set before inject.js wrappers start intercepting.
  chrome.runtime.sendMessage({ type: 'get_tab_mode' }, (response) => {
    if (response && response.mode) {
      setMode(response.mode);
    }
  });

  // ─── Inject the detection script into the page context ───────────
  const script = document.createElement('script');
  script.src = chrome.runtime.getURL('inject.js');
  script.onload = function () {
    this.remove();
  };
  (document.head || document.documentElement).appendChild(script);

  // ─── Listen for mode changes from background (live toggle) ───────
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === 'fp_mode_changed') {
      setMode(msg.mode);
    }
  });

  // ─── Forward detection events from inject.js to background ───────
  function onMessage(e) {
    const selfOrigin = window.location.origin;
    const sameOrigin = selfOrigin === 'null'
      ? e.origin === 'null'
      : e.origin === selfOrigin;
    if (e.source !== window || !sameOrigin || !e.data || e.data.type !== '__fp_detect__') return;

    if (!isExtensionAlive()) {
      window.removeEventListener('message', onMessage);
      return;
    }

    try {
      chrome.runtime.sendMessage({
        type: 'fp_detected',
        category: e.data.category,
        api: e.data.api,
        timestamp: e.data.timestamp,
        stack: e.data.stack || '',
        returnValue: e.data.returnValue,
        blocked: e.data.blocked || false,
        url: window.location.href,
        domain: frameDomain,
      });
    } catch (_) {
      window.removeEventListener('message', onMessage);
    }
  }

  window.addEventListener('message', onMessage);
})();
