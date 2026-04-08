// Fingerprint Detector - Background Service Worker
// Tracks detections per tab, updates badge, provides data to popup
// Manages per-site and global mode settings (detect/ghost/spoof)

const tabData = new Map();
const MAX_ENTRIES_PER_TAB = 10000;

const CATEGORY_LABELS = {
  canvas: 'Canvas',
  webgl: 'WebGL',
  audio: 'Audio',
  plugins: 'Plugins',
  hardware: 'Hardware',
  screen: 'Screen',
  fonts: 'Fonts',
  webrtc: 'WebRTC',
  battery: 'Battery',
  ua_platform: 'UA / Platform',
  storage: 'Storage',
  connection: 'Connection',
};

function getSeverity(data) {
  const categories = new Set(Object.keys(data.categoryCounts));
  const total = data.totalCount || data.entries.length;
  const catCount = categories.size;

  const suspiciousCategories = ['audio', 'fonts', 'webrtc', 'battery', 'connection', 'storage'];
  const suspiciousCount = suspiciousCategories.filter((c) => categories.has(c)).length;

  const hasCanvas = categories.has('canvas');
  const hasWebgl = categories.has('webgl');
  const hasAudio = categories.has('audio');
  const aggressiveCombo = hasCanvas && hasWebgl && hasAudio;

  if (
    (catCount >= 8 && total >= 100) ||
    (aggressiveCombo && total >= 75) ||
    (suspiciousCount >= 3 && total >= 50) ||
    total >= 200
  ) {
    return 'high';
  }

  if (
    (catCount >= 5 && total >= 30) ||
    (suspiciousCount >= 2 && total >= 20) ||
    (aggressiveCombo && total >= 15) ||
    total >= 75
  ) {
    return 'medium';
  }

  return 'low';
}

const SEVERITY_BADGE_BG = {
  low: [76, 175, 80, 255],
  medium: [255, 152, 0, 255],
  high: [244, 67, 54, 255],
};

function updateBadge(tabId) {
  const data = tabData.get(tabId);
  if (!data || data.totalCount === 0) {
    chrome.action.setBadgeText({ tabId, text: '' });
    return;
  }

  const severity = getSeverity(data);
  const count = data.totalCount;
  const text = count > 999 ? '999+' : String(count);

  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({
    tabId,
    color: SEVERITY_BADGE_BG[severity],
  });
  chrome.action.setTitle({
    tabId,
    title: `Fingerprint Detector: ${count} API calls detected (${severity} risk)`,
  });
}

// ─── Mode helpers ──────────────────────────────────────────────────
async function getModeForDomain(domain) {
  const result = await chrome.storage.local.get(['fpGlobalMode', 'fpSiteModes']);
  const siteModes = result.fpSiteModes || {};
  return siteModes[domain] || result.fpGlobalMode || 'detect';
}

async function setModeForDomain(domain, mode) {
  const result = await chrome.storage.local.get(['fpSiteModes']);
  const siteModes = result.fpSiteModes || {};
  if (mode === null) {
    // Remove site-specific override (fall back to global)
    delete siteModes[domain];
  } else {
    siteModes[domain] = mode;
  }
  await chrome.storage.local.set({ fpSiteModes: siteModes });

  // Update HTTP header spoofing rules
  await updateHeaderRules();

  // Broadcast to ALL frames in tabs whose primary domain matches
  const tabs = await chrome.tabs.query({});
  const effectiveMode = mode === null
    ? ((await chrome.storage.local.get(['fpGlobalMode'])).fpGlobalMode || 'detect')
    : mode;
  for (const tab of tabs) {
    try {
      const url = new URL(tab.url || '');
      if (url.hostname === domain) {
        // Send to all frames in this tab (including cross-origin iframes)
        chrome.tabs.sendMessage(tab.id, {
          type: 'fp_mode_changed',
          domain,
          mode: effectiveMode,
        }).catch(() => {});
      }
    } catch (_) {}
  }
}

async function setGlobalMode(mode) {
  await chrome.storage.local.set({ fpGlobalMode: mode });
  await updateHeaderRules();
}

// ─── HTTP Header Spoofing via declarativeNetRequest ────────────────
const SPOOF_UA_HEADER = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

async function updateHeaderRules() {
  // Remove all existing dynamic rules first
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const removeIds = existing.map(r => r.id);
  if (removeIds.length > 0) {
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: removeIds });
  }

  const result = await chrome.storage.local.get(['fpGlobalMode', 'fpSiteModes']);
  const globalMode = result.fpGlobalMode || 'detect';
  const siteModes = result.fpSiteModes || {};
  const rules = [];
  let ruleId = 1;

  // Create rules for each domain with ghost/spoof mode
  for (const [domain, mode] of Object.entries(siteModes)) {
    if (mode === 'ghost' || mode === 'spoof') {
      rules.push({
        id: ruleId++,
        priority: 2,
        action: {
          type: 'modifyHeaders',
          requestHeaders: [
            { header: 'User-Agent', operation: 'set', value: SPOOF_UA_HEADER },
            { header: 'Accept-Language', operation: 'set', value: 'en-US,en;q=0.9' },
          ],
        },
        condition: {
          requestDomains: [domain],
          resourceTypes: ['main_frame', 'sub_frame', 'xmlhttprequest', 'script', 'stylesheet', 'image', 'font', 'media', 'other'],
        },
      });
    }
  }

  // If global mode is ghost/spoof, add a catch-all rule (lower priority)
  if (globalMode === 'ghost' || globalMode === 'spoof') {
    // Exclude domains that are explicitly set to 'detect'
    const detectDomains = Object.entries(siteModes)
      .filter(([_, m]) => m === 'detect')
      .map(([d]) => d);

    const rule = {
      id: ruleId++,
      priority: 1,
      action: {
        type: 'modifyHeaders',
        requestHeaders: [
          { header: 'User-Agent', operation: 'set', value: SPOOF_UA_HEADER },
          { header: 'Accept-Language', operation: 'set', value: 'en-US,en;q=0.9' },
        ],
      },
      condition: {
        resourceTypes: ['main_frame', 'sub_frame', 'xmlhttprequest', 'script', 'stylesheet', 'image', 'font', 'media', 'other'],
      },
    };
    if (detectDomains.length > 0) {
      rule.condition.excludedRequestDomains = detectDomains;
    }
    rules.push(rule);
  }

  if (rules.length > 0) {
    await chrome.declarativeNetRequest.updateDynamicRules({ addRules: rules });
  }
}

// ─── Message handlers ──────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'fp_detected' && sender.tab) {
    const tabId = sender.tab.id;

    // Determine the tab's primary domain from sender.tab.url
    let tabDomain = msg.domain;
    try {
      tabDomain = new URL(sender.tab.url || '').hostname || msg.domain;
    } catch (_) {}

    if (!tabData.has(tabId)) {
      tabData.set(tabId, {
        domain: tabDomain,
        entries: [],
        totalCount: 0,
        categoryCounts: {},
      });
    }

    const data = tabData.get(tabId);
    data.totalCount++;
    data.categoryCounts[msg.category] =
      (data.categoryCounts[msg.category] || 0) + 1;
    // Only update domain from the main frame, not iframes
    if (msg.domain === tabDomain) {
      data.domain = tabDomain;
    }

    if (data.entries.length < MAX_ENTRIES_PER_TAB) {
      data.entries.push({
        category: msg.category,
        api: msg.api,
        timestamp: msg.timestamp,
        stack: msg.stack,
        returnValue: msg.returnValue,
        blocked: msg.blocked || false,
        url: msg.url,
      });
    }

    updateBadge(tabId);
    return;
  }

  // Return the mode for this tab's PRIMARY domain (not iframe domain)
  // so all frames in a tab share one mode.
  if (msg.type === 'get_tab_mode' && sender.tab) {
    let tabDomain = '';
    try {
      tabDomain = new URL(sender.tab.url || '').hostname;
    } catch (_) {}
    getModeForDomain(tabDomain).then((mode) => {
      sendResponse({ mode, tabDomain });
    });
    return true;
  }

  if (msg.type === 'get_data') {
    const tabId = msg.tabId;
    const data = tabData.get(tabId) || {
      domain: '',
      entries: [],
      totalCount: 0,
      categoryCounts: {},
    };
    const severity = data.totalCount > 0 ? getSeverity(data) : 'low';

    // Also return the current mode for this domain
    const domain = data.domain || msg.domain || '';
    getModeForDomain(domain).then((mode) => {
      sendResponse({
        ...data,
        severity,
        mode,
        categoryLabels: CATEGORY_LABELS,
      });
    });
    return true; // async sendResponse
  }

  if (msg.type === 'clear_data') {
    const tabId = msg.tabId;
    tabData.delete(tabId);
    updateBadge(tabId);
    sendResponse({ ok: true });
    return true;
  }

  if (msg.type === 'set_mode') {
    setModeForDomain(msg.domain, msg.mode).then(() => {
      sendResponse({ ok: true });
    });
    return true;
  }

  if (msg.type === 'set_global_mode') {
    setGlobalMode(msg.mode).then(() => {
      sendResponse({ ok: true });
    });
    return true;
  }

  if (msg.type === 'get_mode') {
    chrome.storage.local.get(['fpGlobalMode', 'fpSiteModes'], (result) => {
      const globalMode = result.fpGlobalMode || 'detect';
      const siteModes = result.fpSiteModes || {};
      const siteMode = siteModes[msg.domain];
      const hasSiteOverride = siteMode !== undefined;
      sendResponse({
        mode: hasSiteOverride ? siteMode : globalMode,
        globalMode,
        hasSiteOverride,
      });
    });
    return true;
  }
});

// Clean up when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  tabData.delete(tabId);
});

// Reset when tab navigates to a new page
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading') {
    tabData.delete(tabId);
    updateBadge(tabId);
  }
});

// Initialize header rules on service worker startup
updateHeaderRules().catch(() => {});
