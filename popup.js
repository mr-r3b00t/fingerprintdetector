// Fingerprint Detector - Popup Script

const CATEGORY_ICONS = {
  canvas: '\uD83C\uDFA8',
  webgl: '\uD83D\uDD3A',
  audio: '\uD83D\uDD0A',
  plugins: '\uD83E\uDDE9',
  hardware: '\uD83D\uDDA5\uFE0F',
  screen: '\uD83D\uDCF1',
  fonts: '\uD83D\uDD24',
  webrtc: '\uD83C\uDF10',
  battery: '\uD83D\uDD0B',
  ua_platform: '\uD83D\uDD0D',
  storage: '\uD83D\uDCBE',
  connection: '\uD83D\uDCF6',
};

function formatTime(ts) {
  const d = new Date(ts);
  return d.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function truncateStack(stack) {
  if (!stack) return '';
  return stack
    .replace(/^\s*at\s+/, '')
    .substring(0, 120);
}

// ─── Mode toggle ──────────────────────────────────────────────────
let currentMode = 'detect';
let currentGlobalMode = 'detect';
let currentDomain = '';
let hasSiteOverride = false;

function setActiveMode(mode) {
  currentMode = mode;
  document.querySelectorAll('.mode-btn').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.mode === mode);
  });
  document.body.dataset.mode = mode;
}

function updateModeScope() {
  const scopeEl = document.getElementById('mode-scope');
  const resetBtn = document.getElementById('reset-site-btn');

  if (hasSiteOverride) {
    scopeEl.textContent = `Site: ${currentDomain}`;
    scopeEl.className = 'mode-scope mode-scope-site';
    resetBtn.style.display = '';
  } else {
    scopeEl.textContent = `Global default (${currentGlobalMode})`;
    scopeEl.className = 'mode-scope mode-scope-global';
    resetBtn.style.display = 'none';
  }
}

// Toggle buttons only change the visual selection — don't save until user clicks an action
document.getElementById('mode-toggle').addEventListener('click', (e) => {
  const btn = e.target.closest('.mode-btn');
  if (!btn) return;
  setActiveMode(btn.dataset.mode);
});

// "Set for site" — save mode for this specific domain
document.getElementById('set-site-btn').addEventListener('click', () => {
  if (!currentDomain) return;
  chrome.runtime.sendMessage({
    type: 'set_mode',
    domain: currentDomain,
    mode: currentMode,
  }, () => {
    hasSiteOverride = true;
    updateModeScope();
    flashButton('set-site-btn', 'Site set!', 'Set for site');
  });
});

// "Set as default" — save mode as global default
document.getElementById('set-default-btn').addEventListener('click', () => {
  chrome.runtime.sendMessage({
    type: 'set_global_mode',
    mode: currentMode,
  }, () => {
    currentGlobalMode = currentMode;
    updateModeScope();
    flashButton('set-default-btn', 'Default set!', 'Set as default');
  });
});

// "Reset to default" — remove site-specific override
document.getElementById('reset-site-btn').addEventListener('click', () => {
  if (!currentDomain) return;
  chrome.runtime.sendMessage({
    type: 'set_mode',
    domain: currentDomain,
    mode: null, // null = remove override
  }, () => {
    hasSiteOverride = false;
    setActiveMode(currentGlobalMode);
    updateModeScope();
  });
});

function flashButton(id, flashText, originalText) {
  const btn = document.getElementById(id);
  btn.textContent = flashText;
  btn.classList.add('flash');
  setTimeout(() => {
    btn.textContent = originalText;
    btn.classList.remove('flash');
  }, 1500);
}

// ─── Render data ──────────────────────────────────────────────────
function renderData(data) {
  const domainEl = document.getElementById('domain');
  const summaryEl = document.getElementById('summary');
  const categoriesEl = document.getElementById('categories');
  const emptyEl = document.getElementById('empty');

  const shareBar = document.getElementById('share-bar');
  const totalCount = data ? (data.totalCount || data.entries.length) : 0;
  if (!data || totalCount === 0) {
    domainEl.textContent = '';
    summaryEl.innerHTML = '';
    categoriesEl.innerHTML = '';
    emptyEl.style.display = 'block';
    shareBar.style.display = 'none';
    return;
  }

  emptyEl.style.display = 'none';
  shareBar.style.display = '';
  domainEl.textContent = data.domain;

  const total = totalCount;
  const severity = data.severity;
  const severityLabel =
    severity === 'high'
      ? 'High Risk'
      : severity === 'medium'
        ? 'Moderate'
        : 'Low';

  const blockedCount = data.entries.filter((e) => e.blocked).length;
  const blockedLabel = blockedCount > 0
    ? ` <span class="blocked-count">${blockedCount} blocked</span>`
    : '';

  summaryEl.innerHTML = `
    <span class="severity-badge severity-${escapeHtml(severity)}">${escapeHtml(severityLabel)}</span>
    <span class="total-count">${total} API call${total !== 1 ? 's' : ''} detected${blockedLabel}</span>
  `;

  // Group entries by category
  const grouped = {};
  for (const entry of data.entries) {
    if (!grouped[entry.category]) {
      grouped[entry.category] = [];
    }
    grouped[entry.category].push(entry);
  }

  const sortedCategories = Object.keys(grouped).sort(
    (a, b) => grouped[b].length - grouped[a].length
  );

  categoriesEl.innerHTML = '';

  for (const cat of sortedCategories) {
    const entries = grouped[cat];
    const label = data.categoryLabels[cat] || cat;
    const icon = CATEGORY_ICONS[cat] || '\u2753';

    const catDiv = document.createElement('div');
    catDiv.className = 'category';

    const headerDiv = document.createElement('div');
    headerDiv.className = 'category-header';
    headerDiv.innerHTML = `
      <span class="category-name">
        <span class="arrow">\u25B6</span>
        <span class="category-icon">${escapeHtml(icon)}</span>
        ${escapeHtml(label)}
      </span>
      <span class="category-count">${entries.length}</span>
    `;

    headerDiv.addEventListener('click', () => {
      catDiv.classList.toggle('expanded');
    });

    const entriesDiv = document.createElement('div');
    entriesDiv.className = 'category-entries';

    const apiCounts = {};
    const apiFirst = {};
    const apiLastReturn = {};
    const apiBlocked = {};
    for (const entry of entries) {
      if (!apiCounts[entry.api]) {
        apiCounts[entry.api] = 0;
        apiFirst[entry.api] = entry;
        apiBlocked[entry.api] = false;
      }
      apiCounts[entry.api]++;
      if (entry.returnValue !== undefined) {
        apiLastReturn[entry.api] = entry.returnValue;
      }
      if (entry.blocked) {
        apiBlocked[entry.api] = true;
      }
    }

    for (const [api, count] of Object.entries(apiCounts)) {
      const entry = apiFirst[api];
      const returnVal = apiLastReturn[api];
      const blocked = apiBlocked[api];
      const entryDiv = document.createElement('div');
      entryDiv.className = 'entry' + (blocked ? ' entry-blocked' : '');
      entryDiv.innerHTML = `
        <div class="entry-api">${blocked ? '<span class="blocked-badge">BLOCKED</span> ' : ''}${escapeHtml(api)}${count > 1 ? ` <span style="color:#999;font-weight:400;">\u00D7${count}</span>` : ''}</div>
        ${returnVal !== undefined ? `<div class="entry-return">\u2192 ${escapeHtml(String(returnVal))}</div>` : ''}
        <div class="entry-meta">
          <span>${formatTime(entry.timestamp)}</span>
        </div>
        ${entry.stack ? `<div class="entry-stack">${escapeHtml(truncateStack(entry.stack))}</div>` : ''}
      `;
      entriesDiv.appendChild(entryDiv);
    }

    catDiv.appendChild(headerDiv);
    catDiv.appendChild(entriesDiv);
    categoriesEl.appendChild(catDiv);
  }
}

// ─── Load data ────────────────────────────────────────────────────
let currentData = null;

async function loadData() {
  const [tab] = await chrome.tabs.query({
    active: true,
    currentWindow: true,
  });

  if (!tab) return;

  // Extract domain from the tab URL
  try {
    const url = new URL(tab.url || '');
    currentDomain = url.hostname;
  } catch (_) {
    currentDomain = '';
  }

  // Fetch detection data and mode info in parallel
  chrome.runtime.sendMessage(
    { type: 'get_data', tabId: tab.id, domain: currentDomain },
    (response) => {
      if (response) {
        currentData = response;
        renderData(response);
      }
    }
  );

  chrome.runtime.sendMessage(
    { type: 'get_mode', domain: currentDomain },
    (response) => {
      if (response) {
        currentGlobalMode = response.globalMode || 'detect';
        hasSiteOverride = response.hasSiteOverride || false;
        setActiveMode(response.mode || 'detect');
        updateModeScope();
      }
    }
  );
}

// ─── Export button ────────────────────────────────────────────────
document.getElementById('export-btn').addEventListener('click', () => {
  if (!currentData || (currentData.totalCount || currentData.entries.length) === 0) return;

  const report = {
    exportedAt: new Date().toISOString(),
    domain: currentData.domain,
    mode: currentMode,
    severity: currentData.severity,
    totalApiCalls: currentData.totalCount || currentData.entries.length,
    entriesCapped: currentData.entries.length < (currentData.totalCount || currentData.entries.length),
    categorySummary: Object.entries(currentData.categoryCounts).map(
      ([category, count]) => ({
        category,
        label: currentData.categoryLabels[category] || category,
        count,
      })
    ),
    entries: currentData.entries.map((e) => ({
      category: e.category,
      api: e.api,
      returnValue: e.returnValue !== undefined ? e.returnValue : null,
      blocked: e.blocked || false,
      timestamp: new Date(e.timestamp).toISOString(),
      stack: e.stack || null,
      url: e.url,
    })),
  };

  const blob = new Blob([JSON.stringify(report, null, 2)], {
    type: 'application/json',
  });
  const url = URL.createObjectURL(blob);
  const safeDomain = (currentData.domain || 'unknown').replace(/[^a-zA-Z0-9.\-]/g, '_');
  const filename = `fingerprint-report-${safeDomain}-${Date.now()}.json`;

  chrome.downloads.download({ url, filename, saveAs: true }, () => {
    URL.revokeObjectURL(url);
  });
});

// ─── Clear button ─────────────────────────────────────────────────
document.getElementById('clear-btn').addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({
    active: true,
    currentWindow: true,
  });

  if (!tab) return;

  chrome.runtime.sendMessage(
    { type: 'clear_data', tabId: tab.id },
    () => {
      renderData(null);
    }
  );
});

// ─── Share to Twitter/X ───────────────────────────────────────────
document.getElementById('share-twitter-btn').addEventListener('click', () => {
  if (!currentData) return;
  const total = currentData.totalCount || currentData.entries.length;
  const domain = currentData.domain || 'a website';
  const text = `We found ${total} trackers on ${domain} using FingerprintDetector by @UK_Daniel_Card`;
  const url = `https://twitter.com/intent/tweet?text=${encodeURIComponent(text)}`;
  window.open(url, '_blank');
});

// ─── GitHub link ──────────────────────────────────────────────────
document.getElementById('github-link').addEventListener('click', (e) => {
  e.preventDefault();
  window.open('https://github.com/mr-r3b00t/fingerprintdetector', '_blank');
});

loadData();
