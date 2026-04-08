# Fingerprint Detector

A Chrome extension that detects, blocks, and spoofs browser fingerprinting attempts in real time.

**Copyright Xservus Limited. All rights reserved.**

---

## Disclaimer

This is a **test version**. It is provided as-is with **no warranty, no support, and no guarantee of functionality**. Use at your own risk. Xservus Limited accepts no liability for any issues arising from the use of this software.

---

## What it does

Websites use browser fingerprinting to track you without cookies. They probe dozens of browser APIs (canvas, WebGL, audio, screen size, fonts, plugins, hardware info, etc.) to build a unique identifier for your browser.

Fingerprint Detector intercepts these API calls and gives you three modes:

| Mode | What it does |
|------|-------------|
| **Detect** | Monitors fingerprinting API calls without interfering. Shows you exactly what a site is probing. |
| **Ghost** | Returns common generic values for all fingerprinting APIs. Blocks canvas/audio/WebGL data extraction. Spoofs HTTP headers. Makes you blend into the crowd. |
| **Spoof** | Returns uniform fake values (Chrome 120 / Windows 10 / Intel UHD 630) with deterministic noise on canvas and audio. Every visit looks like the same common browser. |

### Features

- Real-time detection of 12+ fingerprinting categories (Canvas, WebGL, Audio, Plugins, Hardware, Screen, Fonts, WebRTC, Battery, UA/Platform, Storage, Connection)
- Per-site mode configuration with global defaults
- HTTP User-Agent and Accept-Language header spoofing via declarativeNetRequest
- CSS font enumeration protection
- Timezone spoofing (Intl.DateTimeFormat + Date.getTimezoneOffset)
- Return value logging showing exactly what data sites extracted
- Blocked call counter with visual indicators
- JSON export of detection reports
- Share results on X/Twitter
- Badge showing detection count and severity (green/orange/red)

---

## Installation

### Step 1: Download the extension

Clone or download this repository to your computer:

```
git clone https://github.com/mr-r3b00t/fingerprintdetector.git
```

Or click **Code > Download ZIP** on GitHub and extract the ZIP file.

### Step 2: Open Chrome Extensions

1. Open Google Chrome
2. Navigate to `chrome://extensions/`
3. Enable **Developer mode** using the toggle in the top-right corner

### Step 3: Load the extension

1. Click **Load unpacked**
2. Select the folder containing the extension files (the folder with `manifest.json` in it)
3. The extension icon should appear in your Chrome toolbar

### Step 4: Pin the extension (optional)

1. Click the puzzle piece icon in the Chrome toolbar
2. Find **Fingerprint Detector** in the list
3. Click the pin icon to keep it visible in the toolbar

---

## Usage

1. Visit any website
2. Click the Fingerprint Detector icon in the toolbar
3. The popup shows all detected fingerprinting API calls, grouped by category
4. Use the **Detect / Ghost / Spoof** toggle to change protection mode
5. Click **Set for site** to save the mode for the current domain, or **Set as default** for all sites
6. Click **Export** to download a JSON report of all detections
7. Click **Post on X** to share your findings

### Modes explained

- **Detect**: Passive monitoring only. See what sites are doing without changing anything.
- **Ghost**: Active protection. Returns the most common browser values so you blend in with millions of other Chrome users. Blocks canvas pixel extraction, audio fingerprinting, and WebRTC IP leaks.
- **Spoof**: Returns a fixed fake identity (Chrome 120 on Windows 10 with Intel UHD 630 graphics). Adds deterministic noise to canvas and audio so your fingerprint is consistent per-domain but different from your real one.

---

## Tested against

- [EFF Cover Your Tracks](https://coveryourtracks.eff.org/) - Achieves "randomized fingerprint" status in Ghost mode
- LinkedIn, Google, Facebook, and other high-fingerprinting sites

---

## Acknowledgements

Thanks to **Horatio** for suggesting the share to social media feature!

---

## License

Copyright Xservus Limited. All rights reserved.

This software is proprietary. No license is granted for redistribution, modification, or commercial use without explicit written permission from Xservus Limited.

---

## Contact

- GitHub: [github.com/mr-r3b00t/fingerprintdetector](https://github.com/mr-r3b00t/fingerprintdetector)
- Twitter/X: [@UK_Daniel_Card](https://twitter.com/UK_Daniel_Card)
