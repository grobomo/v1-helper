#!/usr/bin/env node
/**
 * Load analysis.json into a running V1 Helper extension instance.
 * Connects to an existing Chromium via CDP and pushes analysis data
 * into the extension's chrome.storage.local.
 *
 * Usage:
 *   node scripts/load-analysis.js [--customer ep] [--file reports/analysis.json]
 *
 * Requires: Chromium launched with --remote-debugging-port=9222
 *   node scripts/launch-extension.js  (already does this)
 */
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const PROJECT_ROOT = path.resolve(__dirname, '..');

function findAnalysisFile(customer) {
  // Try per-customer first, then shared
  const candidates = [];
  if (customer) {
    candidates.push(path.join(PROJECT_ROOT, 'reports', `${customer}-analysis.json`));
  }
  candidates.push(path.join(PROJECT_ROOT, 'reports', 'analysis.json'));

  for (const p of candidates) {
    if (fs.existsSync(p)) return p;
  }
  return null;
}

(async () => {
  // Parse args
  const args = process.argv.slice(2);
  let customer = null;
  let filePath = null;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--customer' && args[i + 1]) customer = args[++i];
    else if (args[i] === '--file' && args[i + 1]) filePath = args[++i];
  }

  // Find analysis file
  const analysisPath = filePath || findAnalysisFile(customer);
  if (!analysisPath) {
    console.error('No analysis file found. Run report first or specify --file.');
    process.exit(1);
  }

  console.log(`Loading analysis from: ${analysisPath}`);

  // Load and normalize analysis data
  let raw = JSON.parse(fs.readFileSync(analysisPath, 'utf8'));
  let analyses;
  if (Array.isArray(raw)) {
    analyses = {};
    for (const a of raw) {
      if (a.cve) analyses[a.cve] = a;
    }
  } else {
    analyses = raw;
  }
  console.log(`  ${Object.keys(analyses).length} CVEs loaded`);

  // Launch extension in Chromium
  const extPath = path.resolve(PROJECT_ROOT, 'extension');
  const ctx = await chromium.launchPersistentContext('', {
    headless: false,
    args: [
      `--disable-extensions-except=${extPath}`,
      `--load-extension=${extPath}`,
    ]
  });

  // Wait for service worker
  let sw = ctx.serviceWorkers()[0];
  if (!sw) {
    sw = await ctx.waitForEvent('serviceworker', { timeout: 10000 });
  }
  console.log(`  Extension loaded: ${sw.url().split('/')[2]}`);

  // Push analysis data into extension storage
  await sw.evaluate((data) => {
    return chrome.storage.local.set({
      v1h_analysis: data,
      v1h_overlay_enabled: true,
    });
  }, analyses);

  // Verify
  const stored = await sw.evaluate(() => chrome.storage.local.get('v1h_analysis'));
  const count = Object.keys(stored.v1h_analysis || {}).length;
  console.log(`  Loaded ${count} CVEs into extension storage`);

  // Count by relevance
  let yes = 0, low = 0, no = 0;
  for (const a of Object.values(stored.v1h_analysis || {})) {
    const r = (a.relevant || '').toLowerCase();
    if (r === 'yes') yes++;
    else if (r === 'low') low++;
    else if (r === 'no') no++;
  }
  console.log(`  Relevant: ${yes} | Low: ${low} | Not relevant: ${no}`);
  console.log('\nBrowser running with analysis loaded. Navigate to V1 console to see overlays.');
  console.log('Close the window or Ctrl+C to exit.');

  ctx.on('close', () => process.exit(0));
  process.on('SIGINT', async () => { await ctx.close(); process.exit(0); });
})().catch(e => { console.error(e.message); process.exit(1); });
