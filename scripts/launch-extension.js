#!/usr/bin/env node
/**
 * Launch Chromium with V1 Helper extension loaded.
 * Uses Playwright's bundled Chromium (bypasses enterprise Chrome policies).
 *
 * Usage: node scripts/launch-extension.js [--url <url>]
 */
const { chromium } = require('playwright');
const path = require('path');

(async () => {
  const extPath = path.resolve(__dirname, '..', 'extension');
  const urlArg = process.argv.find((_, i, a) => a[i - 1] === '--url') || 'about:blank';

  console.log(`Extension: ${extPath}`);
  console.log(`URL: ${urlArg}`);

  const ctx = await chromium.launchPersistentContext('', {
    headless: false,
    args: [
      `--disable-extensions-except=${extPath}`,
      `--load-extension=${extPath}`,
    ]
  });

  // Wait for service worker
  let sw;
  try {
    sw = ctx.serviceWorkers()[0] || await ctx.waitForEvent('serviceworker', { timeout: 5000 });
    console.log(`Service worker: ${sw.url()}`);
  } catch {
    console.log('Warning: service worker did not register in 5s');
  }

  // Navigate to URL if provided
  if (urlArg !== 'about:blank') {
    const page = ctx.pages()[0] || await ctx.newPage();
    await page.goto(urlArg);
  }

  console.log('Browser running. Close the window or Ctrl+C to exit.');

  // Keep alive until browser closes
  ctx.on('close', () => process.exit(0));
  process.on('SIGINT', async () => { await ctx.close(); process.exit(0); });
})().catch(e => { console.error(e.message); process.exit(1); });
