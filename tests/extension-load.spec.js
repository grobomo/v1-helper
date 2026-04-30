/**
 * Playwright test: Load V1 Helper extension in Chrome and verify it works.
 *
 * Run: npx playwright test tests/extension-load.spec.js --headed
 * Or:  node tests/extension-load.spec.js  (standalone mode)
 */

const path = require('path');
const { chromium } = require('playwright');

const EXTENSION_PATH = path.resolve(__dirname, '..', 'extension');

async function runTest() {
  console.log('Loading extension from:', EXTENSION_PATH);

  // Launch Chrome with extension loaded (must be headed + persistent context)
  const context = await chromium.launchPersistentContext('', {
    headless: false,
    args: [
      `--disable-extensions-except=${EXTENSION_PATH}`,
      `--load-extension=${EXTENSION_PATH}`,
      '--no-first-run',
      '--disable-default-apps',
    ],
  });

  const results = { pass: 0, fail: 0, errors: [] };

  function assert(name, condition, detail) {
    if (condition) {
      console.log(`  PASS: ${name}`);
      results.pass++;
    } else {
      console.log(`  FAIL: ${name}${detail ? ' — ' + detail : ''}`);
      results.fail++;
      results.errors.push(name);
    }
  }

  try {
    // 1. Service worker should start
    console.log('\n--- Service Worker ---');
    let sw = context.serviceWorkers()[0];
    if (!sw) {
      console.log('  Waiting for service worker...');
      sw = await context.waitForEvent('serviceworker', { timeout: 10000 });
    }
    assert('Service worker started', !!sw);

    const swUrl = sw.url();
    assert('Service worker URL is chrome-extension://', swUrl.startsWith('chrome-extension://'));

    const extensionId = swUrl.split('/')[2];
    console.log(`  Extension ID: ${extensionId}`);
    assert('Extension ID extracted', extensionId && extensionId.length > 0);

    // 2. Popup should load and render
    console.log('\n--- Popup ---');
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/chrome/popup.html`);
    await popup.waitForLoadState('domcontentloaded');

    // Capture popup console for debugging
    const popupLogs = [];
    popup.on('console', msg => popupLogs.push(`[${msg.type()}] ${msg.text()}`));
    popup.on('pageerror', err => popupLogs.push(`[pageerror] ${err.message}`));

    // Wait for popup JS to render
    await popup.waitForSelector('#root', { timeout: 5000 });
    const rootHtml = await popup.$eval('#root', el => el.innerHTML);
    assert('Popup root element has content', rootHtml.length > 0);

    // Check for V1 Helper branding
    const headerText = await popup.textContent('.popup-header');
    if (headerText && headerText.includes('Error')) {
      const errorText = await popup.textContent('#root');
      console.log('  Popup error details:', errorText);
      console.log('  Popup console:', popupLogs.join('\n    '));
    }
    assert('Popup shows V1 Helper title', headerText && headerText.includes('V1 Helper'), `got: "${headerText}"`);

    // Check version is rendered
    assert('Version label present', headerText && headerText.includes('v0.1.0'), `got: "${headerText}"`);

    // Check MCP status section
    const statusText = await popup.textContent('.status-row');
    assert('MCP Status row present', statusText && statusText.includes('MCP Status'));

    // Check CVE analysis section
    const v1Section = await popup.textContent('.v1-section');
    assert('CVE Analysis section present', v1Section && v1Section.includes('CVE Analysis'));
    assert('Import button present', v1Section && v1Section.includes('Import analysis.json'));

    // Check toggle button
    const toggleBtn = await popup.$('#toggleButton');
    assert('Toggle button exists', !!toggleBtn);
    const toggleText = await toggleBtn.textContent();
    assert('Toggle shows Disable (extension enabled by default)', toggleText.trim() === 'Disable');

    // Check settings link
    const settingsBtn = await popup.$('#settingsButton');
    assert('Settings button exists', !!settingsBtn);

    // 3. Settings page should render
    console.log('\n--- Settings ---');
    await settingsBtn.click();
    await popup.waitForSelector('#portInput', { timeout: 3000 });

    const portValue = await popup.$eval('#portInput', el => el.value);
    assert('Port default is 5555', portValue === '5555');

    const debugCheckbox = await popup.$('#debugModeCheckbox');
    assert('Debug mode checkbox exists', !!debugCheckbox);
    const isChecked = await debugCheckbox.isChecked();
    assert('Debug mode off by default', !isChecked);

    // Cancel back to main
    const cancelBtn = await popup.$('#cancelButton');
    await cancelBtn.click();
    await popup.waitForSelector('#toggleButton', { timeout: 3000 });
    assert('Cancel returns to main view', true);

    // 4. Content script — verify it loads on a real page without errors
    console.log('\n--- Content Script ---');
    const testPage = await context.newPage();
    const pageErrors = [];
    testPage.on('pageerror', err => pageErrors.push(err.message));
    await testPage.goto('https://example.com', { waitUntil: 'domcontentloaded' });
    // Wait for content script to run (it fires tech stack detection after 100ms)
    await new Promise(r => setTimeout(r, 500));
    assert('No page errors after content script injection', pageErrors.length === 0,
      pageErrors.length > 0 ? pageErrors.join('; ') : undefined);

    // Verify service worker is still healthy after page navigation
    const swStillAlive = sw.url().startsWith('chrome-extension://');
    assert('Service worker still active after page load', swStillAlive);

    // 5. Extension icon should be set
    console.log('\n--- Icons ---');
    const iconExists = await popup.evaluate((id) => {
      return new Promise((resolve) => {
        const img = new Image();
        img.onload = () => resolve(true);
        img.onerror = () => resolve(false);
        img.src = `chrome-extension://${id}/icons/icon-128.png`;
      });
    }, extensionId);
    assert('128px icon loads', iconExists);

    // 6. No console errors in popup
    console.log('\n--- Error Check ---');
    const consoleErrors = [];
    popup.on('console', msg => {
      if (msg.type() === 'error') consoleErrors.push(msg.text());
    });
    // Reload popup to catch any errors
    await popup.reload();
    await popup.waitForSelector('#root', { timeout: 5000 });
    // Brief wait for any async errors
    await new Promise(r => setTimeout(r, 1000));
    assert('No console errors in popup', consoleErrors.length === 0,
      consoleErrors.length > 0 ? consoleErrors.join('; ') : undefined);

    await testPage.close();
    await popup.close();

  } catch (err) {
    console.error('\nTest error:', err.message);
    results.fail++;
    results.errors.push(`Unexpected: ${err.message}`);
  } finally {
    await context.close();
  }

  // Summary
  console.log('\n========================================');
  console.log(`Results: ${results.pass} passed, ${results.fail} failed`);
  if (results.errors.length > 0) {
    console.log('Failed:', results.errors.join(', '));
  }
  console.log('========================================\n');

  process.exit(results.fail > 0 ? 1 : 0);
}

runTest().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});
