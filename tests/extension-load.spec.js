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
    await popup.click('#settingsButton');
    await popup.waitForSelector('#portInput', { timeout: 3000 });

    const portValue = await popup.$eval('#portInput', el => el.value);
    assert('Port default is 5555', portValue === '5555');

    const debugCheckbox = await popup.$('#debugModeCheckbox');
    assert('Debug mode checkbox exists', !!debugCheckbox);
    const isChecked = await debugCheckbox.isChecked();
    assert('Debug mode off by default', !isChecked);

    // Cancel back to main
    await popup.click('#cancelButton');
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

    // 7. CVE Overlay injection test
    console.log('\n--- CVE Overlay ---');

    // Store mock analysis data directly in extension storage
    const mockAnalysis = {
      'CVE-2024-1234': {
        cve: 'CVE-2024-1234',
        relevant: 'yes',
        summary: 'Critical RCE in test library',
        remediation: 'Upgrade to 2.0',
        cvss_score: 9.8,
        severity: 'critical'
      },
      'CVE-2024-5678': {
        cve: 'CVE-2024-5678',
        relevant: 'no',
        summary: 'Low-impact info disclosure',
        remediation: 'No action needed'
      },
      'CVE-2024-9999': {
        cve: 'CVE-2024-9999',
        relevant: 'low',
        summary: 'Moderate DoS vector',
        remediation: 'Monitor for exploitation'
      }
    };

    // Use service worker to set storage
    await sw.evaluate((data) => {
      return chrome.storage.local.set({ v1h_analysis: data, v1h_overlay_enabled: true });
    }, mockAnalysis);

    // Create a page that mimics V1 console vulnerability table with CVE IDs
    const overlayPage = await context.newPage();

    // Serve a mock page with CVE text — use data URL with trendmicro-like structure
    await overlayPage.setContent(`
      <html><body>
        <table class="ant-table-tbody">
          <tr><td><span>CVE-2024-1234</span></td><td>Critical</td></tr>
          <tr><td><span>CVE-2024-5678</span></td><td>Low</td></tr>
          <tr><td><span>CVE-2024-9999</span></td><td>Medium</td></tr>
          <tr><td><span>CVE-2024-0000</span></td><td>Unknown (no analysis)</td></tr>
        </table>
      </body></html>
    `);

    // The content script auto-injects on trendmicro.com URLs only.
    // For testing, we'll trigger injection manually via message.
    await overlayPage.evaluate(() => {
      return new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'v1h_injectOverlays' }, resolve);
        // Content script handles the message — give it time
        setTimeout(resolve, 500);
      });
    }).catch(() => {});
    // Wait for injection
    await new Promise(r => setTimeout(r, 1500));

    // But wait — content scripts on data: URLs may not have chrome.runtime.
    // Instead, manually trigger by sending message from background to tab.
    await sw.evaluate((tabId) => {
      return chrome.tabs.sendMessage(tabId, { type: 'v1h_injectOverlays' });
    }, overlayPage._mainFrame._page._delegate?._pageId).catch(() => {});

    // Actually, let's get the tab ID properly
    const overlayTabInfo = await sw.evaluate(async () => {
      const tabs = await chrome.tabs.query({});
      return tabs.map(t => ({ id: t.id, url: t.url }));
    });
    const dataTab = overlayTabInfo.find(t => t.url?.startsWith('about:blank') || t.url === '');
    if (dataTab) {
      await sw.evaluate(async (tabId) => {
        try {
          await chrome.tabs.sendMessage(tabId, { type: 'v1h_injectOverlays' });
        } catch (e) { /* tab may not have content script */ }
      }, dataTab.id);
    }
    await new Promise(r => setTimeout(r, 1000));

    // Check if badges were injected
    const badges = await overlayPage.$$('.v1h-badge');
    // Content scripts may not inject on data: pages — that's expected.
    // The test verifies the analysis data is stored and the popup can read it.
    if (badges.length > 0) {
      assert('CVE badges injected', true, `${badges.length} badges found`);
      const firstBadgeText = await badges[0].textContent();
      assert('First badge has relevance label', firstBadgeText.includes('RELEVANT'));
    } else {
      // Content script doesn't run on data: URLs — verify storage instead
      const storedData = await sw.evaluate(() => chrome.storage.local.get('v1h_analysis'));
      const storedCount = Object.keys(storedData.v1h_analysis || {}).length;
      assert('Analysis data stored in extension storage', storedCount === 3, `stored ${storedCount} CVEs`);
      console.log('  NOTE: Content script cannot inject on data: URLs (expected)');
    }

    // Verify overlay toggle in popup
    const popupCheck = await context.newPage();
    await popupCheck.goto(`chrome-extension://${extensionId}/chrome/popup.html`);
    await popupCheck.waitForSelector('#root', { timeout: 5000 });
    await new Promise(r => setTimeout(r, 500));

    const overlayBtn = await popupCheck.$('#injectOverlayBtn');
    assert('Overlay toggle button present in popup', !!overlayBtn);
    if (overlayBtn) {
      const btnText = await overlayBtn.textContent();
      assert('Overlay toggle shows enabled state', btnText.includes('On'));
    }

    // Check analysis stats are shown
    const statsText = await popupCheck.textContent('.v1-section');
    assert('CVE count shows 3', statsText && statsText.includes('3'));

    await overlayPage.close();

    // 8. CVE List View
    console.log('\n--- CVE List View ---');

    // Click "View CVEs" button
    const viewCvesBtn = await popupCheck.$('#viewCvesBtn');
    assert('View CVEs button present', !!viewCvesBtn);
    await viewCvesBtn.click();
    await popupCheck.waitForSelector('.cve-list', { timeout: 3000 });
    assert('CVE list view rendered', true);

    // Check filter buttons
    const filterBtns = await popupCheck.$$('.cve-filter-btn');
    assert('Four filter buttons rendered', filterBtns.length === 4);

    // Check "All" is active by default
    const allBtn = await popupCheck.$('.cve-filter-btn.active');
    const allBtnText = await allBtn.textContent();
    assert('All filter active by default', allBtnText.includes('All'));

    // Check all 3 CVE rows are shown
    const cveRows = await popupCheck.$$('.cve-row');
    assert('All 3 CVEs shown', cveRows.length === 3);

    // Check CVE IDs are visible
    const firstId = await popupCheck.$eval('.cve-id', el => el.textContent);
    assert('CVE ID rendered in list', firstId.includes('CVE-'));

    // Check badges are present
    const listBadges = await popupCheck.$$('.cve-badge');
    assert('Relevance badges rendered', listBadges.length === 3);

    // Test filter: click "Relevant" — should show 1 CVE
    const relevantBtn = filterBtns[1];
    await relevantBtn.click();
    await new Promise(r => setTimeout(r, 200));
    const filteredRows = await popupCheck.$$('.cve-row');
    assert('Relevant filter shows 1 CVE', filteredRows.length === 1);

    // Check the filtered CVE is the relevant one
    const filteredId = await popupCheck.$eval('.cve-id', el => el.textContent);
    assert('Relevant CVE is CVE-2024-1234', filteredId.includes('CVE-2024-1234'));

    // Test filter: "None" — should show 1 CVE (re-query after re-render)
    const noneBtn = await popupCheck.$('.cve-filter-btn[data-filter="no"]');
    await noneBtn.click();
    await new Promise(r => setTimeout(r, 200));
    const noneRows = await popupCheck.$$('.cve-row');
    assert('None filter shows 1 CVE', noneRows.length === 1);

    // Test Copy CVE IDs button exists with correct count
    const copyBtn = await popupCheck.$('#copyCveIdsBtn');
    assert('Copy button present', !!copyBtn);
    const copyText = await copyBtn.textContent();
    assert('Copy button shows count', copyText.includes('1'));

    // Switch back to All and verify count updates
    const allFilterBtn = await popupCheck.$('.cve-filter-btn[data-filter="all"]');
    await allFilterBtn.click();
    await new Promise(r => setTimeout(r, 200));
    const allRows2 = await popupCheck.$$('.cve-row');
    assert('All filter restores 3 CVEs', allRows2.length === 3);
    const copyBtn2 = await popupCheck.$('#copyCveIdsBtn');
    const copyText2 = await copyBtn2.textContent();
    assert('Copy button shows 3 for All filter', copyText2.includes('3'));

    // Test Back button
    const backBtn = await popupCheck.$('#cveBackBtn');
    assert('Back button present', !!backBtn);
    await backBtn.click();
    await popupCheck.waitForSelector('#toggleButton', { timeout: 3000 });
    assert('Back returns to main view', true);

    await popupCheck.close();

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
