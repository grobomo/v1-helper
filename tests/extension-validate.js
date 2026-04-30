#!/usr/bin/env node
/**
 * V1 Helper extension validation tests.
 * No Playwright dependency — validates structure, manifest, and JS syntax.
 *
 * Run: node tests/extension-validate.js
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const EXT_DIR = path.resolve(__dirname, '..', 'extension');
const results = { pass: 0, fail: 0, errors: [] };

function assert(name, condition, detail) {
  if (condition) {
    console.log(`  PASS: ${name}`);
    results.pass++;
  } else {
    console.log(`  FAIL: ${name}${detail ? ' -- ' + detail : ''}`);
    results.fail++;
    results.errors.push(name);
  }
}

// --- Manifest ---
console.log('\n--- Manifest ---');

const manifestPath = path.join(EXT_DIR, 'manifest.json');
assert('manifest.json exists', fs.existsSync(manifestPath));

let manifest;
try {
  manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  assert('manifest.json is valid JSON', true);
} catch (e) {
  assert('manifest.json is valid JSON', false, e.message);
  process.exit(1);
}

assert('manifest_version is 3', manifest.manifest_version === 3);
assert('name is set', !!manifest.name);
assert('version is semver', /^\d+\.\d+\.\d+$/.test(manifest.version));
assert('description exists', !!manifest.description);
assert('description does not mention MCP', !manifest.description.toLowerCase().includes('mcp'));

// Permissions
assert('permissions is array', Array.isArray(manifest.permissions));
assert('no debugger permission', !manifest.permissions.includes('debugger'));
assert('no webRequest permission', !manifest.permissions.includes('webRequest'));
assert('no offscreen permission', !manifest.permissions.includes('offscreen'));
assert('storage permission present', manifest.permissions.includes('storage'));
assert('tabs permission present', manifest.permissions.includes('tabs'));

// Host permissions
assert('host_permissions scoped to trendmicro.com',
  manifest.host_permissions?.every(p => p.includes('trendmicro.com')),
  `got: ${JSON.stringify(manifest.host_permissions)}`);

// --- Referenced Files ---
console.log('\n--- Referenced Files ---');

// Service worker
const swPath = path.join(EXT_DIR, manifest.background?.service_worker || '');
assert('service worker file exists', fs.existsSync(swPath), manifest.background?.service_worker);

// Popup
const popupPath = path.join(EXT_DIR, manifest.action?.default_popup || '');
assert('popup HTML exists', fs.existsSync(popupPath), manifest.action?.default_popup);

// Icons
for (const [size, iconPath] of Object.entries(manifest.icons || {})) {
  const fullPath = path.join(EXT_DIR, iconPath);
  assert(`icon-${size} exists`, fs.existsSync(fullPath), iconPath);
}

// Content scripts
for (const cs of manifest.content_scripts || []) {
  for (const jsFile of cs.js || []) {
    const fullPath = path.join(EXT_DIR, jsFile);
    assert(`content script exists: ${jsFile}`, fs.existsSync(fullPath));
  }
  assert('content script matches scoped to trendmicro.com',
    cs.matches?.every(m => m.includes('trendmicro.com')),
    `got: ${JSON.stringify(cs.matches)}`);
}

// --- JS Syntax ---
console.log('\n--- JS Syntax ---');

const jsFiles = [
  manifest.background?.service_worker,
  ...(manifest.content_scripts || []).flatMap(cs => cs.js || []),
];

// Find popup JS from popup HTML
if (fs.existsSync(popupPath)) {
  const popupHtml = fs.readFileSync(popupPath, 'utf8');
  const scriptMatches = popupHtml.match(/src="([^"]+\.js)"/g) || [];
  for (const match of scriptMatches) {
    const src = match.match(/src="([^"]+)"/)[1];
    const resolved = path.join(path.dirname(popupPath), src);
    jsFiles.push(path.relative(EXT_DIR, resolved));
  }
  const cssMatches = popupHtml.match(/href="([^"]+\.css)"/g) || [];
  for (const match of cssMatches) {
    const href = match.match(/href="([^"]+)"/)[1];
    const resolved = path.join(path.dirname(popupPath), href);
    assert(`CSS file exists: ${href}`, fs.existsSync(resolved));
  }
}

for (const jsFile of jsFiles) {
  if (!jsFile) continue;
  const fullPath = path.join(EXT_DIR, jsFile);
  if (!fs.existsSync(fullPath)) continue;

  try {
    const code = fs.readFileSync(fullPath, 'utf8');
    // Basic syntax check via Node
    new Function(code);
    assert(`${jsFile} has valid JS syntax`, true);
  } catch (e) {
    // Module syntax (import/export) will fail in Function() but is valid
    if (e instanceof SyntaxError && (e.message.includes('import') || e.message.includes('export'))) {
      assert(`${jsFile} has valid JS syntax (module)`, true);
    } else {
      assert(`${jsFile} has valid JS syntax`, false, e.message);
    }
  }
}

// --- Content Checks ---
console.log('\n--- Content Checks ---');

// Background script should NOT import from shared modules
const bgCode = fs.readFileSync(swPath, 'utf8');
assert('background has no ES6 imports', !bgCode.includes('import '));
assert('background has no WebSocket reference', !bgCode.includes('WebSocket'));
assert('background has no require()', !bgCode.includes('require('));
assert('background handles getConnectionStatus', bgCode.includes('getConnectionStatus'));
assert('background is under 200 lines', bgCode.split('\n').length < 200,
  `${bgCode.split('\n').length} lines`);

// Content script should have CVE overlay logic
const csPath = path.join(EXT_DIR, manifest.content_scripts[0].js[0]);
const csCode = fs.readFileSync(csPath, 'utf8');
assert('content script has CVE overlay injection', csCode.includes('injectOverlays'));
assert('content script has V1 URL detection', csCode.includes('trendmicro'));
assert('content script has relevance colors', csCode.includes('RELEVANT'));
assert('content script has SPA navigation watcher', csCode.includes('MutationObserver'));
assert('content script has detail panel', csCode.includes('showDetailPanel'));

// Popup should NOT reference MCP
const popupJsPath = path.join(EXT_DIR, 'shared', 'popup', 'popup.js');
if (fs.existsSync(popupJsPath)) {
  const popupCode = fs.readFileSync(popupJsPath, 'utf8');
  assert('popup has no MCP port reference', !popupCode.includes('mcpPort'));
  assert('popup has no stealth mode reference', !popupCode.includes('stealthMode'));
  assert('popup has CVE analysis import', popupCode.includes('importAnalysis'));
  assert('popup has V1 region selector', popupCode.includes('V1_REGIONS'));
  assert('popup has overlay toggle', popupCode.includes('overlayEnabled'));
}

// --- No Stale Dependencies ---
console.log('\n--- Dependencies ---');

// Check no shared modules remain (except popup)
const sharedDirs = ['adapters', 'connection', 'handlers', 'utils'];
for (const dir of sharedDirs) {
  const dirPath = path.join(EXT_DIR, 'shared', dir);
  assert(`shared/${dir}/ removed`, !fs.existsSync(dirPath));
}
assert('shared/popup/ exists', fs.existsSync(path.join(EXT_DIR, 'shared', 'popup')));

// Check no _locales remain
assert('_locales removed', !fs.existsSync(path.join(EXT_DIR, 'chrome', '_locales')));

// Check no public test pages remain
assert('chrome/public/ removed', !fs.existsSync(path.join(EXT_DIR, 'chrome', 'public')));

// --- Summary ---
console.log('\n========================================');
console.log(`Results: ${results.pass} passed, ${results.fail} failed`);
if (results.errors.length > 0) {
  console.log('Failed:', results.errors.join(', '));
}
console.log('========================================\n');

process.exit(results.fail > 0 ? 1 : 0);
