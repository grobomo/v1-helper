/**
 * V1 Helper content script
 * - Detects tech stack (frameworks, libraries, CSS frameworks)
 * - Sends tech stack info to background script
 * - Forwards console messages from injected script to background
 * - Watches for focus requests from MCP server
 */

// Listen for console messages from injected script
window.addEventListener('message', (event) => {
  if (event.source !== window) return;

  if (event.data && event.data.__blueprintConsole) {
    const message = event.data.__blueprintConsole;
    chrome.runtime.sendMessage({
      type: 'console',
      level: message.level,
      text: message.text,
      timestamp: message.timestamp
    });
  }
});

// Watch for focus requests from MCP server
const observer = new MutationObserver(() => {
  const focusElement = document.querySelector('.mcp-extension-focus-tab');
  if (focusElement) {
    chrome.runtime.sendMessage({ type: 'focusTab' });
  }
});

observer.observe(document.documentElement, {
  childList: true,
  subtree: true
});

/**
 * Tech stack detection
 * Detects frameworks, libraries, CSS frameworks, and dev tools
 */
function detectTechStack() {
  const stack = {
    frameworks: [],
    libraries: [],
    css: [],
    devTools: [],
    spa: false,
    autoReload: false,
    obfuscatedCSS: false
  };

  try {
    // JS Frameworks
    if (window.React || window.__REACT_DEVTOOLS_GLOBAL_HOOK__ ||
        document.getElementById('root') || document.getElementById('react-root')) {
      stack.frameworks.push('React');
      stack.spa = true;
    }
    if (window.Vue || window.__VUE__ || window.__VUE_DEVTOOLS_GLOBAL_HOOK__) {
      stack.frameworks.push('Vue');
      stack.spa = true;
    }
    if (window.ng || typeof window.getAllAngularRootElements === 'function') {
      stack.frameworks.push('Angular');
      stack.spa = true;
    }
    if (window.Turbo || document.querySelector('turbo-frame')) {
      stack.frameworks.push('Turbo');
      stack.spa = true;
    }
    if (window.__NEXT_DATA__) {
      stack.frameworks.push('Next.js');
      stack.spa = true;
    }
    if (document.querySelector('[data-svelte]') || window.__SVELTE__) {
      stack.frameworks.push('Svelte');
      stack.spa = true;
    }
    // Ant Design (V1 console uses this)
    if (document.querySelector('[class^="ant-"], [class*=" ant-"]')) {
      stack.css.push('Ant Design');
    }

    // JS Libraries
    if (window.jQuery || window.$) stack.libraries.push('jQuery');
    if (window.htmx) stack.libraries.push('htmx');
    if (window.Alpine || document.querySelector('[x-data]')) stack.libraries.push('Alpine.js');

    // CSS Frameworks
    if (document.querySelector('.container') && document.querySelector('[class*="col-"]')) {
      stack.css.push('Bootstrap');
    }
    const hasTailwind = document.querySelector('[class*="text-"][class*="-500"], [class*="bg-"][class*="-600"]');
    if (hasTailwind) stack.css.push('Tailwind');
    if (document.querySelector('[class*="Mui"]')) stack.css.push('Material-UI');

    // Check for obfuscated CSS
    const bodyClasses = document.body?.className || '';
    if (bodyClasses.match(/\b_[a-z0-9]{4,}\b/)) {
      stack.obfuscatedCSS = true;
    }
  } catch (error) {
    console.error('[V1 Helper] Error detecting tech stack:', error);
  }

  return stack;
}

// Run detection on load (skip if stealth mode enabled)
async function sendTechStackDetection() {
  try {
    const response = await chrome.runtime.sendMessage({ type: 'isStealthMode' });
    if (response?.isStealthMode) return;
  } catch {
    // If we can't check stealth mode, proceed
  }

  const stack = detectTechStack();
  chrome.runtime.sendMessage({
    type: 'techStackDetected',
    stack: stack,
    url: window.location.href
  }).catch(() => {});
}

// Initial detection after page loads
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => setTimeout(sendTechStackDetection, 100));
} else {
  setTimeout(sendTechStackDetection, 100);
}

// Watch for URL changes (SPA navigation)
let lastUrl = window.location.href;
new MutationObserver(() => {
  const currentUrl = window.location.href;
  if (currentUrl !== lastUrl) {
    lastUrl = currentUrl;
    setTimeout(sendTechStackDetection, 200);
  }
}).observe(document, { subtree: true, childList: true });

window.addEventListener('popstate', () => setTimeout(sendTechStackDetection, 200));

// Guard against multiple content script executions
if (!window.__v1HelperContentScriptLoaded) {
  window.__v1HelperContentScriptLoaded = true;

  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    if (event.data && event.data.__blueprintConsole) {
      const message = event.data.__blueprintConsole;
      chrome.runtime.sendMessage({
        type: 'console',
        level: message.level,
        text: message.text,
        timestamp: message.timestamp
      }).catch(() => {});
    }
  });
}
