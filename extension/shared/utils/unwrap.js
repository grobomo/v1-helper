/**
 * Method unwrapping utility for bot detection bypass
 *
 * This module provides code to temporarily restore native DOM methods
 * that might be wrapped by bot detection scripts. The unwrapping is done
 * only during model code execution and methods are restored afterwards.
 */

/**
 * List of DOM methods that might be wrapped by bot detectors
 * These will be temporarily restored to their native implementations
 */
const WRAPPED_METHODS = [
  // Document methods - these are the most commonly wrapped
  'getElementById',
  'getElementsByClassName',
  'getElementsByTagName',
  'getElementsByName',
  'querySelector',
  'querySelectorAll',
  'evaluate' // XPath
];

/**
 * Generate code that wraps user code with method unwrapping
 * @param {string} userCode - The user's code to execute
 * @returns {string} Wrapped code with unwrap/restore logic
 */
export function wrapWithUnwrap(userCode) {
  return `
(() => {
  // Save wrapped methods
  const _wrapped = {};
  ${WRAPPED_METHODS.map(method => `
  try {
    _wrapped['${method}'] = document.${method};
  } catch (e) {
    // Method might not exist or be accessible
  }`).join('')}

  // Get native methods from iframe
  const _iframe = document.createElement('iframe');
  _iframe.style.display = 'none';
  document.body.appendChild(_iframe);

  ${WRAPPED_METHODS.map(method => `
  try {
    if (_iframe.contentWindow.document.${method}) {
      document.${method} = _iframe.contentWindow.document.${method};
    }
  } catch (e) {
    // Method might not exist or be accessible
  }`).join('')}

  document.body.removeChild(_iframe);

  try {
    // Execute user code (already wrapped as IIFE by server)
    // Server sends: (function)() so we just need to eval it, not call it again
    return ${userCode};
  } finally {
    // Restore wrapped methods
    ${WRAPPED_METHODS.map(method => `
    try {
      if (_wrapped['${method}'] !== undefined) {
        document.${method} = _wrapped['${method}'];
      }
    } catch (e) {
      // Ignore restore errors
    }`).join('')}
  }
})()
`.trim();
}

/**
 * Check if code should be wrapped with unwrap logic
 * @param {string} code - The code to check
 * @returns {boolean} True if code should be wrapped
 */
export function shouldUnwrap(code) {
  // Don't wrap if code is already wrapped
  if (code.includes('_wrapped') || code.includes('_iframe')) {
    return false;
  }

  // Only wrap if code might use DOM methods
  const domMethods = [
    'getElementById',
    'getElementsByClassName',
    'getElementsByTagName',
    'querySelector',
    'document.',
    'element.'
  ];

  return domMethods.some(method => code.toLowerCase().includes(method.toLowerCase()));
}
