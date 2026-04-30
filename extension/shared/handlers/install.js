/**
 * Install handler for V1 Helper.
 * No welcome page — just logs install.
 */

export function setupInstallHandler(browserAPI) {
  browserAPI.runtime.onInstalled.addListener((details) => {
    if (details.reason === 'install') {
      console.log('[V1 Helper] Extension installed');
    } else if (details.reason === 'update') {
      console.log('[V1 Helper] Extension updated to', browserAPI.runtime.getManifest().version);
    }
  });
}
