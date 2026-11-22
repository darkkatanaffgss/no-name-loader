/**
 * no name Open-Source Loader SDK
 * -----------------------------------------------------------
 * Central configuration for software entries, API endpoint,
 * and extensible launch adapters for developers building on top
 * of this loader UI + licensing template.
 */

const SDK_CONFIG = {
  brandName: 'no name',
  apiBaseUrl: process.env.NONAME_API_URL || 'http://127.0.0.1:3840',
  // Shared HMAC secret matching api-server/server.js (override via env in production)
  hmacSecret: process.env.API_SECRET || 'noname-opensource-hmac-secret-change-me',
  softwareCatalog: {
    cs2: {
      id: 'cs2',
      title: 'Counter-Strike 2',
      updated: 'Nov 13 2026 (16:15 PM)',
      lastLaunch: 'Last Month',
      defaultBranch: 'Nightly',
      changelog: [
        'UI layout synchronized with v2.1 acrylic engine',
        'Integrated HMAC-signed subscription verification',
        'Improved branch switcher and session status'
      ]
    },
    csgo: {
      id: 'csgo',
      title: 'Counter-Strike: Global Offensive',
      updated: 'Nov 10 2026 (12:40 PM)',
      lastLaunch: '2 Weeks Ago',
      defaultBranch: 'Stable',
      changelog: [
        'Legacy profile configuration verified',
        'Added HWID-locked session validation',
        'Updated branch selector controls'
      ]
    },
    minecraft: {
      id: 'minecraft',
      title: 'Minecraft',
      updated: 'Nov 18 2026 (19:05 PM)',
      lastLaunch: 'Yesterday',
      defaultBranch: 'Beta',
      changelog: [
        'Added official Minecraft grass block asset',
        'Added release channel switcher (Nightly / Beta / Stable)',
        'Connected license entitlement checks'
      ]
    }
  }
};

/**
 * Developer Launch Hook
 * Replace or extend this adapter with your own legitimate application
 * startup pipeline (e.g., spawning an authorized desktop module or modpack).
 */
async function executeLaunchHook({ productId, branch, session }) {
  if (!session || !session.valid) {
    throw new Error('Active verified license required');
  }
  if (!session.products.includes(productId)) {
    throw new Error(`Your license tier (${session.tier}) does not include ${productId}`);
  }
  if (!session.branches.includes(branch)) {
    throw new Error(`Branch "${branch}" requires a higher subscription tier`);
  }

  return {
    ok: true,
    productId,
    branch,
    sessionToken: session.nonce,
    message: `${SDK_CONFIG.softwareCatalog[productId].title} (${branch}) session verified`
  };
}

module.exports = {
  SDK_CONFIG,
  executeLaunchHook
};
