/**
 * CJS wrapper for lemon-tls.
 * 
 * On Node 22+, require('lemon-tls') works natively with the ESM module.
 * On Node 16-21, this wrapper provides require() support via dynamic import.
 *
 * Usage:
 *   const tls = require('lemon-tls');           // sync on Node 22+
 *   const tls = await require('lemon-tls');     // async on Node 16-21
 */

let cached = null;

async function load() {
  if (!cached) cached = await import('./index.js');
  return cached.default || cached;
}

// Try sync require first (Node 22+)
try {
  const m = require('./index.js');
  module.exports = m.default || m;
} catch (e) {
  // Node 16-21: return a promise that resolves to the module
  // Users need: const tls = await require('lemon-tls');
  module.exports = load();
  module.exports.__esModule = true;
}
