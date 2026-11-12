/**
 * CJS wrapper for lemon-tls.
 *
 * Where require() of an ES module is built in (Node 20.19+, 22.12+),
 * require('lemon-tls') returns the module itself, synchronously.
 *
 *   const tls = require('lemon-tls');
 *
 * The fallback below — a Promise of the module — is for Node 18 and for a
 * runtime or bundler whose require() cannot load ES modules; there,
 * `await require('lemon-tls')`.
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
  // require() of ES modules not available: a promise of the module.
  // Users need: const tls = await require('lemon-tls');
  module.exports = load();
  module.exports.__esModule = true;
}
