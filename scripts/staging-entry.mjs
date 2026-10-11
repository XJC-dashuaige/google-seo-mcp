/**
 * Staging only. Run GA4/GSC diagnostics, then start the ordinary HTTP server.
 * This avoids App Runner's shell quoting differences in StartCommand.
 * Production continues to use "node dist/index.js --http".
 */
try {
  await import("./verify-staging-google-access.mjs");
} catch (err) {
  console.error(JSON.stringify({ check: "STAGING_DIAGNOSTIC", ok: false, error: err?.message?.slice(0,100) }));
}
process.exitCode = 0; // a missing GA4 permission must not make health check unavailable
if (!process.argv.includes("--http")) process.argv.push("--http");
await import("../dist/index.js");
