import assert from "node:assert/strict";
import { assertSafeAuditUrl } from "../dist/tools/audit-url-policy.js";
import { fetchWithTimeout } from "../dist/tools/web.js";
// The existing App Runner CI invokes this file on Node 22.
import "./unit/audit-dns.test.mjs";

for (const safe of [
  "https://cjrb.net/products/test",
  "https://www.cjrb.net/robots.txt",
  "https://artisancutlery.net/",
  "https://pagespeedonline.googleapis.com/pagespeedonline/v5/runPagespeed",
]) assert.doesNotThrow(() => assertSafeAuditUrl(safe), safe);

for (const unsafe of [
  "file:///etc/passwd", "http://localhost:8080/", "http://127.0.0.1/",
  "http://[::1]/", "http://169.254.169.254/latest/meta-data/",
  "http://10.0.0.5/", "https://example.local/secret",
  "http://admin:password@cjrb.net/", "https://cjrb.net:8443/",
]) assert.throws(() => assertSafeAuditUrl(unsafe), undefined, unsafe);

process.env.SEO_MCP_AUDIT_ALLOWED_HOSTS = "cjrb.net,artisancutlery.net";
assert.doesNotThrow(() => assertSafeAuditUrl("https://www.cjrb.net/"));
assert.throws(() => assertSafeAuditUrl("https://attacker.example.org/"));
const oldFetch = globalThis.fetch;
let calls = 0;
globalThis.fetch = async (url) => {
  calls++;
  if (url === "https://cjrb.net/") return new Response("", { status: 302, headers: { location: "http://169.254.169.254/latest/meta-data/" } });
  return new Response("unexpected");
};
try {
  await assert.rejects(fetchWithTimeout("https://cjrb.net/"), /Internal or numeric IP/);
  assert.equal(calls, 1, "redirect target rejected without an outbound fetch");
  await assert.rejects(fetchWithTimeout("http://127.0.0.1/"), /Internal or numeric IP/);
  assert.equal(calls, 1, "initial private target rejected without an outbound fetch");
} finally {
  globalThis.fetch = oldFetch;
  delete process.env.SEO_MCP_AUDIT_ALLOWED_HOSTS;
}
console.log("audit URL policy and redirect tests passed");
