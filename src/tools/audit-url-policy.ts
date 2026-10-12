/**
 * Reject private/internal targets before page auditing. This is a hostname
 * policy, not DNS pinning; deploy behind egress controls for full SSRF defence.
 * SEO_MCP_AUDIT_ALLOWED_HOSTS narrows user supplied site fetches in staging.
 */
import { isIP } from "node:net";
import { envValue } from "../env.js";

export function assertSafeAuditUrl(input: string): void {
  const url = new URL(input);
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error("Only HTTP(S) URLs may be audited");
  if (url.username || url.password) throw new Error("URLs with credentials cannot be audited");
  const host = url.hostname.replace(/\.$/, "").toLowerCase();
  if (!host || host === "localhost" || host.endsWith(".localhost") ||
      host.endsWith(".local") || host.endsWith(".internal") ||
      host.endsWith(".test") || host.endsWith(".invalid") ||
      host.endsWith(".onion") || host.includes(":") || isIP(host)) throw new Error("Internal or numeric IP audit targets are not allowed");
  if (url.port && !["80","443"].includes(url.port)) throw new Error("Nonstandard URL port is not allowed");
  const configured = envValue("SEO_MCP_AUDIT_ALLOWED_HOSTS");
  if (configured) {
    const hosts = configured.split(",").map(x => x.trim().toLowerCase()).filter(Boolean);
    // First-party sites and vetted external API endpoints used by enabled tools.
    const systemApis = new Set([
      "www.googleapis.com", "pagespeedonline.googleapis.com",
      "chromeuxreport.googleapis.com", "kgsearch.googleapis.com",
      "www.wikidata.org", "query.wikidata.org", "web.archive.org",
      "api.search.brave.com", "api.perplexity.ai", "api.indexnow.org",
      "places.googleapis.com",
    ]);
    if (!hosts.some(h => host === h || host.endsWith("." + h)) && !systemApis.has(host)) {
      throw new Error("Audit target is outside the configured allowed hosts");
    }
  }
}
