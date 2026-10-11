/** Guard intended App Runner toolset expansion without Google credentials or API requests. */
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const env = {
  ...process.env,
  SEO_MCP_TOOLSETS: "gsc,ga4,web,geo,analysis",
  SEO_MCP_READ_ONLY: "1",
  WP_SITES: "",
  GITHUB_TOKEN: "",
  GMAIL_CREDENTIALS: "",
};
const client = new Client({ name: "readonly-expansion-smoke", version: "1" });
try {
  await client.connect(new StdioClientTransport({
    command: "node", args: ["dist/index.js"], env, stderr: "pipe",
  }));
  const { tools } = await client.listTools();
  const names = new Set(tools.map((t) => t.name));
  for (const expected of [
    "gsc_list_sites", "gsc_site_snapshot",
    "ga_list_properties", "ga_run_report", "ga_landing_page_seo",
    "page_audit", "pagespeed", "robots_check",
    "ai_crawler_access", "structured_data_audit", "geo_page_score",
    "seo_digest", "content_refresh_candidates", "crux_snapshot",
  ]) {
    assert(names.has(expected), `Expected tool absent: ${expected}`);
  }
  for (const item of tools) {
    assert.equal(item.annotations?.readOnlyHint, true, `Not read-only: ${item.name}`);
    assert(!/^(gsc_submit_|gsc_add_|gsc_delete_|ga_create_|indexnow_submit|github_commit_|wp_update_|wp_run|oauth_revoke_)/.test(item.name), `Write tool exposed: ${item.name}`);
    assert(!/^(wp_|github_|gmail_)/.test(item.name), `Unrequested toolset exposed: ${item.name}`);
  }
  console.log(`PASS: ${tools.length} tools exposed, five read-only toolsets, write and unrelated tools absent`);
} finally {
  await client.close();
}
