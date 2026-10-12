/**
 * Staging-only bounded smoke test for enabled, read-only SEO tools.
 * Makes one real PageSpeed request and two public page audit requests.
 * Avoids leaking credentials or full website HTML into logs.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createServer } from "./server.js";

type ToolResult = { isError?: boolean; content?: Array<{ type: string; text?: string }> };
function summary(result: ToolResult, tool: string) {
  if (result.isError) return { check: tool, ok: false, type: "tool_error" };
  const raw = result.content?.find(c => c.type === "text")?.text ?? "";
  try {
    const value = JSON.parse(raw) as Record<string, unknown>;
    const object = value.result && typeof value.result === "object" ? value.result as Record<string, unknown> : value;
    return {
      check: tool, ok: true,
      ...(typeof object.score === "number" ? { score: object.score } : {}),
      ...(typeof object.status === "number" ? { status: object.status } : {}),
      ...(object.strategy ? { strategy: object.strategy } : {}),
    };
  } catch {
    return { check: tool, ok: !!raw, format: "text" };
  }
}
export async function verifyStagingWeb(): Promise<void> {
  if (process.env.SEO_MCP_STAGING_WEB_DIAGNOSTIC !== "1") return;
  const server = createServer({ toolsets: ["web", "geo"], readOnly: true });
  const client = new Client({ name: "staging-web-diagnostic", version: "1" });
  const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
  try {
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    const cases = [
      { name: "page_audit", arguments: { url: "https://cjrb.net/", checkFavicon: false } },
      { name: "geo_page_score", arguments: { url: "https://cjrb.net/" } },
      { name: "pagespeed", arguments: { url: "https://cjrb.net/", strategy: "mobile", categories: ["performance", "seo"], topOpportunities: 1, maxFailedAudits: 0 } },
    ];
    for (const test of cases) {
      try {
        const result = await client.callTool({ name: test.name, arguments: test.arguments }, undefined, { timeout: 190000 }) as ToolResult;
        console.error(JSON.stringify(summary(result, test.name)));
      } catch (err) {
        console.error(JSON.stringify({ check: test.name, ok: false, errorType: (err as Error).name, detail: String((err as Error).message).slice(0, 150) }));
      }
    }
  } finally {
    await client.close().catch(() => {});
    await server.close().catch(() => {});
  }
}
