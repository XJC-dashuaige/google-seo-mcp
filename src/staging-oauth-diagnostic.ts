/**
 * Staging-only diagnostic using REAL DynamoDB requests and synthetic random grants.
 * No operator credentials or real ChatGPT OAuth grants are read or changed.
 * NOTE: Small synthetic grant records will expire automatically via DynamoDB TTL.
 */
import { createHash, randomBytes } from "node:crypto";
import { DynamoOAuthStore } from "./oauth-dynamodb-store.js";

function fail(check: string, error: unknown) {
  console.error(JSON.stringify({ check, ok: false, errorType: (error as Error)?.name ?? "Error" }));
}
export async function verifyStagingOAuth(): Promise<void> {
  const table = process.env.SEO_MCP_DYNAMODB_TABLE;
  if (!table || process.env.SEO_MCP_STAGING_DIAGNOSTIC !== "1") return;
  const a = new DynamoOAuthStore(table, process.env.AWS_REGION ?? "us-east-1");
  const b = new DynamoOAuthStore(table, process.env.AWS_REGION ?? "us-east-1");
  const tag = randomBytes(12).toString("hex");
  let grantId: string | undefined;
  let concurrentGrantId: string | undefined;
  let phase = "init";
  try {
    phase = "CLIENT_REGISTER";
    const client = await a.registerClient("staging-diagnostic-" + tag, ["https://example.org/oauth-callback"]);
    const loaded = await b.getClient(client.clientId);
    if (!loaded || loaded.clientId !== client.clientId) throw new Error("ClientReadBackFailed");
    console.error(JSON.stringify({ check: "OAUTH_DYNAMO_CLIENT_READ", ok: true }));

    const code = createHash("sha256").update("diagnostic-" + tag).digest("hex");
    const pending = { clientId: client.clientId, redirectUri: client.redirectUris[0], challenge: tag, scope: "mcp:read", exp: Date.now() + 120000 };
    phase = "SAVE_CODE";
    await a.saveCode(code, pending);
    const consumed = await b.consumeCode(code);
    if (consumed?.clientId !== client.clientId || await a.consumeCode(code) !== null) {
      throw new Error("CodeNotSingleUse");
    }
    console.error(JSON.stringify({ check: "OAUTH_DYNAMO_ONE_TIME_CODE", ok: true }));

    phase = "GRANT_ISSUE";
    const grant = await a.issue(client.clientId, "mcp:read");
    grantId = grant.grantId;
    phase = "ACCESS_RESOLVE";
    if ((await b.resolveAccess(grant.access))?.scope !== "mcp:read") throw new Error("AccessReadFailed");
    phase = "ROTATE";
    const rotated = await b.rotate(grant.refresh, client.clientId);
    if (!rotated || await a.resolveAccess(grant.access) !== null || !await a.resolveAccess(rotated.access)) {
      throw new Error("RotationFailed");
    }
    console.error(JSON.stringify({ check: "OAUTH_DYNAMO_ROTATION", ok: true }));
    phase = "REPLAY";
    if (await a.rotate(grant.refresh, client.clientId) !== null || await b.resolveAccess(rotated.access) !== null) {
      throw new Error("ReplayNotRevoked");
    }
    console.error(JSON.stringify({ check: "OAUTH_DYNAMO_REPLAY_REVOCATION", ok: true }));

    phase = "CONCURRENT_ISSUE";
    const concurrent = await a.issue(client.clientId, "mcp:read");
    concurrentGrantId = concurrent.grantId;
    phase = "CONCURRENT_ROTATE";
    const attempts = await Promise.all([
      a.rotate(concurrent.refresh, client.clientId),
      b.rotate(concurrent.refresh, client.clientId),
    ]);
    if (attempts.filter(Boolean).length !== 1) throw new Error("ConcurrentRotationNotExclusive");
    const winner = attempts.find(Boolean)!;
    if (await a.resolveAccess(winner.access) !== null) throw new Error("ReplayNotRevokedAfterRace");
    console.error(JSON.stringify({ check: "OAUTH_DYNAMO_CONCURRENT_REFRESH", ok: true }));
  } catch (error) {
    fail("OAUTH_DYNAMO_STAGING_" + phase, error);
  } finally {
    // Prevent these test grants from remaining usable; client metadata expires
    // through the existing orphan-registration pruning mechanism.
    for (const id of [grantId, concurrentGrantId]) {
      if (id) await a.revokeGrant(id).catch(() => {});
    }
  }
}
