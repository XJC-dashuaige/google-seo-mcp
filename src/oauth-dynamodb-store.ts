/**
 * Durable OAuth state in a single DynamoDB table (pk string, TTL attr 'ttl').
 * No raw bearer/refresh/code tokens are persisted: only SHA-256 hashes.
 * One table supports client registration, access/refresh indexes and one-time
 * authorization codes. Refresh rotation is a conditional atomic transaction.
 */
import { randomBytes } from "node:crypto";
import { DynamoApi, dynamoString, dynamoNumber } from "./oauth-dynamodb-api.js";
import { hashToken } from "./hosted/store.js";

const ACCESS_TTL = 86_400;
const REFRESH_TTL = 90 * 86_400;
const epoch = () => Math.floor(Date.now() / 1000);
const stamp = () => new Date().toISOString();
const newToken = (p: string) => p + randomBytes(32).toString("base64url");
type Client = { clientId: string; name: string | null; redirectUris: string[]; createdAt: string; lastUsedAt: string | null };
type Grant = { id: string; clientId: string; scope: string; accessHash: string; accessExp: number; refreshHash: string; refreshExp: number; prevRefreshHash: string | null; createdAt: string; lastUsedAt: string | null; calls: number; revokedAt: string | null };
type Pending = { clientId: string; redirectUri: string; challenge: string; scope: string; exp: number };
const body = (obj: unknown) => dynamoString(JSON.stringify(obj));
const decode = <T>(item: Record<string, any> | null): T | null => {
  if (!item || typeof item.body?.S !== "string") return null;
  return JSON.parse(item.body.S) as T;
};
const put = (table: string, pk: string, obj: unknown, ttl: number, condition = "attribute_not_exists(pk)") => ({
  Put: {
    TableName: table, Item: { pk: dynamoString(pk), body: body(obj), ttl: dynamoNumber(ttl) },
    ConditionExpression: condition,
  },
});
const remove = (table: string, pk: string) => ({ Delete: { TableName: table, Key: { pk: dynamoString(pk) } } });

export class DynamoOAuthStore {
  private api: DynamoApi;
  constructor(table: string, region: string) { this.api = new DynamoApi(table, region); }
  private get table() { return this.api.table; }
  close() {}
  async registerClient(name: string | null, redirectUris: string[]): Promise<Client> {
    const client: Client = { clientId: randomBytes(16).toString("hex"), name, redirectUris, createdAt: stamp(), lastUsedAt: null };
    // Clients must not expire while a refresh grant is active; clean stale
    // registrations explicitly instead of using a TTL on approved clients.
    await this.api.put("client#" + client.clientId, { body: body(client) }, "attribute_not_exists(pk)");
    return client;
  }
  async getClient(clientId: string): Promise<Client | null> {
    return decode<Client>(await this.api.get("client#" + clientId));
  }
  async countClients(): Promise<number> { return (await this.api.scan("client#")).length; }
  async countGrants(): Promise<number> {
    return (await this.api.scan("grant#")).filter(x => { const g = decode<Grant>(x); return g && !x.revokedAt && g.refreshExp > epoch(); }).length;
  }
  async pruneClients(): Promise<number> {
    const clients = await this.api.scan("client#");
    const grants = (await this.api.scan("grant#")).map(x => decode<Grant>(x)).filter((x): x is Grant => !!x);
    const active = new Set(grants.map(x => x.clientId));
    const cutoff = Date.now() - 86_400_000;
    let n = 0;
    for (const item of clients) {
      const client = decode<Client>(item);
      if (client && !active.has(client.clientId) && Date.parse(client.createdAt) < cutoff) {
        await this.api.delete("client#" + client.clientId); n++;
      }
    }
    return n;
  }
  async saveCode(codeHash: string, pending: Pending): Promise<void> {
    await this.api.put("code#" + codeHash, { body: body(pending), ttl: dynamoNumber(Math.ceil(pending.exp / 1000)) }, "attribute_not_exists(pk)");
  }
  async consumeCode(codeHash: string): Promise<Pending | null> {
    const result = decode<Pending>(await this.api.delete("code#" + codeHash, true));
    return result && result.exp >= Date.now() ? result : null;
  }
  async issue(clientId: string, scope: string) {
    const access = newToken("mcpa_"), refresh = newToken("mcpr_");
    const grant: Grant = {
      id: randomBytes(8).toString("hex"), clientId, scope,
      accessHash: hashToken(access), refreshHash: hashToken(refresh),
      accessExp: epoch() + ACCESS_TTL, refreshExp: epoch() + REFRESH_TTL,
      prevRefreshHash: null, createdAt: stamp(), lastUsedAt: null, calls: 0, revokedAt: null,
    };
    await this.api.transaction([
      { Put: { TableName: this.table, Item: { pk: dynamoString("grant#" + grant.id), body: body(grant), ttl: dynamoNumber(grant.refreshExp), refreshHash: dynamoString(grant.refreshHash) }, ConditionExpression: "attribute_not_exists(pk)" } },
      put(this.table, "access#" + grant.accessHash, { grantId: grant.id }, grant.accessExp),
      put(this.table, "refresh#" + grant.refreshHash, { grantId: grant.id }, grant.refreshExp),
    ]);
    return { access, refresh, expiresIn: ACCESS_TTL, scope, grantId: grant.id };
  }
  private async lookup(pk: string): Promise<Grant | null> {
    const link = decode<{ grantId: string }>(await this.api.get(pk));
    if (!link) return null;
    const item = await this.api.get("grant#" + link.grantId);
    const grant = decode<Grant>(item);
    if (grant && item?.revokedAt) grant.revokedAt = String((item.revokedAt as { S: string }).S);
    return grant;
  }
  async resolveAccess(token: string) {
    if (!token.startsWith("mcpa_")) return null;
    const hash = hashToken(token);
    const grant = await this.lookup("access#" + hash);
    if (!grant || grant.revokedAt || grant.accessExp < epoch() || grant.accessHash !== hash) return null;
    return {
      id: grant.id, clientId: grant.clientId, scope: grant.scope, accessExp: grant.accessExp,
      refreshExp: grant.refreshExp, createdAt: grant.createdAt, calls: grant.calls,
    };
  }
  async rotate(refresh: string, clientId: string | null) {
    if (!refresh.startsWith("mcpr_")) return null;
    const hash = hashToken(refresh);
    const grant = await this.lookup("refresh#" + hash);
    if (!grant) {
      const spent = decode<{ grantId: string }>(await this.api.get("spent#" + hash));
      if (spent) await this.revokeGrant(spent.grantId);
      return null;
    }
    if (grant.revokedAt || grant.refreshExp < epoch() || grant.refreshHash !== hash ||
        (clientId && clientId !== grant.clientId)) return null;
    const access = newToken("mcpa_"), next = newToken("mcpr_");
    const updated: Grant = {
      ...grant, accessHash: hashToken(access), accessExp: epoch() + ACCESS_TTL,
      prevRefreshHash: hash, refreshHash: hashToken(next), refreshExp: epoch() + REFRESH_TTL,
      lastUsedAt: stamp(),
    };
    // Conditional overwrite of the grant is the serialization point:
    // two concurrent refresh requests can never both rotate the same token.
    try {
      await this.api.transaction([
        { Update: {
          TableName: this.table, Key: this.api.key("grant#" + grant.id),
          UpdateExpression: "SET #body = :body, #ttl = :ttl, #refreshHash = :new",
          ExpressionAttributeNames: { "#body": "body", "#ttl": "ttl", "#refreshHash": "refreshHash" },
          ConditionExpression: "(attribute_not_exists(refreshHash) OR refreshHash = :old) AND attribute_not_exists(revokedAt)",
          ExpressionAttributeValues: {
            ":body": body(updated), ":ttl": dynamoNumber(updated.refreshExp),
            ":new": dynamoString(updated.refreshHash), ":old": dynamoString(hash),
          },
        } },
        remove(this.table, "access#" + grant.accessHash),
        remove(this.table, "refresh#" + hash),
        put(this.table, "access#" + updated.accessHash, { grantId: grant.id }, updated.accessExp),
        put(this.table, "refresh#" + updated.refreshHash, { grantId: grant.id }, updated.refreshExp),
        put(this.table, "spent#" + hash, { grantId: grant.id }, updated.refreshExp),
      ]);
    } catch (error) {
      // If another instance has already rotated, treat this as a replay.
      if ((error as Error).name === "TransactionCanceledException") {
        const spent = await this.api.get("spent#" + hash);
        if (spent) await this.revokeGrant(grant.id);
        return null;
      }
      throw error;
    }
    return { access, refresh: next, expiresIn: ACCESS_TTL, scope: grant.scope, grantId: grant.id };
  }
  async listGrants(includeRevoked = false) {
    const grants = (await this.api.scan("grant#"))
      .map(x => { const g = decode<Grant>(x); if (g && x.revokedAt) g.revokedAt = String((x.revokedAt as { S: string }).S); return g; }).filter((x): x is Grant => !!x && (includeRevoked || !x.revokedAt));
    const list = await Promise.all(grants.map(async g => {
      const client = await this.getClient(g.clientId);
      return {
        id: g.id, client: client?.name ?? null, clientId: g.clientId,
        scope: g.scope, createdAt: g.createdAt, lastUsedAt: g.lastUsedAt,
        calls: g.calls, revokedAt: g.revokedAt,
        accessExpired: g.accessExp < epoch(), refreshExpired: g.refreshExp < epoch(),
      };
    }));
    return list.sort((a,b) => b.createdAt.localeCompare(a.createdAt));
  }
  async revokeGrant(id: string): Promise<boolean> {
    const item = await this.api.get("grant#" + id);
    const grant = decode<Grant>(item);
    if (grant && item?.revokedAt) grant.revokedAt = String((item.revokedAt as { S: string }).S);
    if (!grant || grant.revokedAt) return false;
    // Atomically set a revocation attribute; access lookups check it.
    // The old body remains only to preserve audit/debug metadata.
    try {
      await this.api.call("UpdateItem", {
        TableName: this.table, Key: this.api.key("grant#" + id),
        UpdateExpression: "SET revokedAt = :at",
        ConditionExpression: "attribute_exists(pk) AND attribute_not_exists(revokedAt)",
        ExpressionAttributeValues: { ":at": dynamoString(stamp()) },
      });
      return true;
    } catch (error) {
      if ((error as Error).name === "ConditionalCheckFailedException") return false;
      throw error;
    }
  }
  async revoke(token: string): Promise<boolean> {
    const hash = hashToken(token);
    const g = await this.lookup("access#" + hash) ??
      await this.lookup("refresh#" + hash) ??
      await this.lookup("spent#" + hash);
    return g ? this.revokeGrant(g.id) : false;
  }
}
