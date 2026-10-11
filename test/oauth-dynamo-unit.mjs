/**
 * Offline DynamoDB OAuth store transaction tests. No AWS account or secrets.
 * Mock the DynamoDB wire API to exercise sign, grant persistence, rotation,
 * replay revocation, and one-time authorization-code consumption.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { DynamoOAuthStore } from "../dist/oauth-dynamodb-store.js";
process.env.AWS_ACCESS_KEY_ID = "test-access";
process.env.AWS_SECRET_ACCESS_KEY = "test-secret";
process.env.AWS_REGION = "us-east-1";
const items = new Map();
const copy = (x) => structuredClone(x);
const error = (name) => Object.assign(new Error(name), { name });
const key = (obj) => obj.pk.S;
const check = (statement, old, values) => {
  if (!statement) return true;
  if (statement === "attribute_not_exists(pk)") return !old;
  if (statement === "attribute_exists(pk) AND attribute_not_exists(revokedAt)") return !!old && !old.revokedAt;
  if (statement.includes("refreshHash")) {
    return !old?.revokedAt && (!old.refreshHash || old.refreshHash.S === values[":old"].S);
  }
  throw new Error("Unknown test condition: " + statement);
};
function exec(op, args, state) {
  if (op === "GetItem") return { Item: state.get(key(args.Key)) };
  if (op === "PutItem") {
    const pk = key(args.Item);
    if (!check(args.ConditionExpression, state.get(pk), args.ExpressionAttributeValues ?? {})) throw error("ConditionalCheckFailedException");
    state.set(pk, copy(args.Item)); return {};
  }
  if (op === "DeleteItem") {
    const pk = key(args.Key), old = state.get(pk);
    state.delete(pk);
    return { ...(args.ReturnValues === "ALL_OLD" && old ? { Attributes: old } : {}) };
  }
  if (op === "Scan") {
    const prefix = args.ExpressionAttributeValues[":prefix"].S;
    return { Items: [...state.entries()].filter(([k]) => k.startsWith(prefix)).map(([,v]) => v) };
  }
  if (op === "UpdateItem") {
    const pk = key(args.Key), old = state.get(pk);
    if (!check(args.ConditionExpression, old, args.ExpressionAttributeValues ?? {})) throw error("ConditionalCheckFailedException");
    const next = copy(old);
    const v = args.ExpressionAttributeValues;
    if (args.UpdateExpression === "SET revokedAt = :at") next.revokedAt = copy(v[":at"]);
    else if (args.UpdateExpression.includes("refreshHash = :new")) {
      next.body = copy(v[":body"]); next.ttl = copy(v[":ttl"]); next.refreshHash = copy(v[":new"]);
    } else throw Error("Unsupported update expression");
    state.set(pk, next); return {};
  }
  if (op === "TransactWriteItems") {
    const cloned = new Map([...state].map(([k,v]) => [k,copy(v)]));
    try {
      for (const tx of args.TransactItems) {
        const [name, payload] = Object.entries(tx)[0];
        exec(name === "Put" ? "PutItem" : name === "Delete" ? "DeleteItem" : "UpdateItem", payload, cloned);
      }
    } catch { throw error("TransactionCanceledException"); }
    state.clear(); for (const [k,v] of cloned) state.set(k,v);
    return {};
  }
  throw new Error("Unexpected DynamoDB operation: " + op);
}
const originalFetch = globalThis.fetch;
globalThis.fetch = async (_url, options) => {
  const operation = options.headers["x-amz-target"].split(".")[1];
  assert.match(options.headers.authorization, /^AWS4-HMAC-SHA256 Credential=test-access\//);
  let status = 200, output;
  try { output = exec(operation, JSON.parse(options.body), items); }
  catch (e) { status = 400; output = { __type: e.name }; }
  return new Response(JSON.stringify(output), { status, headers: { "content-type": "application/json" } });
};
try {
  const first = new DynamoOAuthStore("oauth-test-123", "us-east-1");
  const second = new DynamoOAuthStore("oauth-test-123", "us-east-1");
  const client = await first.registerClient("ChatGPT", ["https://client.example/callback"]);
  assert.deepEqual(await second.getClient(client.clientId), client);
  const pending = { clientId: client.clientId, redirectUri: client.redirectUris[0], challenge: "test", scope: "mcp:read", exp: Date.now() + 120000 };
  const codeHash = createHash("sha256").update("code").digest("hex");
  await first.saveCode(codeHash, pending);
  assert.deepEqual(await second.consumeCode(codeHash), pending);
  assert.equal(await first.consumeCode(codeHash), null, "authorization code is consumed once");
  const issued = await first.issue(client.clientId, "mcp:read");
  assert.equal((await second.resolveAccess(issued.access))?.scope, "mcp:read");
  const rotated = await second.rotate(issued.refresh, client.clientId);
  assert.ok(rotated && rotated.access !== issued.access);
  assert.equal(await first.resolveAccess(issued.access), null, "old access token is invalidated");
  assert.ok(await first.resolveAccess(rotated.access));
  assert.equal(await first.rotate(issued.refresh, client.clientId), null, "spent refresh rejected");
  assert.equal(await second.resolveAccess(rotated.access), null, "replayed refresh revokes grant");
  const another = await first.issue(client.clientId, "mcp:read");
  assert.equal(await second.revoke(another.access), true);
  assert.equal(await first.resolveAccess(another.access), null);
  console.log("DynamoDB OAuth store tests passed (offline)");
} finally { globalThis.fetch = originalFetch; }
