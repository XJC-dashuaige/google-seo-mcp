/**
 * Low-level DynamoDB JSON API client for the optional durable OAuth store.
 * Uses Node's built-in SigV4 primitives: avoids introducing dependencies into the
 * App Runner npm lockfile. Not enabled until the store adapter is complete.
 *
 * Security: credentials come exclusively from the App Runner task role; never
 * accept an endpoint or credential URL from MCP requests. No token values/logs.
 */
import { createHash, createHmac } from "node:crypto";
import { envValue } from "./env.js";

type Json = Record<string, unknown>;
type Credentials = { accessKeyId: string; secretAccessKey: string; sessionToken?: string; expiration?: number };
const hex = (data: string) => createHash("sha256").update(data).digest("hex");
const hmac = (key: Buffer | string, data: string) => createHmac("sha256", key).update(data).digest();
const hmacHex = (key: Buffer | string, data: string) => createHmac("sha256", key).update(data).digest("hex");

export function signDynamoRequest(args: {
  method?: string; host: string; region: string; target: string; body: string;
  accessKeyId: string; secretAccessKey: string; sessionToken?: string;
  date: Date;
}): Record<string, string> {
  const { host, region, target, body, accessKeyId, secretAccessKey, sessionToken, date } = args;
  const amzDate = date.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const day = amzDate.slice(0, 8);
  const headers: Record<string, string> = {
    "content-type": "application/x-amz-json-1.0",
    host,
    "x-amz-date": amzDate,
    "x-amz-target": "DynamoDB_20120810." + target,
  };
  if (sessionToken) headers["x-amz-security-token"] = sessionToken;
  const names = Object.keys(headers).sort();
  const canonicalHeaders = names.map((k) => k + ":" + headers[k].trim() + "\n").join("");
  const signed = names.join(";");
  const request = [
    args.method ?? "POST", "/", "", canonicalHeaders, signed, hex(body),
  ].join("\n");
  const scope = day + "/" + region + "/dynamodb/aws4_request";
  const toSign = ["AWS4-HMAC-SHA256", amzDate, scope, hex(request)].join("\n");
  const signingKey = hmac(hmac(hmac(hmac("AWS4" + secretAccessKey, day), region), "dynamodb"), "aws4_request");
  headers.authorization = "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/" + scope +
    ", SignedHeaders=" + signed + ", Signature=" + hmacHex(signingKey, toSign);
  return headers;
}

let cache: Credentials | null = null;
async function taskCredentials(): Promise<Credentials> {
  if (cache && (!cache.expiration || cache.expiration > Date.now() + 120_000)) return cache;
  const accessKeyId = envValue("AWS_ACCESS_KEY_ID");
  const secretAccessKey = envValue("AWS_SECRET_ACCESS_KEY");
  if (accessKeyId && secretAccessKey) {
    return { accessKeyId, secretAccessKey, sessionToken: envValue("AWS_SESSION_TOKEN") };
  }
  const relative = envValue("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI");
  const full = envValue("AWS_CONTAINER_CREDENTIALS_FULL_URI");
  // Restrict metadata lookups to the documented task-credential endpoint.
  const endpoint = relative && relative.startsWith("/")
    ? "http://169.254.170.2" + relative
    : full && /^https?:\/\/(169\.254\.170\.2|127\.0\.0\.1|localhost)(:\d+)?\//.test(full)
      ? full : null;
  if (!endpoint) throw new Error("AWS task role credentials are unavailable");
  const response = await fetch(endpoint, { signal: AbortSignal.timeout(4000) });
  if (!response.ok) throw new Error("AWS task role credentials could not be retrieved");
  const value = await response.json() as { AccessKeyId: string; SecretAccessKey: string; Token?: string; Expiration?: string };
  if (!value.AccessKeyId || !value.SecretAccessKey) throw new Error("Invalid task role credentials");
  cache = {
    accessKeyId: value.AccessKeyId, secretAccessKey: value.SecretAccessKey,
    sessionToken: value.Token,
    expiration: value.Expiration ? Date.parse(value.Expiration) : Date.now() + 15 * 60_000,
  };
  return cache;
}

export function dynamoString(value: string): { S: string } { return { S: value }; }
export function dynamoNumber(value: number): { N: string } { return { N: String(value) }; }

export class DynamoApi {
  constructor(readonly table: string, readonly region: string) {
    if (!/^[A-Za-z0-9_.-]{3,255}$/.test(table)) throw new Error("Invalid DynamoDB table name");
    if (!/^[a-z]{2}-[a-z-]+-\d$/.test(region)) throw new Error("Invalid AWS region");
  }
  async call(operation: string, input: Json): Promise<Json> {
    const host = "dynamodb." + this.region + ".amazonaws.com";
    const body = JSON.stringify(input);
    const creds = await taskCredentials();
    const headers = signDynamoRequest({
      host, region: this.region, target: operation, body, date: new Date(), ...creds,
    });
    const response = await fetch("https://" + host + "/", {
      method: "POST", headers, body, signal: AbortSignal.timeout(8000),
    });
    const output = await response.json() as Json;
    if (!response.ok) {
      const type = String(output.__type ?? "DynamoDbError").split("#").pop();
      // Do not echo service payloads; unexpected server errors can include identifiers.
      const staging = envValue("SEO_MCP_STAGING_DIAGNOSTIC") === "1";
      const raw = String(output.message ?? output.Message ?? "");
      const detail = staging ? raw.slice(0, 240).replace(/[A-Za-z0-9_/-]{32,}/g, "[redacted]") : "";
      const e = new Error(detail ? type + ": " + detail : type);
      e.name = type ?? "DynamoDbError";
      throw e;
    }
    return output;
  }
  key(pk: string): Json { return { pk: dynamoString(pk) }; }
  async get(pk: string): Promise<Json | null> {
    const r = await this.call("GetItem", { TableName: this.table, Key: this.key(pk), ConsistentRead: true });
    return (r.Item as Json | undefined) ?? null;
  }
  async put(pk: string, values: Json, condition?: string): Promise<void> {
    await this.call("PutItem", {
      TableName: this.table, Item: { pk: dynamoString(pk), ...values },
      ...(condition ? { ConditionExpression: condition } : {}),
    });
  }
  async delete(pk: string, returnOld = false): Promise<Json | null> {
    const r = await this.call("DeleteItem", {
      TableName: this.table, Key: this.key(pk),
      ...(returnOld ? { ReturnValues: "ALL_OLD" } : {}),
    });
    return (r.Attributes as Json | undefined) ?? null;
  }
  async transaction(actions: Json[]): Promise<void> {
    await this.call("TransactWriteItems", { TransactItems: actions });
  }
  async scan(prefix: string): Promise<Json[]> {
    const out: Json[] = [];
    let last: Json | undefined;
    do {
      const r = await this.call("Scan", {
        TableName: this.table,
        FilterExpression: "begins_with(pk, :prefix)",
        ExpressionAttributeValues: { ":prefix": dynamoString(prefix) },
        ...(last ? { ExclusiveStartKey: last } : {}),
      });
      out.push(...((r.Items as Json[] | undefined) ?? []));
      last = r.LastEvaluatedKey as Json | undefined;
    } while (last);
    return out;
  }
}
