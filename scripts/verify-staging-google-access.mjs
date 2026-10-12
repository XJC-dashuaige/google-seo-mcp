/**
 * Run ONLY in staging, before the HTTP server starts.
 * Checks Google service-account access without revealing credentials or analytics.
 * Outputs statuses and optionally property IDs/names; no customer-level data.
 */
import { analyticsAdmin, analyticsData, searchConsole } from "../dist/google.js";

async function verify() {
  let gscOk = false, ga4Count = 0, ga4ReportsOk = 0;
  try {
    const r = await searchConsole().sites.list();
    const names = (r.data.siteEntry ?? []).map(s => s.siteUrl);
    gscOk = names.some(s => s?.includes("cjrb.net")) && names.some(s => s?.includes("artisancutlery.net"));
    console.log(JSON.stringify({ check: "GSC_LIST", ok: gscOk, siteCount: names.length }));
  } catch (err) {
    console.error(JSON.stringify({ check: "GSC_LIST", ok: false, error: err?.code ?? err?.message?.slice(0,120) }));
  }

  try {
    const properties = [];
    let pageToken;
    do {
      const r = await analyticsAdmin().accountSummaries.list({ pageSize: 200, pageToken });
      for (const a of r.data.accountSummaries ?? []) {
        for (const p of a.propertySummaries ?? []) if (p.property) properties.push({
          id: p.property,
          name: p.displayName ?? "Unnamed",
        });
      }
      pageToken = r.data.nextPageToken ?? undefined;
    } while (pageToken);
    ga4Count = properties.length;
    console.log(JSON.stringify({ check: "GA4_LIST", ok: ga4Count > 0, properties }));
    for (const p of properties.slice(0, 10)) {
      try {
        const r = await analyticsData().properties.runReport({
          property: p.id,
          requestBody: { dateRanges: [{ startDate: "7daysAgo", endDate: "yesterday" }], metrics: [{ name: "sessions" }], limit: "1" },
        });
        ga4ReportsOk++;
        console.log(JSON.stringify({ check: "GA4_REPORT", property: p.id, ok: Boolean(r.data) }));
      } catch (err) {
        console.error(JSON.stringify({ check: "GA4_REPORT", property: p.id, ok: false, error: err?.code ?? err?.message?.slice(0,120) }));
      }
    }
  } catch (err) {
    console.error(JSON.stringify({ check: "GA4_LIST", ok: false, error: err?.code ?? err?.message?.slice(0,120) }));
  }
  console.log(JSON.stringify({ check: "SUMMARY", gscOk, ga4Count, ga4ReportsOk }));
  if (!gscOk || ga4ReportsOk === 0) process.exitCode = 1;
}
await verify();
