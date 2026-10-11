import { analyticsAdmin, analyticsData, searchConsole } from "./google.js";

/** Staging-only non-blocking read probe. Never logs credentials or traffic data. */
export async function verifyStagingGoogleAccess(): Promise<void> {
  try {
    const sites = await searchConsole().sites.list();
    const names = (sites.data.siteEntry ?? []).map(s => s.siteUrl ?? "");
    console.error(JSON.stringify({
      check: "GSC_LIST", ok: names.some(x => x.includes("cjrb.net")) &&
        names.some(x => x.includes("artisancutlery.net")), siteCount: names.length,
    }));
  } catch (error) {
    console.error(JSON.stringify({ check: "GSC_LIST", ok: false, code: String((error as { code?: unknown }).code ?? "API_ERROR") }));
  }

  try {
    const properties: { id: string; name: string }[] = [];
    let pageToken: string | undefined;
    do {
      const response = await analyticsAdmin().accountSummaries.list({ pageSize: 200, pageToken });
      for (const account of response.data.accountSummaries ?? []) {
        for (const p of account.propertySummaries ?? []) {
          if (p.property) properties.push({ id: p.property, name: p.displayName ?? "Unnamed" });
        }
      }
      pageToken = response.data.nextPageToken ?? undefined;
    } while (pageToken);
    console.error(JSON.stringify({ check: "GA4_LIST", ok: properties.length > 0, properties }));
    for (const p of properties.slice(0, 10)) {
      try {
        await analyticsData().properties.runReport({
          property: p.id,
          requestBody: {
            dateRanges: [{ startDate: "7daysAgo", endDate: "yesterday" }],
            metrics: [{ name: "sessions" }], limit: "1",
          },
        });
        console.error(JSON.stringify({ check: "GA4_REPORT", property: p.id, ok: true }));
      } catch (error) {
        console.error(JSON.stringify({ check: "GA4_REPORT", property: p.id, ok: false, code: String((error as { code?: unknown }).code ?? "API_ERROR") }));
      }
    }
  } catch (error) {
    console.error(JSON.stringify({ check: "GA4_LIST", ok: false, code: String((error as { code?: unknown }).code ?? "API_ERROR") }));
  }
}
