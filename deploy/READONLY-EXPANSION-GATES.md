# Read-only expansion gate: GSC + GA4 + Web + GEO + Analysis

Status: **PREPARATION ONLY. DO NOT APPLY TO LIVE APP RUNNER YET.**

## Current live service
- App Runner: `google-seo-mcp`, us-east-1
- Running source branch: `chore/aws-apprunner-readonly`
- ConfigurationSource: `API`, **NOT** `apprunner.yaml`. Editing YAML does not update the live service.
- Environment: `SEO_MCP_TOOLSETS=gsc`, `SEO_MCP_READ_ONLY=1`, `SEO_MCP_OAUTH=1`.
- Secrets: `GOOGLE_CREDENTIALS_JSON`, `MCP_AUTH_TOKEN` provided by AWS Secrets Manager; do not log, inspect, or commit their values.
- Auto deployments: disabled.

## Proposed future change (after all gates pass)
- `SEO_MCP_TOOLSETS=gsc,ga4,web,geo,analysis`
- Keep `SEO_MCP_READ_ONLY=1` and `SEO_MCP_OAUTH=1`.
- Keep all existing credential references, source branch and resource sizing until explicitly reviewed.
- Do **not** configure paid API keys or third-party credentials by default.
- For the first release, test without `BRAVE_API_KEY`, `PERPLEXITY_API_KEY`, `GOOGLE_PLACES_API_KEY`, `INDEXNOW_KEY`.
- Optionally configure a Google API key restricted to **PageSpeed Insights API**. For Chrome UX Report history/snapshot, configure a separate restricted `CRUX_API_KEY` and enable the Chrome UX Report API. Avoid unrestricted keys.

## Google access gate
1. In the existing Google Cloud project, enable Google Analytics Data API and Google Analytics Admin API.
2. Grant the existing GSC service-account identity Viewer on each intended GA4 **property**; no Owner/Editor or GA4 write scopes required.
3. Verify GA4 properties can be listed and a harmless historical read-only report runs after staging.
4. Independently verify the GSC site listing and site snapshot remain unchanged.

## Security gate
1. **Block production redeployment until OAuth persistence is solved.** Upstream `SEO_MCP_OAUTH=1` stores DCR registrations and rotating OAuth grant/refresh-token hashes in a local SQLite `oauth.db`; App Runner files are ephemeral and requests may use different instances.
2. Do not solve by merely setting `SEO_MCP_DATA_DIR` to another path inside the container. App Runner does not provide durable volume persistence.
3. Implement and test durable single-source state storage (e.g. DynamoDB-based OAuth store, including atomic refresh-token rotation/replay protection and client registration) or move OAuth to a vetted external authorization service. Enforce least privilege and avoid placing tokens in logs.
4. Ensure OAuth issuer/public URL matches the existing public endpoint and the ChatGPT registration flow works again after **replacement of the App Runner instance**.
5. Keep `MCP_AUTH_TOKEN` private. All MCP tools must remain read-only, including when the OAuth approval scope is broader.
6. Web audit/crawl tools fetch user-supplied URLs. Before widening access, assess SSRF risk and consider allowlisting audited domains (e.g. cjrb.net, artisancutlery.net), URL redirects and DNS rebinding defenses. Never give anonymous access.
7. Audit HTTP connections now use a dedicated dispatcher whose socket lookup validates the entire DNS answer set and passes those exact addresses to the socket. Private, reserved, mapped and transition addresses fail closed. Each redirect remains subject to the URL policy. Validate the connection on staging; local fake-IP proxies are intentionally rejected.
8. Review public dynamic client registration before production: the DynamoDB implementation scans the table during pruning and counting on each registration, and the client cap is checked separately from the async insert. Bound request cost and enforce capacity atomically before release.

## Cost and API gates
- Existing App Runner capacity usually covers the new tools, but crawling/PageSpeed can increase CPU time, duration, logs and request charges.
- GA4 Data/Admin APIs are quota-controlled; avoid high-frequency bulk reports.
- PageSpeed Insights API has quota limits; use a restricted key and start with low daily usage.
- An unauthenticated PageSpeed test on 2026-10-12 returned quota_limit_value=0 for consumer project 583797351490. The operator's Cloud Console project has a separate 25,000/day quota; do not describe this as that project's exhausted allowance. Use an explicitly authorized PageSpeed-only key and verify the actual result.
- CrUX API needs enablement and an API key and only returns field data for eligible origins/pages.
- Perplexity/Brave/Google Places can incur separate charges or require an account; keep those unset for this deployment.
- Set AWS budget notifications and CloudWatch log retention; budgets are NOT hard spending caps.

## Release / rollback criteria
1. Auth persistence integration tests pass: client registration, authorize, token exchange, rotate, replay prevention, restart/replacement.
2. Existing CI passes. Do not trigger `UpdateService` or `StartDeployment` before that.
3. Staging test discovers all expected read-only tools and no write tools; run GSC and GA4 read tests, PageSpeed and GEO on known safe pages.
4. Update the **App Runner API** configuration with the exact approved toolset change while preserving all other settings.
5. Verify service RUNNING, healthz, ChatGPT OAuth and both properties. Roll back to `gsc` immediately if authentication or GSC regressions occur.
