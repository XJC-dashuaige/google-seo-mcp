# AWS App Runner deployment notes (read-only Search Console MCP)

This branch provides **preparation only**, not a live deployment.

## Recommended baseline
- Region: us-east-1
- Source repository: XJC-dashuaige/google-seo-mcp (this fork)
- Branch: main *after* reviewing and merging this PR
- Source directory: repository root
- Configuration: use apprunner.yaml
- Runtime: Node.js 22
- Port: 8080
- Health check: HTTP, path `/healthz`
- Initial compute: 0.25 vCPU / 0.5 GB
- Google APIs: Search Console API only
- Scope: read-only Search Console; `SEO_MCP_TOOLSETS=gsc`

## Do not put secrets in Git
- Set a long random `MCP_AUTH_TOKEN` through AWS configuration (prefer secret references).
- Set `GOOGLE_CREDENTIALS_JSON` via secure configuration for a *Google service account*.
- Add service-account identity with Search Console permissions only on intended properties.
- No secrets, OAuth refresh tokens or credential JSON belong in `apprunner.yaml`.
- Avoid enabling automatic deployment before persistence and end-to-end testing is resolved.

## ChatGPT OAuth caveat
This project's `SEO_MCP_OAUTH=1` uses a local SQLite `oauth.db` for client grants.
App Runner local storage is **ephemeral**. Client authorizations can disappear after an instance replacement/redeploy.
A persistent OAuth store or other compatible authentication architecture should be implemented and verified before production use. Merely providing an App Runner URL is not enough.

## Deployment checklist
1. Confirm AWS billing and credits eligibility, then explicitly approve creation of billable services.
2. Validate upstream project build against App Runner's managed Node.js 22 runtime.
3. Add Google service account access to intended Search Console properties.
4. Configure secrets and production OAuth persistence.
5. Create App Runner service and configure health check, then test `/healthz`.
6. Verify protected `/mcp` is not accessible anonymously and complete ChatGPT OAuth connection.
7. Limit CloudWatch retention and set AWS budget alarms.
