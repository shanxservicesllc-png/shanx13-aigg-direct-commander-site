# ShanX13 AiGG Direct Commander — separate commercial portal backend

Owner: X / ShanX Services LLC. Independent ShanX13 AiGG product; does NOT change shanxservices.com, previous Commander Cloudflare Workers, X13 canonical task/transport, or installed agents.

This is a source candidate, not a saleable or production-approved system. No customer billing, no OAuth ChatGPT app, and no machine command execution has been verified.

## Trust boundaries
- Distinct new Cloudflare Worker: shanx13-aigg-direct-commander-account.
- New D1 database: shanx13-aigg-direct-commander-usage (never use the old relay D1 database).
- Owner logs into Cloudflare Access using an exact allowlisted email, configured as a secret, not embedded in code. Customers are enrolled separately into dedicated tenant_id records. Cloudflare Access JWTs must have valid RS256 signature, specific issuer, exact Access AUD, unexpired token, valid email. The Worker validates the signature itself.
- A login to the public marketing website is not an authentication mechanism. Marketing is hosted separately and collects no secrets.
- Agents receive individually scoped, one-time 48-byte tokens; only SHA-256 token hashes are stored in D1. POST /api/agent/events accepts authenticated, idempotent usage only; no commands are accepted or executed.
- Usage counts are computed directly from dedicated D1 event records; absence of events is shown as zero with provenance, not synthetic traffic.
- OWNER_EMAILS, ACCESS_TEAM_DOMAIN, ACCESS_AUD must be entered on the NEW Worker via secure Cloudflare configuration. The Worker fails closed with 503 until all required bindings exist.
- Portal pages have anti-framing and strict CSP. No client code sets identity, roles, tenant, usage totals, or payment state.

## Deployment gates
1. Verify owner X's signed-in Cloudflare account (not Mr. Who and not an unrelated Chrome profile).
2. Create a NEW D1 database; apply schema.sql to only that database; fill its exact ID in wrangler.jsonc.
3. Create NEW Worker and NEW Cloudflare Access app for its hostname; require owner verified Google identity and tenant-specific customer policy; configure Access app AUD and team domain.
4. Test unauthenticated denial, owner login, customer isolation, agent token revocation, idempotent usage records, real browser usage figures, request rate controls.
5. Configure and test licensed payment processing, customer subscription state/entitlement enforcement, checkout, refunds/support, terms/privacy, and account lifecycle. Payment processing is NOT implemented in this milestone.
6. Integrate a physically tested, signed, separate-per-customer device agent running the MIT-licensed local MCP engine with verified OS isolation and owner STOP; build OAuth 2.1 MCP endpoint and submit the ChatGPT plugin separately. NONE of these gates is implied by a page loading.

## Local check
Run node --check worker.mjs, node --test tests/portal.test.mjs. No credentials are required for synthetic tests.
