# ShanX13 AiGG Direct Commander — independent website

Owner: X / ShanX Services LLC.

This is a **separate website and repository**, not a page, route, subdirectory, DNS modification, or deployment of shanxservices.com. The green/gold design is original and references only general product-site conventions. It does NOT copy Desktop Commander's website source, brand assets, paid cloud service, or protected design.

## Scope and truth
- Public landing page with responsive navigation, interactive capability previews, security framing, and planned commercial tiers.
- Pricing, checkout, login, telemetry, device enrollment, and the published ChatGPT plugin are **not** implemented here. No buttons imply those services are live.
- All console images, waveforms, and device states are interface concepts and explicitly labeled. No fabricated live metrics.
- No credentials, tenant data, commands, machine contact, or payments are collected.
- The MIT-licensed Desktop Commander local MCP upstream remains separate, with intact copyright/license. The third-party hosted Remote Desktop Commander commercial backend is proprietary and is **not** copied.
- Source checkout was developed in M:\X13_CONTROL\MONSTER_DIRECT\SHANX_COMMANDER_COMMERCE_20261122\Standalone Site. Existing ShanXServices website repo was read-only inspected and NOT edited.

## Local test
Run `python -m http.server 8183` from this folder and open http://localhost:8183.
Use a browser automation or manual inspection of all responsive breakpoints. Run `node --check site.js` and `python tests/site_test.py`.

## Production gaps
Authenticated customer dashboard needs a real identity provider + tenant-separated database + usage event pipeline; payment collection needs an owner's verified merchant account; remote MCP enrollment needs a secure production device agent and OAuth; ChatGPT Directory publication requires independent submission and approval. Never claim saleability before end-to-end verification.
