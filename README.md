# Rootprint — the Tunda fork

> This is [`skyver-labs/rootprint`](https://github.com/skyver-labs/rootprint), a fork of
> [`rootprint/rootprint`](https://github.com/rootprint/rootprint) in which **Tunda is the only way
> to obtain a session**. The local identity system is deleted rather than disabled: no passwords, no
> social login, no console-issued API keys, no local roles. **[FORK.md](FORK.md)** is the divergence
> register and the authority on what differs.
>
> Everything below is upstream's own README, corrected where the fork made it untrue.

[![Bun](https://img.shields.io/badge/Bun-%23000000.svg?logo=bun&logoColor=white)](#)
[![Hono](https://img.shields.io/badge/Hono-%23E36002.svg?logo=hono&logoColor=white)](#)
[![SvelteKit](https://img.shields.io/badge/SvelteKit-%23FF3E00.svg?logo=svelte&logoColor=white)](#)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-%234169E1.svg?logo=postgresql&logoColor=white)](#)
[![Release](https://img.shields.io/github/v/release/rootprint/rootprint)](https://github.com/rootprint/rootprint/releases)
[![License](https://img.shields.io/github/license/rootprint/rootprint)](LICENSE)

### [Live demo](https://demo.rootprint.io) &nbsp;·&nbsp; [Quick start](#quick-start) &nbsp;·&nbsp; [Docs](https://docs.rootprint.io) &nbsp;·&nbsp; [Contributing](CONTRIBUTING.md) &nbsp;·&nbsp; [Changelog](CHANGELOG.md)

Open-source, self-hosted log management with full-text search on object-storage-backed indexes.

Rootprint gives engineering teams a focused log search UI, OpenTelemetry ingestion for logs and
traces, team access control, and Quickwit-powered search without sending telemetry to a hosted SaaS.

> [!TIP]
> **Try it now at [demo.rootprint.io](https://demo.rootprint.io)** - live OpenTelemetry logs and
> traces from a running demo cluster. Read-only, no signup, nothing to install.

[![Rootprint screenshot](.github/assets/hero-screenshot.png)](https://demo.rootprint.io)

## What You Get

- **Search on object storage** - Query indexes stored on S3, MinIO, R2,
  GCS, Azure Blob, or local disk.
- **Open ingestion** - Send logs and traces through OTLP Protobuf or NDJSON HTTP, with OpenTelemetry
  Collector, Vector, Fluent Bit and other OTEL-compatible
  sources.
- **Traces** - View OpenTelemetry traces alongside your logs.
- **Incident-ready UI** - Use severity-aware rows, histograms, field filters, saved views,
  detail drawers, share links, and result exports.
- **Team access** - People sign in with Tunda, and are administered there. This fork issues no
  credential of its own: no password, no invite, no personal or service-account API key, and no
  local role. A telemetry producer authenticates as a registered Tunda client whose permitted
  destinations are signed into its token.
- **Admin controls** - Manage indexes, sources, field configuration, activity, and
  Quickwit.
- **Open source** - Apache-2.0 licensed. Run it, inspect it, fork it.

## Quick Start

```bash
curl -o docker-compose.yml https://docs.rootprint.io/files/docker-compose.full.yaml
docker compose up -d
```

Open:

```text
http://localhost:8282
```

Then:

1. Sign in. You are sent to Tunda, and you come back with a session — there is no account to create
   here, and no first-administrator bootstrap.
2. Register a telemetry producer as a Tunda client with the `observability.logs.ingest` scope and
   the destinations it may write to. The console cannot mint one; see **Settings -> Send logs &
   traces** for the exporter configuration.
3. Send logs to the bundled OpenTelemetry index (`otel-logs-v0_9`). A producer granted a traces
   destination ships spans to `POST /v1/traces`.
4. Search them from the Rootprint UI.

Configuration this fork requires and upstream does not:

```text
TUNDA_ISSUER            the COMPLETE tenant issuer, as a token's `iss` carries
                        it: https://id.example.com/t/tnt_…  (not an origin)
TUNDA_CLIENT_ID         this console's registration
TUNDA_CLIENT_KEY_ID     the kid Tunda registered for this console
TUNDA_CLIENT_PRIVATE_KEY  PKCS#8 PEM. No shared secret: private_key_jwt
TUNDA_REDIRECT_URI      …/api/auth/callback
CONSOLE_SESSION_KEY     32 bytes, base64. Never generated; a missing one refuses to start
TUNDA_ENVIRONMENT       which deployment this is, as producer tokens name it
```

Upstream's install guide still applies to everything else:
https://docs.rootprint.io/install/docker-compose

## Documentation

- Live demo: https://demo.rootprint.io
- Docs: https://docs.rootprint.io
- Quickstart: https://docs.rootprint.io/quickstart
- Send logs: https://docs.rootprint.io/send-logs/overview
- API reference: https://docs.rootprint.io/api/overview
- Query syntax: https://docs.rootprint.io/search/query-language

## Repository Layout

```text
apps/api   Hono API: ingest, search proxy, auth, admin operations
apps/web   SvelteKit SPA: log explorer and administration UI
```

## Local Development

```bash
bun install
cp .env.example .env
docker compose up -d db quickwit
bun --filter api db:migrate
bun run dev:api
bun run dev:web
```

Common checks:

```bash
bun --filter '*' check
bun run lint
bun run format:check
bun --filter api build
```

## Status

Rootprint is under active development and has not reached 1.0.

Expect breaking changes in APIs, configuration, storage schema, and runtime behavior between
releases. Pin exact versions and read the changelog before upgrading.

See [CHANGELOG.md](CHANGELOG.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
