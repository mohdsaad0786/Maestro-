# Maestro

Maestro is an API-first, human-in-the-loop cloud posture scanner. This initial release discovers S3 buckets, Google Cloud Storage buckets, and Azure Storage accounts, stores their relationships and evaluated findings, and provides a read-only dashboard. **It is a foundation, not a 500-rule or fully production-ready CSPM product.** The seven shipped controls are explicitly listed by `GET /api/v1/rules`; unsupported services and permissions do not silently pass scans.

## Quick start

Requirements: Go 1.26+ (required by the pinned cloud SDK dependencies), Node 24+, pnpm 10+, and a cloud SDK credential chain for whichever provider you scan. No cloud credentials are needed to run the UI or API.

```sh
cd backend
export MAESTRO_API_TOKEN="$(openssl rand -hex 32)"
export MAESTRO_DATABASE_URL="file:maestro.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
go run ./cmd/maestro
```

In another shell, run `cd frontend && pnpm install && pnpm dev`. Open the Vite URL and paste your API token into the connection form (held only in memory). The development proxy routes `/api` to the backend. To scan, set `GOOGLE_CLOUD_PROJECT` for GCP or `AZURE_SUBSCRIPTION_ID` for Azure in the backend environment, then select a provider in the UI. AWS uses the default SDK credential chain (`AWS_REGION` must be configured) and lists buckets in the current account; GCP and Azure likewise use their SDK default credentials. Grant least-privilege read-only inventory and configuration permissions. No credentials or Terraform changes are stored or applied by Maestro.

```sh
curl -H "Authorization: Bearer $MAESTRO_API_TOKEN" http://127.0.0.1:8080/api/v1/rules
curl -X POST -H "Authorization: Bearer $MAESTRO_API_TOKEN" -H 'Content-Type: application/json' -d '{"provider":"aws"}' http://127.0.0.1:8080/api/v1/scans
```

`MAESTRO_API_TOKEN` is required (minimum 32 characters). `MAESTRO_DATABASE_URL` defaults to a local SQLite file; PostgreSQL URLs beginning with `postgres://` or `postgresql://` use pgx. `MAESTRO_LISTEN` defaults to `127.0.0.1:8080`; for containers set `:8080`. `/healthz` and `/readyz` expose only status codes without authentication; `/metrics` and all `/api/v1/*` require a bearer token. Put a TLS-terminating authenticated ingress in front of any non-loopback listener. For shared deployments, manage the API token as a secret, rotate it, and restrict access to the database and metrics.

## API

- `POST /api/v1/scans` with `{"provider":"aws|gcp|azure"}` performs a bounded synchronous scan, returning counts. One scan is accepted per process at a time; concurrent submissions return 409. A failed discovery or rule evaluation **does not replace** previously committed results.
- `GET /api/v1/resources`, `/api/v1/findings`, `/api/v1/graph`, `/api/v1/scans`, and `/api/v1/rules` return JSON arrays. Resource IDs and finding IDs are stable across repeated scans. Findings contain rule, resource, severity, framework references, and a review-only Terraform recommendation.
- `GET /metrics` returns Prometheus scan counters and latency histogram. `/healthz` is process liveness and `/readyz` checks database connectivity.

## Boundaries and roadmap

The scanner currently covers **one resource family per provider** and **seven curated controls**, not 500+. Framework labels are directional references, not an audit attestation. Missing explicit bucket-level protection can be offset by account or organization policies; review context before remediating. Remediation is advice only; no Terraform is applied. The graph is stored as parent relationships in SQL; Neo4j is not required. SQLite and the per-process scan lock are for single-instance use; the PostgreSQL schema is usable across instances for reads, but distributed job scheduling and scan coordination are **not implemented**. An external identity-aware gateway, per-tenant authorization, asynchronous durable job queue, multi-account onboarding, audit trail, broader inventory, validated 500+ control catalog, and distributed tracing remain required before multi-tenant production deployment. Live cloud scans require authorized test accounts: the available AWS emulator supports STS and listing buckets but not the security-configuration operations this scanner uses; its Google and Microsoft emulators do not expose Storage or Azure ARM. See `deploy/k8s/README.md` for deployment constraints.

## Development

```sh
cd backend && go test ./... && go vet ./...
cd frontend && pnpm install --frozen-lockfile && pnpm run build
```

Backend benchmarks: `cd backend && go test ./internal/core -run '^$' -bench .`.

The GitHub Actions definition is provided as `deploy/ci-template.yml`. To enable CI, a repository maintainer with GitHub workflow-write permission must copy it to `.github/workflows/ci.yml`; the task's GitHub App cannot publish workflow changes.
