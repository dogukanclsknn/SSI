# SSI — Secure Image Factory

SSI takes container images from public registries, scans them, patches their OS packages,
tests the patched candidates and publishes only approved images to a trusted catalog. Every
decision is policy-checked, approved by a second person and written to an audit trail.

> Originally built for an enterprise environment and published with permission. Company
> names, hosts and people have been replaced with placeholders (`registry.example.com`,
> `ssi-images`, `example-org`). The screenshots below use the built-in sample data.

![Dashboard](docs/screenshots/dashboard.png)

## How an image moves through SSI

```mermaid
flowchart LR
  A[Onboard<br/>quarantine registry] --> B[Scan<br/>Trivy]
  B --> C[Patch<br/>Copacetic, OS packages]
  C --> D[Verify<br/>re-scan]
  D --> E[Candidate test<br/>startup, config, packages]
  E --> F[Consumer acceptance]
  F --> G[Publish policy<br/>thresholds, four-eyes]
  G --> H[Controlled publish<br/>isolated worker]
  H --> I[(Approved catalog)]
  I -. problem found .-> J[Withdraw<br/>by digest]
```

**SSI orchestrates; it never pulls, patches or writes to the registry itself.** Each of those
steps runs in a narrowly scoped CI worker (Azure DevOps pipelines in this repository) that
reports back to SSI with an HMAC-signed result. The application server holds no registry
write credential.

## Features

| Area | What it does |
|---|---|
| Onboarding | Imports images only from allow-listed registries into a quarantine project |
| Scanning | Harbor/Trivy results, canonical reports, CVE queue with risk sorting, image comparison |
| Remediation | Plans fixable OS-package CVEs, patches with Copacetic, re-scans to verify, restores the runtime configuration |
| Pre-release testing | Automatic candidate test (startup, healthcheck, runtime config, package inventory) plus consumer-team sign-off |
| Publish policy | Versioned, fail-closed policy: severity thresholds, four-eyes approval, time-boxed risk acceptance |
| Controlled publish | Isolated worker, digest-pinned handoff, never overwrites a tag, signed receipt; moving `latest` alias |
| Withdrawal | Withdraws an image by digest and cancels its open requests in one transaction |
| Supply chain | Cosign signature, SBOM and provenance evidence; production-gate coverage |
| Identity | LDAP/AD sign-in, scrypt local break-glass admin, signed sessions, sign-in throttling, 4 roles |
| Multi-tenancy | Team-scoped data, publish boundaries and permissions, proven by end-to-end tests |
| Audit | Append-only event log with filters and CSV export |
| VM templates | Offline Ubuntu 24.04 template build (libguestfs): patch, scan, export QCOW2/OVA/VHDX, stream downloads; Windows Server ISO PoC |

## Screenshots

| | |
|---|---|
| ![Inventory](docs/screenshots/inventory.png) | ![Scan results](docs/screenshots/scan-results.png) |
| ![CVE queue](docs/screenshots/cve-queue.png) | ![Policy](docs/screenshots/policy.png) |
| ![Remediation](docs/screenshots/remediation.png) | ![OS templates](docs/screenshots/os-templates.png) |

## Tech stack

React + Vite · Node.js REST API (OpenAPI in `docs/openapi.yaml`) · PostgreSQL · Harbor ·
Trivy · Copacetic · Cosign · regctl · Azure DevOps Pipelines · libguestfs/QEMU · Docker Compose ·
Vitest + Playwright.

## Run it locally (demo mode)

Requirements: Node.js 22.

```bash
npm ci
npm run build
PERSISTENCE_DRIVER=memory SSI_FIXTURES=true SSI_DEV_LOGIN=true SSI_RBAC_ENFORCED=false node server.js
# open http://localhost:5021
```

Demo mode serves sample inventory and scan data and trusts the dev identity header. **Never use
these settings in production.** For a real deployment start from `.env.example` and
`docker-compose.yml` (PostgreSQL, migrations, Harbor, LDAP, Azure DevOps).

## Quality checks

```bash
npm run lint
npm test                 # ~1,000 unit tests
npm run build
# End-to-end tenancy suite (needs an empty PostgreSQL database):
DATABASE_URL=postgres://user:pass@localhost:5432/empty_db DATABASE_SSL_MODE=disable npm run test:e2e:tenancy
```

## Repository layout

| Path | Contents |
|---|---|
| `server.js`, `src/server/` | API server, stores, identity, Azure DevOps client |
| `src/lib/` | Pure domain logic (policy, remediation, publish lifecycle, RBAC) and its tests |
| `src/*.jsx` | React UI |
| `db/migrations/` | PostgreSQL schema |
| `azure-pipelines-*.yml` | Worker pipelines (onboard, scan, patch, test, publish, sign, VM templates) |
| `poc/os-template/` | VM template build scripts |
| `deploy/` | Reverse proxy and SSO examples |
| `docs/` | Worker contracts, RBAC, multi-tenancy, runbooks (mostly in Turkish) |

## License

No license has been chosen yet; all rights reserved until one is added.
