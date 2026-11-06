# Maintained Sub2API fork

## Provenance

- Downstream: <https://github.com/InoriHimea/sub2api>, a native GitHub fork of <https://github.com/Wei-Shaw/sub2api>.
- `origin` is the downstream repository; `upstream` is the original repository.
- Intake: official `main` at `c5ca149a3d856d92fa0b61bea276338be718c5db`, checked on 2026-11-06, `v0.2.19-49-gc5ca149a3`, complete non-shallow Git ancestry. Machine-readable provenance is in `upstream.lock.json`.
- The upstream license, attribution and branding assets are retained. Downstream source changes are not represented as official upstream releases.

## Ownership

This fork owns server-side extensions, their regressions and upstream maintenance. The downstream gateway retains its collector, storage, UI and operational tasks. Hourly usage requirements and implementation tasks follow the existing OpenSpec layout in `openspec/changes/add-hourly-usage-aggregates/`; the API contract is `docs/usage-hourly.md`. Other adaptation and synchronization work is recorded in `TODO.md`. Section headings are the task directory; there is no separate hand-maintained task index.

Hourly aggregation is maintained directly in `backend/`, not by applying patches at build time. Older experiments are migration evidence only, not a second implementation or proof against this intake. Historical operational records and raw local logs are retained privately, not published in this repository.

## Upstream synchronization

1. Fetch official refs with `git fetch upstream`. Record the exact candidate commit/release relative to `upstream.lock.json`; never build or deploy an unreviewed floating `main/latest` reference.
2. Merge a reviewed official commit into an isolated synchronization branch derived from downstream `main`. Preserve ancestry; stop on conflicts or regression failures instead of force-pushing or resetting maintained work.
3. Compare each downstream extension with current native upstream behavior. Once upstream has an equivalent implementation proven against the contract, remove the duplicate downstream difference. Temporary bug workarounds remain separate from permanent features.
4. Update the intake lock and `upstream-main` anchor through reviewable commits. Only fetch from `upstream`; do not push downstream commits there. Local `main` tracks `origin/main`.
5. Re-run the focused behavior and explicit real-PostgreSQL HTTP checks. Downstream release artifacts must identify an immutable fork commit and compiler version.

GitHub Actions remain deliberately disabled remotely. The local release workflow is dispatch-only, defaults to dry run, requires a reviewed full source SHA, and gates publication on candidate regressions, compiler/digest provenance, an explicit repository opt-in and the `fork-release` environment. Required environment reviewers/protected refs must be configured before publication is enabled; YAML alone does not establish those protections. Policy and local verification limits are recorded in `.github/release-tools/README.md`. No automatic VERSION branch write, upstream synchronization or deployment is configured; remote CI/release acceptance remains open in `TODO.md`.

## Verification and security boundary

- Restricted administrator keys require the new explicit global `usage.hourly.read` permission for hourly aggregates. Existing `usage.read`/`dashboard.read` keys do not silently gain it, and hourly-only access does not grant request/user details or write methods. Query `group_id` is filtering, not authorization isolation. Existing administrator JWT and full-access compatibility semantics are unchanged.
- The PostgreSQL regression requires `SUB2API_USAGE_HOURLY_TEST_OWNED=1` and a synthetic loopback database URL ending in `_test`. It creates only a session-local temporary table and uses read-only query sessions. Missing fixtures or Skip are not real integration acceptance.
- Public validation summaries are in `maintenance/verification/`. They contain no operational endpoints, local paths, production credentials or raw logs. Verification uses synthetic loopback resources and does not imply OS-level network namespace isolation or production deployment.
- Deployment, real consumer identities, live permission changes, account provisioning and paid provider requests are separate operations, not authorized or performed by source migration.

## Native HTTP observation contract (OBS-01)

- The current upstream already owns response-model observation, `created_at` filling, `sequence_number` and protocol normalization. The fork adds only HTTP dispatch/body/parser observations; it does not carry alternate implementations of those upstream fixes or change protocol, retry, timeout, account/model selection or TTFT policy.
- `gateway.openai_http_observation_success_sample_rate` (environment `GATEWAY_OPENAI_HTTP_OBSERVATION_SUCCESS_SAMPLE_RATE`) must be finite in `[0,1]`, default0. Sampling is chosen once per request sequence, retained across retries, and emits completion metadata only for the native Responses parser. Configure the actual service environment/YAML; a Compose `.env` entry alone is not container injection.
- `openai.upstream_http_complete` is a structured log, not an Ops success-error row. Completion requires an observed native `response.completed`/`response.done` with no failure or cancellation; EOF or `[DONE]` alone is not proof of completion. Client write failures/cancellation do not acquire provider-failure attribution.
- Failure diagnostics attach immutable per-attempt snapshots to existing Ops error JSON and emit `openai.upstream_http_failure` with bounded stage classification. Credential-acquisition failures do not inherit prior HTTP-attempt data. New fields retain allowlisted protocol/ALPN/network/rejection codes, numeric times/counts and numeric peer address only; no prompts, tokens, headers, arbitrary error text or provider payload are retained by these observations.
- Transport timing starts at dispatch; SSE timing measures parser processing, not packet arrival. Existing `first_token_ms` retains its forward-start clock. Downstream write/flush timings measure actual writer calls, not first-output staging and not proof of client receipt or Internet backpressure. `-1` means unobserved, not zero latency.
- Local synthetic checks cover real HTTP→Forward→TLS H1/H2, unchanged SSE bytes with sampling0/1, authoritative terminal/cancellation/writer failures, non2xx redaction, H2 resets, immutable retry snapshots and native flush/timestamp regressions. No live model requests, production error-table insertion, deployment or OS-level network namespace isolation is claimed.

## Independent Test deployment

`deploy/test-independent/compose.yaml` defines a separate Compose project with bind-mounted data, a nonroot/read-only application, loopback-only port18085 and dedicated networks. Only the app joins the ingress bridge; PostgreSQL/Redis use an internal-only network and publish no host ports. Docker29 does not publish a port for an internal-only application attachment, so do not remove the separate ingress network. Access the UI through an SSH tunnel to the Test host, not an unauthenticated LAN/public setup endpoint.

- Artifact identity and exercised checks: `maintenance/verification/test-independent-20261107.json`. The application commit and deployment Compose digest are separate identities. Package prebuilt binaries and shell entrypoints with explicit0755 modes: plain `cp` under umask077 can make the entrypoint unreadable to the nonroot runtime.
- Initial state deliberately uses `AUTO_SETUP=false`. `GET /setup/status` returning `needs_setup:true` and a healthy container prove the initialization surface only, not migrations, login or hourly/admin-key business acceptance. Success sampling stays0.
- PostgreSQL and Redis belong to the `initialized` profile. Before enabling it, obtain the dedicated approved OpenBao purpose and controlled bootstrap delivery; do not reuse another instance's credentials or substitute trust authentication. Required protected files are the PostgreSQL password and Redis configuration under the deployment's `secrets` directory; do not place their values in `.env`, CLI arguments, logs or this repository. The nonsensitive `.env` pins image identities only.
- Once credentials are properly provisioned, database/Redis service names inside the application network are `postgres` and `redis`, with database/user `sub2api_fork_test`/`sub2api_test`. Completing the private wizard is a separate controlled operation; profile activation alone does not initialize the application.
- Restart smoke exercised the application and verified nonroot bind-mount persistence. Six existing Test service identities/start times/restart counters stayed unchanged. A local-only browser rendered the real setup form; payment SDK requests were intentionally blocked by its verification allowlist, not reported as an unrestricted all-network UI test.

Use the recorded deployment directory as `TEST_ROOT`; never point these commands at an existing business stack:

```sh
docker compose --project-directory "$TEST_ROOT" -f "$TEST_ROOT/compose.yaml" restart app
docker compose --project-directory "$TEST_ROOT" -f "$TEST_ROOT/compose.yaml" up -d --wait --wait-timeout 60 --no-build --pull never app
# Reversible rollback for this new instance: stop only its application.
docker compose --project-directory "$TEST_ROOT" -f "$TEST_ROOT/compose.yaml" stop app
# Approved removal of this independent project's containers/networks, preserving bind-mounted data:
docker compose --project-directory "$TEST_ROOT" -f "$TEST_ROOT/compose.yaml" down
```

Do not delete bind-mounted data, run volume-pruning commands, touch existing proxy routes, or restore a database automatically. After initialization, future upgrades require a separately reviewed data/schema rollback plan; the pre-initialization stop/start check is not proof of database rollback.
