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
