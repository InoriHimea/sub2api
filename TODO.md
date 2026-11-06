# Maintained fork — open work

## [In progress] FORK-01 Native fork and task ownership migration (2026-11-06)

- Goal: maintain permanent server-side additions in an independent upstream-tracking fork rather than a downstream patch workflow.
- Acceptance: native GitHub parent/source relation, complete upstream ancestry and explicit remotes; direct source and regression ownership; technical task migration; latest-intake HTTP/PostgreSQL verification; immutable published source reference and retirement of duplicated feature entrypoints.
- Scope: source, repository metadata, technical tasks and synthetic local verification only; no deployments, live identities, consumer policy changes or provider requests.
- Current: native InoriHimea/sub2api fork verified with parent Wei-Shaw/sub2api; official main intake c5ca149a3d856d92fa0b61bea276338be718c5db, non-shallow history, Go1.27.3. Source and regressions are migrated and verified locally; publication and final ownership readback are in progress.
- Next: publish privacy-reviewed source/tasks, verify the downstream commit and upstream anchor, then close this migration task. Operational history and raw local evidence remain private.

## [Locally verified / release pending] HOUR-01 Additive hourly usage aggregates (2026-11-06)

- Goal: UTC hour × nullable group × requested-model aggregates with exact additive request/token/cost/duration statistics for sub-day and longer-window consumers.
- Contract and detailed implementation acceptance: docs/usage-hourly.md and openspec/changes/add-hourly-usage-aggregates/. Collector/storage/UI changes are owned by the downstream consumer, not duplicated here.
- Implementation: direct repository/service/handler/route code; RFC3339 half-open ranges, maximum31days, explicit row overflow, independent costs, duration sum and non-NULL count including0ms. PostgreSQL microsecond-grid handling preserves fractional-bound comparisons.
- Latest-intake adaptation: explicit usage.hourly.read global permission, independent of legacy usage.read/dashboard.read and not granting request/user details or writes.
- Evidence: seven focused pass events; ordinary unit round intentionally skips the gated PG case; three selected existing permission regressions pass; related packages build; explicit real PostgreSQL HTTP integration passes1/skip0; independent TCP HTTP smoke passes. Public sanitized summary: maintenance/verification/hourly-latest.json.
- Next: separate release/rollback review, narrowly authorized real consumer access and live hourly reconciliation. Local verification is not deployment acceptance.

## [Owned / adaptation pending] ADMKEY-01 Administrator creation of a target user's API key (2026-11-06)

- Goal: a formal admin operation can create an API key for a specified user while backend-only mode stays enabled, without borrowing a user session or disabling global protection.
- Prior reference: implementation was qualified against older upstream0.2.16/01842576b3d5c1e2545b5a99ad555d36e28ed306; this does not qualify the current intake. Historical material is retained privately.
- Acceptance: compare current native capabilities first, then retain the minimum necessary direct-source difference for POST /api/v1/admin/users/:id/api-keys; enforce target user/group/subscription constraints and current restricted-admin permissions; real synthetic PostgreSQL/Redis/HTTP and audit/cache regressions must pass.
- Risk: key insertion and idempotency success recording were not one transaction. Review unknown-result recovery and do not claim exactly-once behavior or blindly repeat writes under a new idempotency key.
- Current: technical task ownership migrated; the old implementation is not blindly applied to this intake. No real account or key provisioning is performed.

## [Owned / semantic comparison pending] OBS-01 Long-lived HTTP failure and completion observations (2026-11-06)

- Goal: redacted failure-stage and per-request sampled native-stream completion metadata. Successful sampling defaults to0; no success error rows or changes to protocol/retry/timeout/account/model/TTFT policy.
- Prior reference: older0.2.17/060d0160417782cd962a0c7f460f6cd4565d4916 qualification is historical evidence, not current implementation acceptance.
- Acceptance: compare current upstream observations and port only necessary permanent extensions directly into source. Separate temporary timestamp/sequence/protocol bug workarounds; remove those already fixed upstream rather than carrying them indefinitely.
- Verification: synthetic loopback HTTP/TLS H1/H2 behavior and byte-preservation, redaction, sampling and performance checks. Real provider experiments, deployments or host/network changes require separate scope.
- Current: task migrated; no old mixed observation patch is blindly applied to maintained source.

## [Pending] SYNC-01 Upstream synchronization and release provenance gates (2026-11-06)

- Goal: track official upstream and reproducibly identify maintained downstream source, rather than rebuilding a permanent patch collection.
- Acceptance: reviewed commit/release intake and conflict handling; regression failures stop synchronization; artifacts identify immutable fork commit/compiler and independent digests. Inherited workflows are not assumed to be configured downstream CI.
- Current: explicit origin/upstream and intake lock exist; the synchronization procedure is in FORK.md. GitHub Actions are deliberately disabled; scheduled synchronization, fork CI, artifact releases and deployment are not configured.
- Next: configure a separate reviewed CI/release policy after source migration, without enabling automatic production changes.
