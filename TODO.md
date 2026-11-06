# Maintained fork — open work

## [Locally verified / release pending] HOUR-01 Additive hourly usage aggregates (2026-11-06)

- Goal: UTC hour × nullable group × requested-model aggregates with exact additive request/token/cost/duration statistics for sub-day and longer-window consumers.
- Contract and detailed implementation acceptance: docs/usage-hourly.md and openspec/changes/add-hourly-usage-aggregates/. Collector/storage/UI changes are owned by the downstream consumer, not duplicated here.
- Implementation: direct repository/service/handler/route code; RFC3339 half-open ranges, maximum31days, explicit row overflow, independent costs, duration sum and non-NULL count including0ms. PostgreSQL microsecond-grid handling preserves fractional-bound comparisons.
- Latest-intake adaptation: explicit usage.hourly.read global permission, independent of legacy usage.read/dashboard.read and not granting request/user details or writes.
- Evidence: seven focused pass events; ordinary unit round intentionally skips the gated PG case; three selected existing permission regressions pass; related packages build; explicit real PostgreSQL HTTP integration passes1/skip0; independent TCP HTTP smoke passes. Public sanitized summary: maintenance/verification/hourly-latest.json.
- 2026-11-07 review: docs/usage-hourly.md now records artifact identity, whole-intake migration compatibility, rollback/consumer pause, least-privilege checks and closed-hour reconciliation gates. Existing evidence explicitly excludes image/release and live acceptance; local Go1.27.3 is available.
- Blocked release: no selected target/current deployment identity, approved release/rollback materials or hourly consumer credential scope has been supplied in this repository. Existing statistics credential policies do not authorize this new GET. No deployment, credential read or live reconciliation performed.
- Next: obtain the narrowly scoped Test release and consumer acceptance inputs; HOUR-01 stays open. Ledger-order local work on2026-11-07 completed ADMKEY-01 and OBS-01 (TODO-m.md); SYNC-01 local gates are verified but remote acceptance remains open. No production changes were made.

## [In progress] TEST-01 Independent Test instance deployment (2026-11-07)

- Goal: user explicitly requested an independent instance in the existing Test environment, following the isolated-test proposal; do not replace any existing business instance.
- Scope: discover the documented Test host and deployment convention; build source-identifiable fork artifacts; create a separate application, PostgreSQL and Redis with isolated ports/network/data. Keep success sampling0, no production changes, existing business credential reads or real provider requests.
- Acceptance: independently running service with full UI, migrations and health verified; synthetic hourly/admin-key/observation behavior exercised where safely available; restart and rollback/removal path documented without touching existing stacks. Real consumer reconciliation remains a separate HOUR-01 gate.
- Host verified: root@192.168.58.34 using existing pinned torii-test-known_hosts; x86_64, Docker29.1.3/Compose5.0.0, about15GiB available memory and24GiB disk. /opt/sub2api-fork-test absent; existing Torii/Bifrost/AxonHub and databases remain untouched.
- Credential gate: no approved sub2api-fork-test OpenBao reader/enrollment exists in loaded rules or local deployment helpers. Do not borrow production usages/migration identities, read existing service secrets, generate a replacement secret store or enable trust authentication to bypass this gate.
- Reachable next: build the complete embedded-UI candidate and start a private loopback-only initialization instance with AUTO_SETUP disabled. Database/admin bootstrap, migrations and authenticated acceptance remain blocked pending controlled credential provisioning; this is not completion of TEST-01.

## [Local gates verified / remote acceptance pending] SYNC-01 Upstream synchronization and release provenance gates (2026-11-07)

- Goal: track official upstream and reproducibly identify maintained downstream source, rather than rebuilding a permanent patch collection.
- Acceptance: reviewed commit/release intake and conflict handling; regression failures stop synchronization; artifacts identify immutable fork commit/compiler and independent digests. Inherited workflows are not assumed to be configured downstream CI.
- Current: explicit origin/upstream and intake lock exist; the synchronization procedure is in FORK.md. GitHub Actions are deliberately disabled; scheduled synchronization, fork CI, artifact releases and deployment are not configured.
- Next: configure remote reviewed environment protections and execute the candidate dry-run only after separate authorization; local source gate preparation is complete, with no automatic production changes.
- 2026-11-07 local policy: release dispatch only, default dry run, full reviewed SHA match, explicit publication opt-in plus release environment, candidate unit/owned PG+Redis qualification dependency; removed automatic VERSION branch writes. Compiler provenance joins existing archive SHA-256 manifests and full-release assets.
- Evidence: actionlint passed; seven platform-independent helper regressions passed; real collect/verify CLI smoke accepted Go1.27.3 and rejected mismatched compiler. Configuration CLI confirmed no mutating pre-build hooks and readonly dependencies. Exact qualification parser accepted observed pass events and rejected missing admin integration.
- Limitation: full helper suite has Windows POSIX-mode/default-WSL limitations, not a green Linux/remote run. Generated manifests identify runner-reported compiler/commit/digests, not a cryptographic build attestation.
- Remaining: separately authorize remote Actions/environment reviewer and protected-ref configuration, then execute a reviewed immutable candidate dry-run matrix. No remote workflow enablement, upstream merge, publish, deployment or scheduled automation performed.
