# Maintained fork — completion evidence

## [Completed] FORK-01 Native fork and task ownership migration (2026-11-06)

- Goal: create an independent upstream-tracking fork for permanent server-side additions and migrate their source/tests/technical tasks, rather than maintain feature patch application paths in the consumer project.
- Native fork: https://github.com/InoriHimea/sub2api; GitHub reports fork=true, parent/source=Wei-Shaw/sub2api, default branch main. Official intake is c5ca149a3d856d92fa0b61bea276338be718c5db, complete non-shallow ancestry, v0.2.19 plus49 commits, Go1.27.3.
- Published source commit: 15004bb0ab562f98e22fea73434ef3d1d5ce50e1; main and the upstream-main anchor were read back at the expected commits, and official ancestry was checked. origin is the maintained fork and upstream is the original repository.
- Hourly aggregate source/regressions and the explicit hourly-only permission are maintained directly in backend. HOUR-01 details follow the existing OpenSpec layout; ADMKEY-01/OBS-01/SYNC-01 adaptation and maintenance tasks are owned by this fork's TODO.md. Consumer collector/storage/UI work remains outside this repository.
- Latest-intake verification: focused behavior7 pass events with one explicitly gated PG skip; selected existing permission regressions3 pass events; related packages build. The explicit synthetic real PostgreSQL HTTP integration is1pass/0skip, and an independent actual TCP HTTP smoke passes, including fractional half-open bounds and permission isolation. Sanitized source-bound evidence is maintenance/verification/hourly-latest.json.
- Old hourly and administrator-key feature patch application entrypoints were retired in the consumer project. Historical implementation/operational records and raw logs remain private; no such records or local paths are published here.
- Inherited GitHub Actions are disabled; no automatic synchronization, release pipeline or deployment was enabled. Test data/services and temporary smoke scaffolding were cleaned up. No business credentials, live permission changes, real account provisioning or provider requests were involved.
- Remaining work is explicit: HOUR-01 release/live-consumer acceptance, ADMKEY-01 latest-intake adaptation, OBS-01 semantic comparison, and SYNC-01 reviewed CI/release gates. Source migration does not claim those separate tasks are complete.
