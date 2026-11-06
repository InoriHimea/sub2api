# Release matrix

The release workflow builds the frontend once, then runs each configured Go target on its own Linux runner. `CGO_ENABLED=0` permits cross-compilation. The target matrix is read from `.goreleaser.yaml`, including its exclusions; simple releases select Linux amd64 only.

Each build uses GoReleaser OSS in snapshot mode with the selected release version and one target. Archive naming, bundled files, Go flags and release templates remain in the existing GoReleaser configurations. Every archive is accompanied by its source commit, target, version, SHA256 and the Go compiler selected in the backend module. The compiler must match the exact patch version in `backend/go.mod`; collection and verification reject mismatches. These manifests bind runner-reported build metadata, not a cryptographic build attestation. Full releases publish the manifests with the archives and checksums. The publishing job verifies the complete matrix before building images or publishing; no compilation is repeated there. No Pro license is needed.

Go caches are isolated by target and refreshed on each source commit, with fallback to the preceding target cache. Generated build configurations disable mutating pre-build hooks (including upstream `go mod tidy`) and add `-mod=readonly`; dependency updates must be reviewed before release. Matrix jobs upload uniquely named artifacts. The publishing job extracts only the regular Linux binary from each verified archive and restores its executable permission before constructing Docker contexts. QEMU remains limited to runtime-image instructions. DockerHub images are omitted when its credentials are absent; GHCR is always retained. Simple mode still publishes only the amd64 GHCR image and the simple release description.

All build jobs use the commit resolved by `prepare`, including a manual release's selected tag. Helper scripts come from the workflow revision and are passed as a run-local artifact, so older application tags do not need to contain the new scripts. The workflow serializes release runs to prevent simultaneous updates to moving image tags.

## Maintained fork policy

- Dispatch only: tag pushes do not start a release. Supply a reviewed full `expected_sha`; the selected ref must resolve to that exact commit. Review the workflow revision as well as the application revision because tooling comes from the former.
- Dry run is the default. Publication also requires repository variable `FORK_RELEASE_PUBLICATION_ENABLED=true` and the `fork-release` environment. Before setting that variable, configure required reviewers and protected source refs on the environment; the YAML cannot establish those server-side protections. Remote Actions remain disabled until separately authorized.
- The candidate commit must pass the `qualify` job: the unit suite with owned loopback PostgreSQL and Redis fixtures. The Go JSON report must explicitly contain passing hourly PG/HTTP, admin-key PG/Redis/HTTP and observation H1/H2 smoke tests; missing tests or Skip cannot qualify an older upstream tag. Any regression failure blocks publication.
- There is no automatic VERSION commit/push, production deployment, or scheduled upstream merge. Upstream intake remains an isolated reviewed merge under `FORK.md`.
- Local checks on2026-11-07: actionlint passed; seven platform-independent provenance/configuration regressions passed; actual collect/verify CLI smoke accepted matching Go1.27.3 metadata and rejected a wrong compiler. Configuration CLI smoke confirmed disabled hooks and readonly dependencies. The exact qualification parser accepted observed local test events and rejected a report missing admin-key integration. A full local helper run was not green: Windows lacks POSIX executable-mode semantics and its default `bash` resolves to unavailable WSL. No remote workflow, image build or publication was exercised.


## Validate without publication

From a branch containing this workflow:

```bash
gh workflow run release.yml --ref <branch> \
  -f tag=<reviewed-ref> -f expected_sha=<full-commit> -f dry_run=true -f simple_release=false
```

A dry run builds all selected archives and both runtime images, verifies artifact provenance and produces the final checksum file. It exports images locally as OCI archives instead of pushing them. It skips registry logins, GitHub Release publication, DockerHub description updates and Telegram notifications. Test the simple path separately with `simple_release=true`; VERSION synchronization has been removed for all modes.

Dry-run artifacts are available in the Actions run, including `release-dry-run-report`. Compare job start/end times, GoReleaser's build duration and cache restore results. Do not present an initial cold-cache run as a warmed-cache benchmark; publishing network time is not measured by dry runs.

Helper checks:

```bash
python -m pip install -r .github/release-tools/requirements-release.txt
python -m unittest discover -s .github/release-tools -p 'test_release_matrix.py'
bash -n .github/release-tools/release-images.sh
```
