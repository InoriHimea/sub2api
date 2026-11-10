#!/bin/sh
# GitHub Actions invokes this file with the qualify or build phase.
set -eu

repo_dir=$(CDPATH= cd -P "$(dirname "$0")/../.." && pwd)
cd "$repo_dir"

case "${1-}" in
    qualify)
        python3 scripts/ci/preflight_release.py
        exec python3 scripts/ci/qualify_release.py --output release/qualification.json
        ;;
    build)
        python3 scripts/ci/build_release.py --output release
        tar -czf release-bundle.tar.gz release
        sha256sum release-bundle.tar.gz
        ;;
    *)
        echo "usage: release.sh qualify|build" >&2
        exit 2
        ;;
esac
