#!/bin/sh
# Versioned trusted controller entrypoint, not a script from the GitHub artifact.
set -eu
controller_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
exec python3 -B "$controller_dir/bamboo_cd.py" "$@"
