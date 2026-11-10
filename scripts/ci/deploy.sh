#!/bin/sh
# This file ships in release/tools; deployment jobs do not check out source.
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: deploy.sh gateway3|sub2api3" >&2
    exit 2
fi

tools_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
bundle_dir=$(dirname "$tools_dir")
exec python3 "$tools_dir/deploy_release.py" --bundle "$bundle_dir" --target "$1"
