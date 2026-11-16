#!/bin/sh
# Startup-only wrapper; retain the service environment and vendor option assembly.
set -eu
if [ "$#" -eq 0 ]; then
    echo 'Missing Bamboo startup command' >&2
    exit 78
fi
CATALINA_OPTS="${CATALINA_OPTS:+${CATALINA_OPTS} }-javaagent:/opt/bamboo-querysafe/querysafe-juli.jar"
export CATALINA_OPTS
exec "$@"
