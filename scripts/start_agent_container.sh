#!/bin/sh

set -eu

checker_data_dir="${AIG_API_CHECKER_DATA_DIR:-/api-checker-data}"
case "$checker_data_dir" in
    /api-checker-data|/api-checker-data/*) ;;
    *)
        echo "[agent-container] AIG_API_CHECKER_DATA_DIR must be /api-checker-data or a child path" >&2
        exit 1
        ;;
esac

mkdir -p "$checker_data_dir"
chown -R agent:agent /api-checker-data

exec gosu agent:agent /usr/local/bin/python /app/start_agent_container.py
