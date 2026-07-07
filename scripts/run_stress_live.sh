#!/usr/bin/env bash
# Genera carga SOCKS5 contra un servidor ya en ejecución.
# NO levanta server ni echo_backend. Usar bin/client en otra terminal para el monitor.
#
# Requiere (en terminales aparte):
#   ./bin/server -p 1080 -m 8080 -u socksuser:sockspass -a admin:admin
#   ./bin/echo_backend -p 9999
#   ./bin/client -p 8080   → AUTH, STATS, CONNECTIONS
#
# Uso:
#   ./scripts/run_stress_live.sh -n 500
#   ./scripts/run_stress_live.sh -n 200 -k 60
#   ./scripts/run_stress_live.sh -H 127.0.0.1 -n 100 -k 0

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SOCKS_USER="${SOCKS_USER:-socksuser}"
SOCKS_PASS="${SOCKS_PASS:-sockspass}"
PROXY_HOST="${PROXY_HOST:-127.0.0.1}"
SOCKS_PORT="${SOCKS_PORT:-1080}"
ECHO_PORT="${ECHO_PORT:-9999}"
MONITOR_PORT="${MONITOR_PORT:-8080}"

make -s stress

DEFAULT_ARGS=(
    -M live
    -H "${PROXY_HOST}"
    -p "${SOCKS_PORT}"
    -u "${SOCKS_USER}:${SOCKS_PASS}"
    -d "${PROXY_HOST}:${ECHO_PORT}"
    -m "${MONITOR_PORT}"
    -n 100
    -k 0
)

if [ "$#" -eq 0 ]; then
    echo "No extra args: using -n 100 -k 0 (override with -n, -k, etc.)"
fi

exec ./bin/stress_client "${DEFAULT_ARGS[@]}" "$@"
