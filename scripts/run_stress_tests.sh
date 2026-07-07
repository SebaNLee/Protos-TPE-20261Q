#!/usr/bin/env bash
# Ejecuta la suite de pruebas de estrés dentro del contenedor Docker.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SOCKS_USER="${SOCKS_USER:-socksuser}"
SOCKS_PASS="${SOCKS_PASS:-sockspass}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin}"
SOCKS_PORT="${SOCKS_PORT:-1080}"
MONITOR_PORT="${MONITOR_PORT:-8080}"
ECHO_PORT="${ECHO_PORT:-9999}"

COMMON_ARGS=(
    -u "${SOCKS_USER}:${SOCKS_PASS}"
    -d "127.0.0.1:${ECHO_PORT}"
    -m "${MONITOR_PORT}"
    -A "${ADMIN_USER}:${ADMIN_PASS}"
    -q
)

mkdir -p /tmp/stress_results

echo "==> Building binaries"
make stress server

echo "==> Starting echo backend on port ${ECHO_PORT}"
./bin/echo_backend -p "${ECHO_PORT}" &
ECHO_PID=$!

echo "==> Starting SOCKS server"
./bin/server -p "${SOCKS_PORT}" -m "${MONITOR_PORT}" \
    -u "${SOCKS_USER}:${SOCKS_PASS}" -a "${ADMIN_USER}:${ADMIN_PASS}" &
SERVER_PID=$!

cleanup() {
    # El servidor hace graceful shutdown (espera drenar sesiones) y echo_backend
    # puede quedar bloqueado en accept(); no esperar indefinidamente.
    kill -TERM "${SERVER_PID}" 2>/dev/null || true
    kill -TERM "${ECHO_PID}" 2>/dev/null || true

    local waited=0
    while [ "${waited}" -lt 3 ]; do
        if ! kill -0 "${SERVER_PID}" 2>/dev/null && ! kill -0 "${ECHO_PID}" 2>/dev/null; then
            break
        fi
        sleep 1
        waited=$((waited + 1))
    done

    kill -9 "${SERVER_PID}" 2>/dev/null || true
    kill -9 "${ECHO_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
    wait "${ECHO_PID}" 2>/dev/null || true
}
trap cleanup EXIT

sleep 1

RESULTS="/tmp/stress_results/run.txt"
: > "${RESULTS}"

run_case() {
    local label="$1"
    shift
    echo "" | tee -a "${RESULTS}"
    echo "===== ${label} =====" | tee -a "${RESULTS}"
    ./bin/stress_client "${COMMON_ARGS[@]}" "$@" 2>&1 | tee -a "${RESULTS}"
}

echo "==> Connection scalability (idle tunnels, 1s hold)"
for n in 10 50 100 200 300 400 500 600; do
    run_case "connections n=${n}" -M connections -n "${n}" -k 1
done

echo "==> Throughput degradation (64 KiB per client)"
for n in 1 10 25 50 100 200 300 400 500; do
    run_case "throughput n=${n}" -M throughput -n "${n}" -b 65536
done

echo "" | tee -a "${RESULTS}"
echo "Results saved to ${RESULTS}" | tee -a "${RESULTS}"
