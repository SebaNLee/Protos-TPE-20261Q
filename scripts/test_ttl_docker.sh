#!/usr/bin/env bash
# Prueba manual del idle TTL vía Docker.
set -euo pipefail

cd "$(dirname "$0")/.."

MONITOR_PORT=8080
SOCKS_PORT=1080
ECHO_PORT=9999
SERVER_PID=""
ECHO_PID=""

cleanup() {
    if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
    fi
    if [[ -n "${ECHO_PID}" ]] && kill -0 "${ECHO_PID}" 2>/dev/null; then
        kill "${ECHO_PID}" 2>/dev/null || true
        wait "${ECHO_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

monitor_session() {
    { printf '%s\n' "$@"; sleep 0.3; } | nc -w 2 127.0.0.1 "${MONITOR_PORT}"
}

wait_port() {
    local port="$1"
    for _ in $(seq 1 30); do
        if nc -z 127.0.0.1 "${port}" 2>/dev/null; then
            return 0
        fi
        sleep 0.2
    done
    echo "timeout waiting for port ${port}" >&2
    return 1
}

echo "==> Building..."
make server client stress >/dev/null

echo "==> Starting echo backend on ${ECHO_PORT}..."
./bin/echo_backend -p "${ECHO_PORT}" >/tmp/echo_backend.log 2>&1 &
ECHO_PID=$!
wait_port "${ECHO_PORT}"

echo "==> Starting SOCKS server..."
./bin/server -p "${SOCKS_PORT}" -m "${MONITOR_PORT}" \
    -u socksuser:sockspass -a admin:admin >/tmp/server.log 2>&1 &
SERVER_PID=$!
wait_port "${SOCKS_PORT}"
wait_port "${MONITOR_PORT}"

assert_monitor_ok() {
    local out="$1"
    if echo "${out}" | grep -q '\-ERR'; then
        echo "FAIL: monitor error in: ${out}" >&2
        exit 1
    fi
    if ! echo "${out}" | grep -q '\+OK'; then
        echo "FAIL: expected +OK in: ${out}" >&2
        exit 1
    fi
}

echo "==> CONFIG timeout 5"
AUTH_OUT=$(monitor_session "AUTH admin admin")
echo "${AUTH_OUT}"
assert_monitor_ok "${AUTH_OUT}"

CONFIG_OUT=$(monitor_session "AUTH admin admin" "CONFIG timeout 5")
echo "${CONFIG_OUT}"
assert_monitor_ok "${CONFIG_OUT}"

echo "==> Opening idle RELAY tunnel (hold 12s, expect TTL ~5-6s)..."
set +e
./bin/stress_client -H 127.0.0.1 -p "${SOCKS_PORT}" \
    -u socksuser:sockspass -d "127.0.0.1:${ECHO_PORT}" \
    -n 1 -M live -k 12 >/tmp/stress.log 2>&1
STRESS_RC=$?
set -e
echo "stress_client exit code: ${STRESS_RC}"

sleep 1

echo "==> ACCESS_LOG"
LOG_OUT=$(monitor_session "AUTH admin admin" "ACCESS_LOG socksuser")
echo "${LOG_OUT}"

if echo "${LOG_OUT}" | grep -q "TTL_EXPIRED"; then
    echo "PASS: ACCESS_LOG contains TTL_EXPIRED"
else
    echo "FAIL: ACCESS_LOG missing TTL_EXPIRED" >&2
    echo "--- server log ---" >&2
    tail -50 /tmp/server.log >&2 || true
    exit 1
fi

echo "==> CONFIG timeout 0 (disable TTL)"
monitor_session "AUTH admin admin" "CONFIG timeout 0" >/dev/null

echo "==> Idle tunnel with TTL disabled should stay up 7s..."
./bin/stress_client -H 127.0.0.1 -p "${SOCKS_PORT}" \
    -u socksuser:sockspass -d "127.0.0.1:${ECHO_PORT}" \
    -n 1 -M live -k 7 >/tmp/stress2.log 2>&1 &
STRESS2_PID=$!

sleep 3
CONN_MID=$(monitor_session "AUTH admin admin" "CONNECTIONS")
echo "${CONN_MID}"
echo "${CONN_MID}" | grep -q "socksuser"

wait "${STRESS2_PID}"

echo "PASS: TTL disabled kept connection alive mid-hold"
echo "All Docker TTL tests passed."
