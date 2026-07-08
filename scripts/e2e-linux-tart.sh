#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_VM="${LIANYAOHU_TART_SOURCE:-ghcr.io/cirruslabs/ubuntu:latest}"
VM_NAME="${LIANYAOHU_TART_VM:-lyh-linux-e2e-$(date +%s)}"
KEEP_VM="${LIANYAOHU_KEEP_TART_VM:-0}"
TARGET="${LIANYAOHU_LINUX_TARGET:-aarch64-unknown-linux-gnu.2.31}"
TARGET_TRIPLE="${TARGET%%.*}"
LINUX_BIN="$ROOT/target/${TARGET_TRIPLE}/release/lianyaohu"
HOST_BIND="${LIANYAOHU_E2E_HOST_BIND:-}"
HOST_PORT="${LIANYAOHU_E2E_HOST_PORT:-18080}"
RUN_LOG="${TMPDIR:-/tmp}/lianyaohu-${VM_NAME}.log"
HTTP_LOG="${TMPDIR:-/tmp}/lianyaohu-http-${VM_NAME}.log"
CREATED_VM=0
TART_PID=""
HTTP_PID=""

cleanup() {
  set +e
  if [[ -n "$TART_PID" ]]; then
    tart exec "$VM_NAME" bash -lc '
      sudo ip route del 0.0.0.0/1 dev tun0 2>/dev/null || true
      sudo ip route del 128.0.0.0/1 dev tun0 2>/dev/null || true
      sudo ip link del tun0 2>/dev/null || true
      if [[ -x /mnt/lyh/scripts/uninstall-helper.sh ]]; then
        sudo /mnt/lyh/scripts/uninstall-helper.sh || true
      fi
    ' >/dev/null 2>&1 || true
    tart stop "$VM_NAME" >/dev/null 2>&1 || true
  fi
  if [[ "$CREATED_VM" == "1" && "$KEEP_VM" != "1" ]]; then
    tart delete "$VM_NAME" >/dev/null 2>&1 || true
  fi
  if [[ -n "$HTTP_PID" ]]; then
    kill "$HTTP_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if ! command -v tart >/dev/null 2>&1; then
  echo "tart is required" >&2
  exit 1
fi

if [[ "${LIANYAOHU_E2E_SKIP_BUILD:-0}" != "1" ]]; then
  if ! command -v cargo-zigbuild >/dev/null 2>&1 && ! cargo zigbuild --version >/dev/null 2>&1; then
    echo "cargo-zigbuild is required for the Linux Tart e2e build" >&2
    exit 1
  fi
  cargo zigbuild --release --target "$TARGET" -p lianyaohu-app
fi

if [[ ! -x "$LINUX_BIN" ]]; then
  echo "missing Linux binary: $LINUX_BIN" >&2
  exit 1
fi

if ! tart list | awk 'NR > 1 {print $2}' | grep -qx "$VM_NAME"; then
  tart clone "$SOURCE_VM" "$VM_NAME"
  CREATED_VM=1
fi

tart run --no-graphics --dir="${ROOT}:tag=lyh" "$VM_NAME" >"$RUN_LOG" 2>&1 &
TART_PID="$!"
tart ip "$VM_NAME" --wait 120 >/dev/null

guest() {
  tart exec "$VM_NAME" bash -lc "$1"
}

for _ in {1..60}; do
  if guest 'true' >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
guest 'true' >/dev/null

if [[ -z "$HOST_BIND" ]]; then
  HOST_BIND="$(guest "ip route show default | awk '/default/ {print \$3; exit}'")"
fi

python3 -m http.server "$HOST_PORT" --bind "$HOST_BIND" --directory "$ROOT" >"$HTTP_LOG" 2>&1 &
HTTP_PID="$!"
sleep 1
if ! kill -0 "$HTTP_PID" >/dev/null 2>&1; then
  echo "failed to start host HTTP server on ${HOST_BIND}:${HOST_PORT}" >&2
  cat "$HTTP_LOG" >&2
  exit 1
fi

guest "
  set -euxo pipefail
  if ! command -v curl >/dev/null 2>&1 || ! command -v iptables >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
    sudo apt-get update
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y curl iproute2 iptables python3
  fi
  sudo mkdir -p /mnt/lyh
  if ! mountpoint -q /mnt/lyh; then
    sudo mount -t virtiofs lyh /mnt/lyh
  fi
  sudo install -m755 /mnt/lyh/target/${TARGET_TRIPLE}/release/lianyaohu /usr/local/bin/lianyaohu
  sudo env LIANYAOHU_HELPER_BINARY=/usr/local/bin/lianyaohu /mnt/lyh/scripts/install-helper.sh
  /usr/local/bin/lianyaohu --helper-status | grep -qx 'not installed'
  sudo ip link del tun0 2>/dev/null || true
  sudo ip tuntap add dev tun0 mode tun user \"\$(id -u)\"
  sudo ip addr add 10.9.0.2 peer 10.9.0.1 dev tun0
  sudo ip link set tun0 up
  sudo ip route replace 0.0.0.0/1 dev tun0
  sudo ip route replace 128.0.0.0/1 dev tun0
  ip route get 1.1.1.1 | grep -q ' dev tun0 '
  curl -fsS --max-time 5 http://${HOST_BIND}:${HOST_PORT}/README.md >/tmp/lyh-host-probe
  sudo rm -rf /var/lyh-outside-sandbox
  sudo mkdir -m 0777 /var/lyh-outside-sandbox
  echo outside | sudo tee /var/lyh-outside-sandbox/secret >/dev/null
  sudo chmod 0644 /var/lyh-outside-sandbox/secret
"

guest "
  rm -f /tmp/lyh-agent-check.sh /tmp/lyh-bind-* /tmp/lyh-child-* /tmp/lyh-fs-* /tmp/lyh-lan-* /tmp/lyh-run.log /tmp/lyh-exit
  sudo rm -f /var/lyh-outside-sandbox/write-test
  cat >/tmp/lyh-agent-check.sh <<'EOF'
#!/bin/sh
set -u
id -g > /tmp/lyh-child-gid
env | sort > /tmp/lyh-child-env
touch /tmp/lyh-child-started
if touch /tmp/lyh-fs-allowed 2>/tmp/lyh-fs-allowed-error; then
  echo fs-write-allowed > /tmp/lyh-fs-allowed-result
else
  echo fs-write-allowed-failed > /tmp/lyh-fs-allowed-result
fi
if cat /var/lyh-outside-sandbox/secret >/tmp/lyh-fs-read-open 2>/tmp/lyh-fs-read-error; then
  echo fs-read-open > /tmp/lyh-fs-read-result
else
  echo fs-read-blocked > /tmp/lyh-fs-read-result
fi
if touch /var/lyh-outside-sandbox/write-test 2>/tmp/lyh-fs-write-error; then
  echo fs-write-open > /tmp/lyh-fs-write-result
else
  echo fs-write-blocked > /tmp/lyh-fs-write-result
fi
if python3 -c 'import socket; s=socket.socket(); s.bind((\"127.0.0.1\", 0)); s.listen(1)' 2>/tmp/lyh-bind-error; then
  echo bind-open > /tmp/lyh-bind-result
else
  echo bind-blocked > /tmp/lyh-bind-result
fi
if timeout 4 curl -fsS --max-time 2 http://${HOST_BIND}:${HOST_PORT}/README.md >/tmp/lyh-lan-response 2>/tmp/lyh-lan-error; then
  echo connected > /tmp/lyh-lan-result
else
  echo blocked > /tmp/lyh-lan-result
fi
sleep 6
EOF
  chmod +x /tmp/lyh-agent-check.sh
  (
    /usr/local/bin/lianyaohu --vpn tun0 --cwd \"\$HOME\" -- /tmp/lyh-agent-check.sh
    echo \$? >/tmp/lyh-exit
  ) >/tmp/lyh-run.log 2>&1 &
"

for _ in {1..30}; do
  if guest 'test -f /tmp/lyh-child-started' >/dev/null 2>&1; then
    break
  fi
  if guest 'test -f /tmp/lyh-exit' >/dev/null 2>&1; then
    guest 'cat /tmp/lyh-run.log >&2'
    exit 1
  fi
  sleep 1
done
guest 'test -f /tmp/lyh-child-started'

guest "
  /usr/local/bin/lianyaohu --helper-status | grep -qx installed
  sudo iptables -S OUTPUT | grep -q -- '--gid-owner 2000000'
  sudo iptables -S LYH-\$(id -u) | grep -q -- '-o tun0 -j RETURN'
"

for _ in {1..30}; do
  if guest 'test -f /tmp/lyh-exit' >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

guest "
  set -euxo pipefail
  test \"\$(cat /tmp/lyh-exit)\" = 0
  grep -qx '2000000' /tmp/lyh-child-gid
  grep -qx 'TZ=UTC' /tmp/lyh-child-env
  grep -qx 'LIANYAOHU_SANDBOX=1' /tmp/lyh-child-env
  grep -qx fs-write-allowed /tmp/lyh-fs-allowed-result
  grep -qx fs-read-blocked /tmp/lyh-fs-read-result
  grep -qx fs-write-blocked /tmp/lyh-fs-write-result
  grep -qx bind-blocked /tmp/lyh-bind-result
  test -f /tmp/lyh-fs-allowed
  test ! -e /var/lyh-outside-sandbox/write-test
  grep -qx blocked /tmp/lyh-lan-result
  /usr/local/bin/lianyaohu --helper-status | grep -qx 'not installed'
  ! sudo iptables -S OUTPUT | grep -q 'LYH-'\$(id -u)
"

echo "Linux Tart e2e passed on ${VM_NAME}"
