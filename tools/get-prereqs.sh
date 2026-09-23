#!/usr/bin/env bash
# tools/get-prereqs.sh — prerequisite bootstrap / checker.
# Usage:
#   tools/get-prereqs.sh --check-only   (default, read-only, CI-safe, no TX)
#   tools/get-prereqs.sh --install      (requires root; installs pinned stable pkgs)
#   tools/get-prereqs.sh --output FILE  (write prereqs.json elsewhere)
set -euo pipefail

MODE="check-only"
OUTPUT="prereqs.json"
PIN_SCAPY="2.6.1"
PIN_PYTEST="8.*"
PIN_TCPDUMP="4.99"
PIN_THC="3.8"
PIN_SI6="2."

usage() {
  cat <<EOF
usage: get-prereqs.sh [--check-only] [--install] [--output FILE]
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --check-only) MODE="check-only"; shift ;;
    --install) MODE="install"; shift ;;
    --output) OUTPUT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

have() { command -v "$1" >/dev/null 2>&1; }

os_id="unknown"; os_ver="unknown"
if [ -f /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  os_id="${ID:-unknown}"; os_ver="${VERSION_ID:-unknown}"
fi
kernel="$(uname -r 2>/dev/null || echo unknown)"
pyver="$(python3 --version 2>&1 || echo 'python3 missing')"
uvver="$(uv --version 2>&1 || echo 'uv missing')"
scapyver="$(python3 -c 'import scapy; print(scapy.__version__)' 2>&1 || echo MISSING)"
pytestver="$(python3 -c 'import pytest; print(pytest.__version__)' 2>&1 || echo MISSING)"
tcpdumpver="$(tcpdump --version 2>&1 | head -1 || echo MISSING)"
ipver="$(ip -V 2>&1 || echo MISSING)"
thcver="MISSING"; si6ver="MISSING"
for b in ex6 dst6 frag6 na6 ns6 rs6 ra6; do
  if have "$b"; then thcver="$("$b" 2>&1 | head -1 || echo present)"; break; fi
done
if have thc-ipv6-attack 2>/dev/null; then thcver="$(thc-ipv6-attack 2>&1 | head -1 || echo present)"; fi
for b in na6 ns6 ra6 ns6 rs6 scan6; do
  if have "$b"; then si6ver="$("$b" --version 2>&1 | head -1 || "$b" 2>&1 | head -1)"; break; fi
done
# thc-ipv6 and SI6 share binary names on some installs; record honestly.
caps="$(capsh --print 2>/dev/null | grep -o 'cap_net_raw' || echo no-cap_net_raw)"
ifaces="$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | paste -sd',' - || echo unknown)"

install_pkgs() {
  if [ "$(id -u)" -ne 0 ]; then echo "ERROR: --install requires root" >&2; exit 1; fi
  if have apt-get; then
    apt-get update
    apt-get install -y --no-install-recommends \
      python3 tcpdump iproute2 libpcap0.8 \
      libssl-dev libpcap-dev pkg-config git make gcc capsh 2>/dev/null || \
    apt-get install -y --no-install-recommends \
      python3 tcpdump iproute2 git make gcc
    # thc-ipv6 / SI6: source build pinned tags when apt lacks them
    if ! have ex6; then
      rm -rf /tmp/thc-ipv6 && git clone --depth 1 --branch "v${PIN_THC}" \
        https://github.com/vanhauser-thc/thc-ipv6.git /tmp/thc-ipv6 2>/dev/null \
        || git clone --depth 1 https://github.com/vanhauser-thc/thc-ipv6.git /tmp/thc-ipv6
      (cd /tmp/thc-ipv6 && make -j"$(nproc)" && make install) || echo "WARN: thc-ipv6 build failed" >&2
    fi
    if ! have scan6; then
      rm -rf /tmp/ipv6toolkit && git clone --depth 1 \
        https://github.com/fgont/ipv6toolkit.git /tmp/ipv6toolkit 2>/dev/null || true
      (cd /tmp/ipv6toolkit 2>/dev/null && ./configure 2>/dev/null && make -j"$(nproc)" && make install) \
        || echo "WARN: SI6 toolkit build failed (optional)" >&2
    fi
    uv sync --group dev 2>/dev/null || uv pip install --system "scapy==${PIN_SCAPY}" "pytest>=8.0" \
      || pip install --break-system-packages "scapy==${PIN_SCAPY}" "pytest>=8.0" \
      || echo "WARN: python pkg install failed; run 'uv sync --group dev' manually" >&2
  elif have dnf; then
    dnf install -y python3 tcpdump iproute libpcap git make gcc
    uv sync --group dev 2>/dev/null || uv pip install --system "scapy==${PIN_SCAPY}" "pytest>=8.0"
  else
    echo "ERROR: no supported package manager (apt/dnf). Install manually." >&2; exit 1
  fi
}

if [ "$MODE" = "install" ]; then install_pkgs; fi

# Re-probe versions after optional install
scapyver="$(python3 -c 'import scapy; print(scapy.__version__)' 2>&1 || echo MISSING)"
pytestver="$(python3 -c 'import pytest; print(pytest.__version__)' 2>&1 || echo MISSING)"

ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat > "$OUTPUT" <<EOF
{
  "timestamp": "$ts",
  "os": "$os_id $os_ver",
  "kernel": "$kernel",
  "python": "$pyver",
  "uv": "$uvver",
  "scapy": "$scapyver",
  "pytest": "$pytestver",
  "tcpdump": "$tcpdumpver",
  "iproute2": "$ipver",
  "thc_ipv6": "$thcver",
  "si6_toolkit": "$si6ver",
  "capabilities": "$caps",
  "interfaces": "$ifaces",
  "pins": {"scapy": "$PIN_SCAPY", "tcpdump": "$PIN_TCPDUMP", "thc_ipv6": "$PIN_THC", "si6": "$PIN_SI6"}
}
EOF

echo "Wrote $OUTPUT"
cat "$OUTPUT"

# Check-only exit status: ERROR if hard requirements missing.
missing=0
[ "$scapyver" = "MISSING" ] && { echo "MISSING: scapy ($PIN_SCAPY)" >&2; missing=1; }
[ "$tcpdumpver" = "MISSING" ] && { echo "MISSING: tcpdump" >&2; missing=1; }
have ip || { echo "MISSING: iproute2 (ip)" >&2; missing=1; }
if [ "$missing" -ne 0 ]; then
  echo "RESULT: PREREQS INCOMPLETE (hard reqs missing)" >&2; exit 1
fi
if [ "$thcver" = "MISSING" ] || [ "$si6ver" = "MISSING" ]; then
  echo "RESULT: OK (core tools ready; thc-ipv6/SI6 are optional extras)." >&2
else
  echo "RESULT: OK" >&2
fi
