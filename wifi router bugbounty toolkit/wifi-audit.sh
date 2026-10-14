#!/usr/bin/env bash
set -Eeuo pipefail

VERSION="1.0.0"
AUTHOR="Mr Sabaz Ali Khan"
OUTDIR="${OUTDIR:-./reports}"
TARGET="${1:-}"

mkdir -p "$OUTDIR"

banner() {
cat <<'EOF'
 __        ___ ______ _   _ _    _ _   _ ____  _   _ _____ _____ 
 \ \      / (_)  ____| \ | | |  | | \ | |  _ \| | | | ____|  _  \
  \ \ /\ / /| | |__  |  \| | |  | |  \| | |_) | | | |  _| | |_) |
   \ V  V / | |  __| | . ` | |  | | . ` |  _ <| | | | |___|  _ <
    \_/\_/  |_|_|    |_| \_|_|  |_|_|\_|_|_| \_\_____|_____|_| \_\

              WIFI ROUTER SECURITY AUDIT TOOLKIT
              Coded by Cyber Security Engineer
                    Mr Sabaz Ali Khan
              Authorized / Lab Use Only
EOF
}

usage() {
  echo "Usage: $0 <router-ip>"
  echo "Example: $0 192.168.1.1"
  echo
  echo "Optional: OUTDIR=./reports $0 192.168.1.1"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[!] Missing dependency: $1"
    return 1
  }
}

timestamp="$(date +%Y%m%d_%H%M%S)"
report="$OUTDIR/router_audit_${timestamp}.txt"

banner
[[ -n "$TARGET" ]] || { usage; exit 1; }

if ! [[ "$TARGET" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
  echo "[!] IPv4 address required."
  exit 1
fi

echo "Wi-Fi Router Security Audit" | tee "$report"
echo "Author: $AUTHOR" | tee -a "$report"
echo "Target: $TARGET" | tee -a "$report"
echo "Started: $(date -Is)" | tee -a "$report"
echo "Scope: authorized/self-owned router only" | tee -a "$report"
echo "==================================================" | tee -a "$report"

echo -e "\n[1] Reachability" | tee -a "$report"
if command -v ping >/dev/null 2>&1; then
  ping -c 2 -W 2 "$TARGET" 2>&1 | tee -a "$report" || true
fi

echo -e "\n[2] Safe TCP service enumeration" | tee -a "$report"
if command -v nmap >/dev/null 2>&1; then
  nmap -Pn --top-ports 100 --open -T2 "$TARGET" 2>&1 | tee -a "$report"
else
  echo "[!] nmap not installed; skipping service enumeration." | tee -a "$report"
fi

echo -e "\n[3] HTTP/HTTPS checks" | tee -a "$report"
for scheme in http https; do
  if command -v curl >/dev/null 2>&1; then
    echo "--- $scheme://$TARGET ---" | tee -a "$report"
    curl -k -sS -I --max-time 5 "$scheme://$TARGET/" 2>&1 | head -n 20 | tee -a "$report" || true
  fi
done

echo -e "\n[4] Common router security observations" | tee -a "$report"
cat <<'EOF' | tee -a "$report"
Review manually in the router's own administration interface:
  - WPA2-AES/WPA3 enabled; avoid WEP/WPA/TKIP.
  - Strong unique Wi-Fi and administrator passwords.
  - WPS disabled unless specifically required.
  - Remote administration disabled unless required and restricted.
  - UPnP disabled unless required.
  - Guest network isolated from the management/LAN network.
  - Firmware is current and obtained from the vendor.
  - Default administrator username/password changed.
  - Management interface is not unnecessarily exposed on WAN.
  - DNS, firewall, and DHCP settings are expected and documented.
EOF

echo -e "\n[5] Optional local Wi-Fi information" | tee -a "$report"
if command -v nmcli >/dev/null 2>&1; then
  nmcli -t -f IN-USE,SSID,BSSID,CHAN,SIGNAL,SECURITY dev wifi 2>/dev/null | tee -a "$report" || true
elif command -v iw >/dev/null 2>&1; then
  iw dev 2>/dev/null | tee -a "$report" || true
else
  echo "[!] nmcli/iw not available." | tee -a "$report"
fi

echo -e "\n[6] Findings checklist" | tee -a "$report"
cat <<'EOF' | tee -a "$report"
[ ] Outdated firmware / known CVE identified
[ ] Default credentials present
[ ] Weak Wi-Fi encryption
[ ] WPS unnecessarily enabled
[ ] WAN administration exposed
[ ] Unnecessary service exposed
[ ] Guest-to-LAN isolation failure
[ ] Sensitive information disclosed by management UI
[ ] Insecure HTTP-only management (if applicable)
[ ] Missing/weak session security in management UI
EOF

echo -e "\nCompleted: $(date -Is)" | tee -a "$report"
echo "[+] Report saved to: $report"
