#!/usr/bin/env bash
# =====================================================================
#  Persistence Audit Tool  (Linux, read-only / defensive)
#  coded by Mr Sabaz Ali Khan  -  Cyber Security Engineer
#
#  Audits common persistence mechanisms and flags suspicious entries.
#  Makes NO changes to the system. Run as root for full coverage.
#
#  Usage: sudo ./persistence_audit.sh [-d DAYS] [-o report.txt] [-q] [-h]
# =====================================================================a

set -u
export LC_ALL=C

RECENT_DAYS=7
OUT_FILE=""
QUIET=0

# ---------- colors ----------
if [ -t 1 ]; then
  R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[34m'; C=$'\e[36m'; M=$'\e[35m'; W=$'\e[1m'; N=$'\e[0m'
else
  R=""; G=""; Y=""; B=""; C=""; M=""; W=""; N=""
fi

banner() {
  printf '%s' "$C"
  cat <<'EOF'
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠿⠋⠀⠀⠙⠛⢿⣿⣿⣿⣿⣷⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣾⡿⠃⠀⠀⠀⠀⣀⡀⠀⠙⣿⣿⣿⣿⣿⣿⣿⣷⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠋⢀⣠⣶⣿⠟⠋⠀⠀⢀⣠⣴⠞⠉⠁⠀⠀⠈⢻⣿⣿⣿⣝⡿⣿⣿⣿⣷⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠏⣠⣴⣿⠟⣋⣤⣶⣿⣿⡿⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣿⣿⣿⣷⣬⡙⠻⢿⣿⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⢃⣼⣿⣿⣿⣿⣿⣿⣟⣋⣁⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣶⣄⡉⠻⣿⣿⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣧⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣛⠉⠙⠛⠳⠶⣤⠀⠀⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣦⣈⠙⢿⣿⣶⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⡝⢿⣿⣿⣿⣿⣿⣷⣄⠙⠻⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⣿⣿⡟⠉⢉⠉⠉⠻⣿⣿⣿⣿⣿⣿⠻⣶⡀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣎⠻⣿⣿⣿⣿⣿⣿⣷⣄⠈⢿⣿⣦⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⡿⠋⣿⣿⣿⣿⣷⠶⠋⠀⠀⢀⡈⢻⣿⣿⣿⣿⣦⠈⠛⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⣿⣦⠘⢿⣿⣿⣿⣿⣿⣿⣧⡀⠙⢿⣧⡀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣷⣾⡿⠛⠉⠁⠀⠀⠀⠀⠀⢀⣷⡀⣿⣿⣿⣿⢿⣷⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣧⡀⢻⣿⣿⣿⣿⣿⣿⣿⣄⠀⢻⣿⣆⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⠁⣿⣿⣿⣿⠀⢻⡆⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣿⣿⣷⠀⠹⣿⣿⣿⣿⣿⣿⣿⣧⡀⠹⣿⣆⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⣿⠏⢠⣿⣿⣿⣿⠀⠈⠃⠀⠀⠀⠀⢀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠹⣿⣿⣿⣿⣿⣿⣿⣧⠀⠙⢿⡀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⠃⢠⣿⣿⣿⡏⡞⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⠀⢹⣿⣿⣿⣿⣿⣿⣿⣧⠀⠈⣧⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⣿⣿⠇⣠⣿⣿⣿⠟⠀⠁⠀⠀⠀⣀⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⢿⣿⣿⣿⣿⣿⣿⣿⣧⡀⢹⣇
⠀⠀⠀⠀⠀⢀⣤⠖⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⡏⢰⣿⣿⣿⣿⣶⣶⣶⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠛
⠀⠀⠀⠀⢠⡾⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⠁⢸⣿⣿⣿⠛⠿⣿⣿⣿⣿⣛⣛⣛⠋⠉⠉⠉⠉⠛⠛⠛⠿⣿⣿⣿⣿⣿⣿⣿⡇⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀
⠀⠀⠀⢰⣿⠃⠀⠀⢀⣠⣤⣤⠴⠶⠂⠀⠀⠀⢹⣿⣿⣿⠀⢸⣿⣿⣿⣷⣄⡀⠉⠙⠻⠿⢿⣿⣿⣿⣶⣦⣄⡀⠀⠀⠀⠀⠉⠻⢿⣿⣿⣿⡇⠀⢸⣿⣿⣿⣿⣷⢹⣿⣿⣇⠀
⠀⠀⢠⣿⡇⠀⢀⣴⣿⠟⠋⠁⠀⠀⠀⠀⠀⠀⠈⢻⣿⣿⡆⠸⣿⣿⣿⣿⣿⣿⣷⣶⣤⣤⣀⡈⠙⠛⠿⣿⣿⣿⣷⣤⣀⠀⠀⠀⠀⠹⣿⣿⡇⠀⠘⣿⣿⣿⣿⣿⠈⣿⣿⣿⠀
⠀⠀⣾⣿⠀⢰⣿⣿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣿⣿⡆⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⡀⠀⠉⠻⣿⣿⣿⣷⣄⠀⠀⠀⠈⢿⡇⠀⠀⣿⣿⣿⣿⣿⠀⢹⣿⣿⡇
⠀⠀⣿⣿⠀⢸⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠻⣦⣀⠙⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣄⠀⠈⠻⣿⣿⣿⣷⡀⠀⠀⠘⡇⠀⢀⣿⣿⣿⣿⣿⠀⢸⣿⣿⠇
⣀⠀⣿⣿⡆⢸⡟⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⡶⠖⣂⣀⣀⣀⡀⠀⠉⠁⠀⠀⠈⠻⢿⣿⣿⣿⣿⣿⣿⢿⣿⣿⣷⡀⠀⠈⢿⣿⣿⣷⡀⠀⠀⠃⠀⢸⣿⣿⣿⣿⣿⠀⢸⣿⣿⠀
⣿⠀⢻⣿⣇⣸⡇⠀⠀⠀⠀⠀⠀⢀⣴⣟⣡⣴⠿⠟⠛⠉⠉⠙⠛⠲⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⣧⠻⣿⣿⣿⡄⠀⠈⢻⣿⣿⣷⠀⠀⠀⠀⣼⣿⣿⣿⣿⡟⠀⢸⣿⡿⠀
⣿⡄⠸⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⣾⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣿⣿⣿⡇⠸⣿⣿⣿⠀⠀⠈⣿⣿⣿⠀⠀⠀⢰⣿⣿⣿⣿⣿⡇⠀⣿⣿⠇⠀
⢹⣧⠀⢻⣿⣿⣿⡆⠀⠀⠀⠀⠀⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⠀⣿⣿⣿⡆⠀⠀⢹⣿⣿⠃⠀⢀⣿⣿⣿⣿⣿⣿⠁⢰⣿⣿⠀⠀
⠘⣿⡄⠈⣿⣿⣿⣿⡀⠀⠀⠀⠀⢿⣿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣶⣶⣦⣄⠀⠀⠀⠀⣿⣿⣿⡟⠀⢸⣿⣿⠃⠀⠀⢸⣿⣿⠀⠀⣸⣿⣿⣿⣿⣿⠃⢀⣾⣿⡏⠀⠀
⠀⢹⣿⣄⠘⣿⣿⣿⣧⠀⠀⠀⠀⠘⣿⣿⣿⡶⠆⠀⠀⠀⠀⠀⠀⣴⣿⣿⠏⠁⠀⠀⠀⠀⠀⢠⣿⣿⣿⠃⠀⣿⣿⡿⠀⠀⠀⣾⣿⡏⠀⣰⣿⣿⣿⣿⣿⠏⠀⣸⣿⠟⠀⠀⠀
⠀⠀⢿⣿⣦⠸⣿⣿⣿⣆⠀⠀⠀⠀⠘⢿⡏⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⠀⠀⠀⠀⠀⠀⣠⣿⣿⣿⠋⠀⣸⣿⣿⠃⠀⠀⣼⣿⡿⠀⣰⣿⣿⣿⣿⣿⠋⠀⣰⣿⠏⠀⠀⠀⠀
⠀⠀⠈⢻⣿⣷⣿⣿⣿⣿⣦⡀⠀⠀⠀⠈⢻⣄⠀⠀⠀⠀⠀⠀⠀⠻⣿⣿⣷⣤⣄⣀⣤⣴⣿⣿⠟⠁⠀⣴⣿⡿⠁⠀⠀⣼⣿⡿⠃⣼⣿⣿⣿⣿⡿⠋⠀⣰⣿⠏⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠈⢿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀⠙⢷⣄⠀⠀⠀⠀⠀⠀⠉⠛⠿⢿⣿⣿⣿⠿⠛⠁⠀⣠⣾⣿⠟⠁⠀⣠⣾⣿⡿⢉⣾⣿⣿⣿⣿⠟⠁⠀⣼⣿⠋⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠈⠛⢿⣿⣿⣿⣿⣿⣷⣄⡀⠀⠀⠀⠈⠳⢦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⣿⠿⠛⠁⠀⣠⣶⣿⣿⢋⣴⣿⣿⣿⣿⡿⠋⠀⣤⣾⠟⠁⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⣿⣿⣿⣿⣿⣿⣶⣤⣀⠀⠀⠀⠀⠉⠙⠛⠲⠶⠶⠶⠶⠾⠿⠛⠛⠉⠀⢀⣤⣶⣿⣿⣿⢟⣵⣿⣿⣿⣿⡿⠋⠀⢀⣼⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠙⢦⣀⠙⠻⢿⣿⣿⣿⣿⣿⣿⣶⣦⣤⣄⣀⣀⠀⠀⠀⠀⣀⣀⣀⣠⣤⣶⣾⣿⣿⣿⣿⣿⣷⣿⣿⣿⣿⡿⠋⠀⠀⣠⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⢶⣦⣤⣝⠛⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀⣀⡔⠋⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
EOF
  printf '%s\n' "$N"
  printf '%s  ╔══════════════════════════════════════════════════════════╗%s\n' "$R" "$N"
  printf '%s  ║%s  %sPERSISTENCE AUDIT TOOL%s  -  Linux Persistence Hunter         %s║%s\n' "$R" "$N" "$W" "$N" "$R" "$N"
  printf '%s  ║%s  %scoded by Mr Sabaz Ali Khan%s  |  Cyber Security Engineer     %s║%s\n' "$R" "$N" "$Y" "$N" "$R" "$N"
  printf '%s  ╚══════════════════════════════════════════════════════════╝%s\n\n' "$R" "$N"
}

usage() {
  cat <<EOF
Usage: $0 [options]
  -d DAYS    Flag files modified within the last DAYS days (default: 7)
  -o FILE    Save a plain-text report to FILE
  -q         Quiet: hide INFO lines, show only findings
  -h         Show this help
Run as root for complete results. This tool is read-only.
EOF
}

while getopts ":d:o:qh" opt; do
  case "$opt" in
    d) RECENT_DAYS="$OPTARG" ;;
    o) OUT_FILE="$OPTARG" ;;
    q) QUIET=1 ;;
    h) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done

case "$RECENT_DAYS" in ''|*[!0-9]*) echo "DAYS must be a number"; exit 1 ;; esac

# ---------- findings engine ----------
CRIT=0; HIGH=0; MED=0; LOW=0; INFO=0
REPORT=()

add_report() { REPORT+=("$1"); }

finding() {  # finding SEVERITY "title" "detail"
  local sev="$1" title="$2" detail="${3:-}" col
  case "$sev" in
    CRITICAL) col="$R"; CRIT=$((CRIT+1)) ;;
    HIGH)     col="$M"; HIGH=$((HIGH+1)) ;;
    MEDIUM)   col="$Y"; MED=$((MED+1)) ;;
    LOW)      col="$B"; LOW=$((LOW+1)) ;;
    *)        col="$G"; INFO=$((INFO+1)); sev="INFO"
              [ "$QUIET" -eq 1 ] && { add_report "[INFO] $title $detail"; return; } ;;
  esac
  printf '  %s[%-8s]%s %s\n' "$col" "$sev" "$N" "$title"
  [ -n "$detail" ] && printf '             %s↳ %s%s\n' "$W" "$detail" "$N"
  add_report "[$sev] $title | $detail"
}

section() {
  printf '\n%s%s━━[ %s ]━━%s\n' "$W" "$C" "$1" "$N"
  add_report ""; add_report "== $1 =="
}

# Suspicious content patterns (reverse shells, droppers, obfuscation)
SUSP='(/dev/tcp/|/dev/udp/|nc(at)?[[:space:]]+(-[a-z]*e|.*[[:space:]]-e[[:space:]])|bash[[:space:]]+-i|sh[[:space:]]+-i[[:space:]]|base64[[:space:]]+(-d|--decode)|curl[^|#]*\|[[:space:]]*(ba)?sh|wget[^|#]*\|[[:space:]]*(ba)?sh|mkfifo|python[0-9.]*[[:space:]]+-c|perl[[:space:]]+-e|ruby[[:space:]]+-e|socat|openssl[[:space:]]+s_client|/dev/shm|/tmp/\.|chmod[[:space:]]+(\+s|[24-7][0-7][0-7][0-7])|insmod|eval[[:space:]]+[\"$(]|\.onion|xmrig|kinsing)'

is_recent() { [ -n "$(find "$1" -maxdepth 0 -mtime "-$RECENT_DAYS" 2>/dev/null)" ]; }

scan_file() {  # scan_file FILE LABEL
  local f="$1" label="$2" hits
  [ -f "$f" ] && [ -r "$f" ] || return 0
  hits=$(grep -nEi "$SUSP" "$f" 2>/dev/null | grep -vE '^[0-9]+:[[:space:]]*#' | head -5)
  if [ -n "$hits" ]; then
    finding HIGH "$label: suspicious content in $f" "$(printf '%s' "$hits" | head -1 | cut -c1-140)"
  fi
  if is_recent "$f"; then
    finding MEDIUM "$label: recently modified ($RECENT_DAYS d): $f" "mtime $(stat -c '%y' "$f" 2>/dev/null | cut -d. -f1)"
  fi
}

list_homes() {
  awk -F: '($3>=1000 && $3<65534) || $1=="root" {print $6}' /etc/passwd 2>/dev/null | sort -u
}

# ---------- checks ----------
check_system_info() {
  section "SYSTEM INFO"
  finding INFO "Host: $(hostname 2>/dev/null)  Kernel: $(uname -r)" "Run at $(date '+%F %T') as $(id -un) (uid $(id -u))"
  [ "$(id -u)" -ne 0 ] && finding LOW "Not running as root" "Some locations (spool dirs, other users' homes) may be unreadable"
}

check_cron() {
  section "CRON / ANACRON / AT"
  local f
  for f in /etc/crontab /etc/anacrontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* \
           /etc/cron.weekly/* /etc/cron.monthly/* /var/spool/cron/* /var/spool/cron/crontabs/*; do
    [ -f "$f" ] || continue
    scan_file "$f" "cron"
  done
  if command -v crontab >/dev/null 2>&1 && [ "$(id -u)" -eq 0 ]; then
    local u
    for u in $(cut -d: -f1 /etc/passwd); do
      crontab -l -u "$u" 2>/dev/null | grep -qvE '^[[:space:]]*(#|$)' && \
        finding INFO "User crontab present: $u" "$(crontab -l -u "$u" 2>/dev/null | grep -vE '^[[:space:]]*(#|$)' | head -1 | cut -c1-120)"
    done
  fi
  for f in /var/spool/at/* /var/spool/cron/atjobs/*; do
    [ -f "$f" ] && finding MEDIUM "Pending 'at' job: $f" ""
  done
}

check_systemd() {
  section "SYSTEMD UNITS & TIMERS"
  command -v systemctl >/dev/null 2>&1 || { finding INFO "systemd not detected" ""; return; }
  local d f
  local dirs=(/etc/systemd/system /usr/local/lib/systemd/system /run/systemd/system)
  for d in $(list_homes); do dirs+=("$d/.config/systemd/user"); done
  for d in "${dirs[@]}"; do
    [ -d "$d" ] || continue
    while IFS= read -r f; do
      scan_file "$f" "systemd"
      grep -qE '^ExecStart[A-Za-z]*=.*(/tmp/|/dev/shm/|/var/tmp/|/home/[^ ]*/\.)' "$f" 2>/dev/null && \
        finding HIGH "systemd: unit runs binary from temp/hidden path: $f" "$(grep -E '^ExecStart' "$f" | head -1 | cut -c1-140)"
    done < <(find "$d" -maxdepth 2 -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' \) 2>/dev/null)
  done
  finding INFO "Active timers" "$(systemctl list-timers --all --no-legend 2>/dev/null | wc -l) timer(s) listed"
}

check_init() {
  section "RC.LOCAL / INIT.D / MOTD / UDEV"
  local f
  for f in /etc/rc.local /etc/rc.d/rc.local /etc/init.d/* /etc/update-motd.d/* /etc/rc.d/init.d/*; do
    [ -f "$f" ] || continue
    scan_file "$f" "init"
  done
  [ -s /etc/rc.local ] && finding LOW "/etc/rc.local exists and is non-empty" "Review commands executed at boot"
  for f in /etc/udev/rules.d/* /lib/udev/rules.d/* /usr/lib/udev/rules.d/*; do
    [ -f "$f" ] || continue
    grep -qE 'RUN\+?=.*(/tmp|/dev/shm|curl|wget|nc |bash -c|sh -c)' "$f" 2>/dev/null && \
      finding HIGH "udev rule executes suspicious command: $f" "$(grep -E 'RUN' "$f" | head -1 | cut -c1-140)"
  done
}

check_shell_profiles() {
  section "SHELL PROFILES / ENV INJECTION"
  local f d
  for f in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/environment /etc/profile.d/*; do
    [ -f "$f" ] && scan_file "$f" "profile"
  done
  for d in $(list_homes); do
    for f in .bashrc .bash_profile .bash_login .profile .zshrc .zprofile .zshenv .bash_logout .config/fish/config.fish; do
      [ -f "$d/$f" ] && scan_file "$d/$f" "profile"
    done
  done
}

check_ssh() {
  section "SSH KEYS & CONFIG"
  local d f
  for d in $(list_homes); do
    for f in "$d/.ssh/authorized_keys" "$d/.ssh/authorized_keys2"; do
      [ -f "$f" ] || continue
      finding INFO "authorized_keys: $f" "$(grep -cvE '^[[:space:]]*(#|$)' "$f") key(s)"
      grep -qE '^(command=|environment=|permitopen=)' "$f" 2>/dev/null && \
        finding HIGH "authorized_keys uses forced command/options: $f" "$(grep -E '^(command=|environment=)' "$f" | head -1 | cut -c1-140)"
      is_recent "$f" && finding MEDIUM "authorized_keys modified in last $RECENT_DAYS d: $f" "mtime $(stat -c '%y' "$f" | cut -d. -f1)"
    done
    [ -f "$d/.ssh/rc" ] && finding HIGH "~/.ssh/rc present (runs on every SSH login): $d/.ssh/rc" ""
    [ -f "$d/.ssh/environment" ] && finding MEDIUM "~/.ssh/environment present: $d/.ssh/environment" ""
  done
  [ -f /etc/ssh/sshrc ] && finding HIGH "/etc/ssh/sshrc present (runs on SSH login)" ""
  if [ -r /etc/ssh/sshd_config ]; then
    grep -qiE '^[[:space:]]*AuthorizedKeysCommand[[:space:]]+/' /etc/ssh/sshd_config && \
      finding MEDIUM "sshd AuthorizedKeysCommand configured" "$(grep -iE '^[[:space:]]*AuthorizedKeysCommand ' /etc/ssh/sshd_config | head -1)"
    grep -qiE '^[[:space:]]*PermitRootLogin[[:space:]]+yes' /etc/ssh/sshd_config && \
      finding MEDIUM "sshd allows root login (PermitRootLogin yes)" ""
    grep -qiE '^[[:space:]]*PermitEmptyPasswords[[:space:]]+yes' /etc/ssh/sshd_config && \
      finding HIGH "sshd allows empty passwords" ""
  fi
}

check_preload() {
  section "LD_PRELOAD / LINKER HIJACKING"
  if [ -s /etc/ld.so.preload ]; then
    finding CRITICAL "/etc/ld.so.preload is non-empty (classic rootkit/hook technique)" "$(head -3 /etc/ld.so.preload | tr '\n' ' ')"
  else
    finding INFO "/etc/ld.so.preload absent/empty" ""
  fi
  local f
  for f in /etc/ld.so.conf /etc/ld.so.conf.d/*; do
    [ -f "$f" ] || continue
    grep -qE '^(/tmp|/dev/shm|/var/tmp|/home)' "$f" 2>/dev/null && \
      finding HIGH "ld.so.conf includes writable path: $f" "$(grep -E '^(/tmp|/dev/shm|/var/tmp|/home)' "$f" | head -1)"
  done
  grep -l 'LD_PRELOAD' /etc/environment /etc/profile /etc/profile.d/* 2>/dev/null | while read -r f; do
    finding HIGH "LD_PRELOAD set in $f" ""
  done
}

check_accounts() {
  section "ACCOUNTS / SUDO / PAM"
  local line
  awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd 2>/dev/null | while read -r line; do
    finding CRITICAL "Extra UID 0 account: $line" "Backdoor root-equivalent account"
  done
  if [ -r /etc/shadow ]; then
    awk -F: '($2=="" ){print $1}' /etc/shadow 2>/dev/null | while read -r line; do
      finding HIGH "Account with EMPTY password: $line" ""
    done
  fi
  awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ && $3>=1000 && $3<65534 {print $1" ("$7")"}' /etc/passwd 2>/dev/null | while read -r line; do
    finding INFO "Interactive user: $line" ""
  done
  local f
  for f in /etc/sudoers /etc/sudoers.d/*; do
    [ -r "$f" ] && [ -f "$f" ] || continue
    grep -nE 'NOPASSWD' "$f" 2>/dev/null | grep -vE '^[0-9]+:[[:space:]]*#' | head -3 | while read -r line; do
      finding MEDIUM "sudo NOPASSWD rule in $f" "$(printf '%s' "$line" | cut -c1-130)"
    done
    is_recent "$f" && finding MEDIUM "sudoers file modified in last $RECENT_DAYS d: $f" ""
  done
  for f in /etc/pam.d/*; do
    [ -f "$f" ] || continue
    grep -qE 'pam_exec\.so|pam_python|pam_script' "$f" 2>/dev/null && \
      finding HIGH "PAM runs external command/script: $f" "$(grep -E 'pam_exec|pam_python|pam_script' "$f" | head -1 | cut -c1-130)"
    is_recent "$f" && finding MEDIUM "PAM config modified in last $RECENT_DAYS d: $f" ""
  done
}

check_kernel_modules() {
  section "KERNEL MODULES"
  local f
  for f in /etc/modules /etc/modules-load.d/* /etc/modprobe.d/*; do
    [ -f "$f" ] || continue
    is_recent "$f" && finding MEDIUM "Module config modified in last $RECENT_DAYS d: $f" ""
    grep -qE '^install[[:space:]].*(/bin/(ba)?sh|curl|wget|/tmp)' "$f" 2>/dev/null && \
      finding HIGH "modprobe 'install' hook runs command: $f" "$(grep -E '^install' "$f" | head -1 | cut -c1-130)"
  done
  if command -v lsmod >/dev/null 2>&1; then
    finding INFO "Loaded modules" "$(lsmod | tail -n +2 | wc -l) module(s)"
    if [ -d /sys/module ]; then
      lsmod | awk 'NR>1{print $1}' | while read -r m; do
        [ -d "/sys/module/$m" ] || finding HIGH "Module in lsmod missing from /sys/module: $m" "Possible hidden-module tampering"
      done
    fi
    [ -r /proc/sys/kernel/tainted ] && [ "$(cat /proc/sys/kernel/tainted)" != "0" ] && \
      finding LOW "Kernel is tainted (value $(cat /proc/sys/kernel/tainted))" "May include out-of-tree/unsigned modules"
  fi
}

check_autostart_hooks() {
  section "DESKTOP AUTOSTART / PACKAGE-MANAGER HOOKS"
  local d f
  for f in /etc/xdg/autostart/*.desktop; do [ -f "$f" ] && scan_file "$f" "autostart"; done
  for d in $(list_homes); do
    for f in "$d"/.config/autostart/*.desktop; do [ -f "$f" ] && scan_file "$f" "autostart"; done
  done
  for f in /etc/apt/apt.conf.d/*; do
    [ -f "$f" ] || continue
    grep -qE 'Pre-Invoke|Post-Invoke|Update-Post-Invoke' "$f" 2>/dev/null && \
      grep -qiE "$SUSP" "$f" 2>/dev/null && finding HIGH "APT hook with suspicious command: $f" "$(grep -E 'Invoke' "$f" | head -1 | cut -c1-130)"
  done
  for f in /etc/yum/pluginconf.d/* /etc/dnf/plugins/*; do [ -f "$f" ] && scan_file "$f" "pkg-hook"; done
}

check_suid() {
  section "SUID / SGID IN UNUSUAL LOCATIONS"
  local f found=0
  while IFS= read -r f; do
    found=1
    finding HIGH "SUID/SGID file in writable/temp location: $f" "$(stat -c '%A %U:%G %y' "$f" 2>/dev/null | cut -d. -f1)"
  done < <(find /tmp /var/tmp /dev/shm /home /opt /srv -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -50)
  [ "$found" -eq 0 ] && finding INFO "No SUID/SGID files in temp/home/opt locations" ""
}

check_hidden_exec() {
  section "HIDDEN / TEMP EXECUTABLES"
  local f found=0
  while IFS= read -r f; do
    found=1
    finding MEDIUM "Executable in temp dir: $f" "$(stat -c '%U %y' "$f" 2>/dev/null | cut -d. -f1)"
  done < <(find /tmp /var/tmp /dev/shm -xdev -type f -perm -u+x 2>/dev/null | head -30)
  [ "$found" -eq 0 ] && finding INFO "No executables in /tmp, /var/tmp, /dev/shm" ""
  while IFS= read -r f; do
    finding MEDIUM "Hidden executable in system bin dir: $f" ""
  done < <(find /usr/bin /usr/sbin /bin /sbin /usr/local/bin /usr/local/sbin -maxdepth 1 -name '.*' -type f 2>/dev/null | head -20)
}

check_listeners() {
  section "LISTENING SERVICES (context for persistence)"
  if command -v ss >/dev/null 2>&1; then
    ss -tulnH 2>/dev/null | awk '{print $1" "$5}' | sort -u | head -25 | while read -r l; do
      finding INFO "Listening: $l" ""
    done
  else
    finding INFO "ss not available" ""
  fi
}

summary() {
  section "SUMMARY"
  printf '  %sCritical:%s %d   %sHigh:%s %d   %sMedium:%s %d   %sLow:%s %d   %sInfo:%s %d\n' \
    "$R" "$N" "$CRIT" "$M" "$N" "$HIGH" "$Y" "$N" "$MED" "$B" "$N" "$LOW" "$G" "$N" "$INFO"
  add_report "Critical=$CRIT High=$HIGH Medium=$MED Low=$LOW Info=$INFO"
  if [ $((CRIT+HIGH)) -gt 0 ]; then
    printf '\n  %s[!] Review CRITICAL/HIGH items first - verify against known-good config.%s\n' "$R" "$N"
  else
    printf '\n  %s[+] No critical/high persistence indicators found.%s\n' "$G" "$N"
  fi
  printf '  %sNote: findings are indicators, not proof. Validate before remediation.%s\n' "$Y" "$N"
  if [ -n "$OUT_FILE" ]; then
    {
      echo "Persistence Audit Report - coded by Mr Sabaz Ali Khan"
      echo "Host: $(hostname)  Date: $(date '+%F %T')  Recent window: ${RECENT_DAYS}d"
      printf '%s\n' "${REPORT[@]}"
    } > "$OUT_FILE" 2>/dev/null && printf '  %sReport saved:%s %s\n' "$G" "$N" "$OUT_FILE"
  fi
  printf '\n  %s-- coded by Mr Sabaz Ali Khan | Cyber Security Engineer --%s\n\n' "$C" "$N"
}

# ---------- main ----------
[ "$(uname -s)" = "Linux" ] || { echo "This tool targets Linux."; exit 1; }
banner
check_system_info
check_cron
check_systemd
check_init
check_shell_profiles
check_ssh
check_preload
check_accounts
check_kernel_modules
check_autostart_hooks
check_suid
check_hidden_exec
check_listeners
summary
