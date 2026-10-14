#!/usr/bin/env bash
# =============================================================================
#  Incident Response Collector (IRC)
#  Coded by Mr Sabaz Ali Khan - Cyber Security Engineer
#
#  Read-only, live-response evidence collector for Linux hosts.
#  Collects in order of volatility, hashes every artifact, writes a
#  chain-of-custody record and packs everything into a sealed archive.
#
#  Usage:  sudo ./ir_collector.sh [options]
#    -o <dir>    Output base directory        (default: ./IR_Collection)
#    -c <id>     Case / incident ID           (default: none)
#    -e <name>   Examiner name                (default: Mr Sabaz Ali Khan)
#    -d <days>   "Recently modified" window   (default: 7)
#    -q          Quick mode (skip heavy filesystem + log sweeps)
#    -n          No archive (leave the folder only)
#    -h          Help
#
#  Use only on systems you own or are explicitly authorised to examine.
# =============================================================================

set -u
export LC_ALL=C
umask 077

VERSION="1.0"
AUTHOR="Mr Sabaz Ali Khan"

# ---------- colours ----------------------------------------------------------
if [[ -t 1 ]]; then
  R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; B=$'\e[1m'; N=$'\e[0m'
else
  R=""; G=""; Y=""; C=""; B=""; N=""
fi

# ---------- banner -----------------------------------------------------------
print_banner() {
  printf '%s' "$C"
  cat <<'BANNER'
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣠⣼⠀⠀⠀⠀⠈⠙⡆⢤⠀⠀⠀⠀⠀⣷⣄⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣾⣿⣿⣿⣿⣿⣿⡿⢿⡷⡆⠀⣵⣶⣿⣾⣷⣸⣄⠀⠀⠀⢰⠾⡿⢿⣿⣿⣿⣿⣿⣿⣷⣦⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣾⣿⣿⣿⣿⣽⣿⣿⣿⣿⡟⠀⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣄⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⡾⣻⣵⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀⠀⠐⣻⣿⣿⡏⢹⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣮⣟⢷⡀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢿⣿⣿⣿⡄⠀⠀⠀⠀⢻⣿⣿⣷⡌⠸⣿⣾⢿⡧⠀⠀⠀⠀⠀⢀⣿⣿⣿⡿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣠⣾⡿⢛⣵⣾⣿⣿⣿⣿⣿⣯⣾⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⢻⣿⣿⣿⣶⣌⠙⠋⠁⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣷⣽⣿⣿⣿⣿⣿⣷⣮⡙⢿⣿⣆⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣰⡿⢋⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⣿⣿⣿⣿⣧⡀⠀⠀⠀⣠⣽⣿⣿⣿⣿⣷⣦⡀⠀⠀⠀⢀⣼⣿⣿⣿⣿⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣝⢿⣇⠀⠀⠀⠀
⠀⠀⠀⣴⣯⣴⣿⣿⠿⢿⣿⣿⣿⣿⣿⣿⡿⢫⣾⣿⣿⣿⣿⣿⣿⡦⢀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⢴⣿⣿⣿⣿⣿⣿⣷⣝⢿⣿⣿⣿⣿⣿⣿⡿⠿⣿⣿⣧⣽⣦⠀⠀⠀
⠀⠀⣼⣿⣿⣿⠟⢁⣴⣿⡿⢿⣿⣿⡿⠛⣰⣿⠟⣻⣿⣿⣿⣿⣿⣿⣿⡿⠿⠋⢿⣿⣿⣿⣿⣿⠻⢿⣿⣿⣿⣿⣿⣿⣿⣟⠻⣿⣆⠙⢿⣿⣿⡿⢿⣿⣦⡈⠻⣿⣿⣿⣧⠀⠀
⠀⡼⣻⣿⡟⢁⣴⡿⠋⠁⢀⣼⣿⠟⠁⣰⣿⠁⢰⣿⣿⣿⡿⣿⣿⣿⠿⠀⣠⣤⣾⣿⣿⣿⣿⣿⠀⠀⠽⣿⣿⣿⢿⣿⣿⣿⡆⠈⢿⣆⠀⠻⣿⣧⡀⠈⠙⢿⣦⡈⠻⣿⣟⢧⠀
⠀⣱⣿⠋⢠⡾⠋⠀⢀⣠⡾⠟⠁⠀⢀⣿⠟⠀⢸⣿⠙⣿⠀⠈⢿⠏⠀⣾⣿⠛⣻⣿⣿⣿⣿⣯⣤⠀⠀⠹⡿⠁⠀⣿⠏⣿⡇⠀⠹⣿⡄⠀⠈⠻⢷⣄⡀⠀⠙⢷⣄⠙⣿⣎⠂
⢠⣿⠏⠀⣏⢀⣠⠴⠛⠉⠀⠀⠀⠀⠈⠁⠀⠀⠀⠛⠀⠈⠀⠀⠀⠀⠈⢿⣿⣼⣿⣿⣿⣿⢿⣿⣿⣶⠀⠀⠀⠀⠀⠁⠀⠛⠀⠀⠀⠀⠁⠀⠀⠀⠀⠉⠛⠦⣄⣀⣹⠀⠹⣿⡄
⣼⡟⣀⣼⣿⣋⡁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠛⠛⠛⠋⠁⠀⢹⣿⣿⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⢿⣧⠀⢻⣷
⣿⠃⢰⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣰⣶⣦⣤⠀⠀⣿⡿⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⡆⠘⣿
⣿⠀⢸⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⡟⠁⠈⢻⣷⣸⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣧⠀⣿
⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣷⣀⣀⣸⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⣿
⢸⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠛⣿⡿⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡇
⠈⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⠁
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢷⣴⡿⣷⠀⠀⢰⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠴⡿⣟⣿⣿⣶⡶⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
BANNER
  printf '%s\n' "$N"
  printf '  %s╔══════════════════════════════════════════════════════════════╗%s\n' "$B" "$N"
  printf '  %s║%s      INCIDENT RESPONSE COLLECTOR  v%-5s  (Linux / Bash)      %s║%s\n' "$B" "$N" "$VERSION" "$B" "$N"
  printf '  %s║%s      Coded by %s%-36s%s        %s║%s\n' "$B" "$N" "$G$B" "$AUTHOR" "$N" "$B" "$N"
  printf '  %s║%s      Cyber Security Engineer                                 %s║%s\n' "$B" "$N" "$B" "$N"
  printf '  %s╚══════════════════════════════════════════════════════════════╝%s\n\n' "$B" "$N"
}

usage() {
  sed -n '/^#  Usage/,/^#  Use only/p' "$0" | sed 's/^#  \{0,1\}//'
  exit 0
}

# ---------- defaults / args --------------------------------------------------
BASE_DIR="./IR_Collection"
CASE_ID="N/A"
EXAMINER="$AUTHOR"
DAYS=7
QUICK=0
ARCHIVE=1

while getopts "o:c:e:d:qnh" opt; do
  case "$opt" in
    o) BASE_DIR="$OPTARG" ;;
    c) CASE_ID="$OPTARG" ;;
    e) EXAMINER="$OPTARG" ;;
    d) DAYS="$OPTARG" ;;
    q) QUICK=1 ;;
    n) ARCHIVE=0 ;;
    h) print_banner; usage ;;
    *) usage ;;
  esac
done

[[ "$DAYS" =~ ^[0-9]+$ ]] || { echo "${R}[!] -d must be a number${N}"; exit 1; }

print_banner

# ---------- helpers ----------------------------------------------------------
info()  { printf '%s[*]%s %s\n' "$C" "$N" "$*"; }
ok()    { printf '%s[+]%s %s\n' "$G" "$N" "$*"; }
warn()  { printf '%s[!]%s %s\n' "$Y" "$N" "$*"; }
err()   { printf '%s[-]%s %s\n' "$R" "$N" "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }

if [[ "$(uname -s)" != "Linux" ]]; then
  err "This collector targets Linux. Detected: $(uname -s)"; exit 1
fi

if [[ $EUID -ne 0 ]]; then
  warn "Not running as root - some artifacts will be incomplete. Re-run with sudo for full collection."
fi

HOST="$(hostname 2>/dev/null || echo unknown)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${BASE_DIR%/}/IR_${HOST}_${TS}"
mkdir -p "$OUT"/{01_volatile,02_system,03_users,04_persistence,05_filesystem,06_logs,07_packages,08_containers} || {
  err "Cannot create output directory: $OUT"; exit 1; }
OUT="$(cd "$OUT" && pwd)"
COLLECTOR_LOG="$OUT/collector.log"

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >> "$COLLECTOR_LOG"; }

# run <relative-output-file> <command...>   (appends, never fails the script)
run() {
  local f="$1"; shift
  have "$1" || { log "SKIP (missing): $1"; return 0; }
  { printf '\n### [%s] $ %s\n' "$(date -u +%FT%TZ)" "$*"; "$@" 2>&1; } >> "$OUT/$f"
  log "RUN: $*"
}

# runsh <relative-output-file> '<shell pipeline>'
runsh() {
  local f="$1"; shift
  { printf '\n### [%s] $ %s\n' "$(date -u +%FT%TZ)" "$*"; bash -c "$*" 2>&1; } >> "$OUT/$f"
  log "RUNSH: $*"
}

# copy_file <src> <dest-dir>   (preserves path layout, skips huge files)
copy_file() {
  local src="$1" dst="$2"
  [[ -f "$src" && -r "$src" ]] || return 0
  local sz; sz=$(stat -c %s "$src" 2>/dev/null || echo 0)
  (( sz > 104857600 )) && { log "SKIP >100MB: $src"; return 0; }
  mkdir -p "$dst$(dirname "$src")" && cp -p "$src" "$dst$src" 2>/dev/null && log "COPY: $src"
}

# ---------- chain of custody -------------------------------------------------
write_custody() {
  cat > "$OUT/00_CHAIN_OF_CUSTODY.txt" <<EOF
=============================================================
  INCIDENT RESPONSE COLLECTION - CHAIN OF CUSTODY
  Tool        : Incident Response Collector v$VERSION
  Coded by    : $AUTHOR (Cyber Security Engineer)
=============================================================
Case ID       : $CASE_ID
Examiner      : $EXAMINER
Collected by  : $(id -un 2>/dev/null) (uid=$EUID)
Host          : $HOST
Collection UTC: $(date -u +%FT%TZ)
Local time    : $(date +%FT%T%z)
Kernel        : $(uname -srvm)
Output path   : $OUT
Quick mode    : $([[ $QUICK -eq 1 ]] && echo yes || echo no)
Recent window : last $DAYS day(s)
=============================================================
EOF
}

# ---------- 01 volatile ------------------------------------------------------
collect_volatile() {
  info "Collecting volatile data (order of volatility)..."
  local f="01_volatile"
  run $f/time.txt date -u
  run $f/time.txt uptime
  run $f/time.txt timedatectl
  run $f/logged_in.txt who -a
  run $f/logged_in.txt w
  run $f/processes.txt ps auxwwf
  run $f/processes.txt ps -eo pid,ppid,user,lstart,etime,stat,args --sort=start_time
  runsh $f/processes.txt 'ls -l /proc/[0-9]*/exe 2>/dev/null | grep -E "\(deleted\)|/tmp/|/dev/shm/|/var/tmp/" || echo "none flagged"'
  runsh $f/process_exe_hashes.txt 'for p in /proc/[0-9]*; do e=$(readlink -f "$p/exe" 2>/dev/null); [ -n "$e" ] && [ -f "$e" ] && echo "$(sha256sum "$e" 2>/dev/null | cut -d" " -f1)  pid=$(basename $p)  $e"; done | sort -k3 -u'
  runsh $f/process_cmdlines.txt 'for p in /proc/[0-9]*; do printf "%s\t" "$(basename $p)"; tr "\0" " " < "$p/cmdline" 2>/dev/null; echo; done'
  runsh $f/process_environ_flags.txt 'for p in /proc/[0-9]*; do tr "\0" "\n" < "$p/environ" 2>/dev/null | grep -E "^(LD_PRELOAD|LD_LIBRARY_PATH)=" | sed "s|^|pid=$(basename $p) |"; done; echo done'
  run $f/network.txt ip -br addr
  run $f/network.txt ip addr
  run $f/network.txt ip route
  run $f/network.txt ip neigh
  run $f/network.txt ip -s link
  if have ss; then
    run $f/network.txt ss -tulpane
    run $f/network.txt ss -s
  else
    run $f/network.txt netstat -tulpan
  fi
  runsh $f/network.txt 'cat /etc/resolv.conf /etc/hosts 2>/dev/null'
  run $f/network.txt iptables -S
  run $f/network.txt nft list ruleset
  run $f/open_files.txt lsof -nP -i
  runsh $f/open_files.txt 'lsof -nP +L1 2>/dev/null | head -n 500'
  runsh $f/mounts.txt 'cat /proc/mounts'
  run $f/mounts.txt df -hT
  run $f/mounts.txt lsblk -f
  run $f/kernel_modules.txt lsmod
  runsh $f/kernel_modules.txt 'cat /proc/modules'
  runsh $f/memory_info.txt 'cat /proc/meminfo; echo; free -m 2>/dev/null; echo; cat /proc/swaps'
  runsh $f/arp_cache.txt 'cat /proc/net/arp'
  runsh $f/promiscuous.txt 'ip -o link | grep -i promisc || echo "no promiscuous interfaces"'
  ok "Volatile data collected"
}

# ---------- 02 system --------------------------------------------------------
collect_system() {
  info "Collecting system information..."
  local f="02_system"
  run $f/os.txt uname -a
  runsh $f/os.txt 'cat /etc/os-release /etc/*release 2>/dev/null'
  run $f/hardware.txt lscpu
  run $f/hardware.txt lsusb
  run $f/hardware.txt lspci
  runsh $f/env.txt 'env | sort'
  runsh $f/sysctl.txt 'sysctl -a 2>/dev/null'
  runsh $f/kernel_cmdline.txt 'cat /proc/cmdline'
  runsh $f/selinux_apparmor.txt 'getenforce 2>/dev/null; sestatus 2>/dev/null; aa-status 2>/dev/null; echo done'
  runsh $f/dmesg.txt 'dmesg -T 2>/dev/null | tail -n 3000'
  runsh $f/tainted.txt 'cat /proc/sys/kernel/tainted'
  runsh $f/ld_preload.txt 'echo "--- /etc/ld.so.preload ---"; cat /etc/ld.so.preload 2>/dev/null || echo "(not present)"; echo "--- /etc/ld.so.conf* ---"; cat /etc/ld.so.conf /etc/ld.so.conf.d/* 2>/dev/null'
  runsh $f/tmp_listing.txt 'ls -laR /tmp /var/tmp /dev/shm 2>/dev/null'
  ok "System information collected"
}

# ---------- 03 users ---------------------------------------------------------
collect_users() {
  info "Collecting user & authentication artifacts..."
  local f="03_users"
  copy_file /etc/passwd "$OUT/$f/etc_copy"
  copy_file /etc/group  "$OUT/$f/etc_copy"
  copy_file /etc/sudoers "$OUT/$f/etc_copy"
  for sf in /etc/sudoers.d/*; do copy_file "$sf" "$OUT/$f/etc_copy"; done
  copy_file /etc/ssh/sshd_config "$OUT/$f/etc_copy"
  runsh $f/uid0_accounts.txt "awk -F: '\$3==0 {print}' /etc/passwd"
  runsh $f/login_shell_accounts.txt "grep -vE '(nologin|false)\$' /etc/passwd"
  runsh $f/empty_passwords.txt "awk -F: '(\$2==\"\" ) {print \$1}' /etc/shadow 2>/dev/null || echo 'cannot read /etc/shadow'"
  runsh $f/shadow_metadata.txt "awk -F: '{print \$1\":\"substr(\$2,1,3)\":\"\$3\":\"\$4\":\"\$5\":\"\$6}' /etc/shadow 2>/dev/null"
  run $f/last_logins.txt last -Fwi -n 200
  run $f/last_logins.txt lastb -Fwi -n 200
  run $f/last_logins.txt lastlog
  runsh $f/sudo_groups.txt 'getent group sudo wheel admin 2>/dev/null'
  # SSH material (metadata + authorized_keys only, never private keys)
  runsh $f/authorized_keys.txt 'for h in /root /home/*; do for k in "$h"/.ssh/authorized_keys "$h"/.ssh/authorized_keys2; do [ -f "$k" ] && { echo "=== $k ==="; ls -l "$k"; cat "$k"; }; done; done'
  runsh $f/ssh_dir_listing.txt 'for h in /root /home/*; do [ -d "$h/.ssh" ] && { echo "=== $h/.ssh ==="; ls -la "$h/.ssh"; }; done'
  runsh $f/known_hosts.txt 'for h in /root /home/*; do [ -f "$h/.ssh/known_hosts" ] && { echo "=== $h ==="; cat "$h/.ssh/known_hosts"; }; done'
  runsh $f/shell_history.txt 'for h in /root /home/*; do for hf in .bash_history .zsh_history .sh_history .python_history .mysql_history; do [ -f "$h/$hf" ] && { echo "=== $h/$hf ==="; tail -n 1000 "$h/$hf"; }; done; done'
  ok "User artifacts collected"
}

# ---------- 04 persistence ---------------------------------------------------
collect_persistence() {
  info "Hunting persistence mechanisms..."
  local f="04_persistence"
  # cron
  runsh $f/cron.txt 'for d in /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs; do [ -e "$d" ] && { echo "=== $d ==="; ls -la "$d" 2>/dev/null; find "$d" -type f -exec sh -c '"'"'echo "--- $1 ---"; cat "$1"'"'"' _ {} \; 2>/dev/null; }; done'
  runsh $f/at_jobs.txt 'atq 2>/dev/null; ls -la /var/spool/at /var/spool/cron/atjobs 2>/dev/null; echo done'
  # systemd
  run $f/systemd_units.txt systemctl list-unit-files --no-pager
  run $f/systemd_units.txt systemctl list-units --all --no-pager
  run $f/systemd_timers.txt systemctl list-timers --all --no-pager
  runsh $f/systemd_recent_units.txt "find /etc/systemd /usr/lib/systemd /lib/systemd /run/systemd -type f \\( -name '*.service' -o -name '*.timer' -o -name '*.socket' \\) -mtime -$DAYS -printf '%TY-%Tm-%Td %TH:%TM  %u  %p\\n' 2>/dev/null | sort -r"
  runsh $f/systemd_execstart.txt "grep -rHE '^(ExecStart|ExecStartPre|ExecStartPost)=' /etc/systemd/system /run/systemd/system 2>/dev/null"
  # init / rc
  runsh $f/rc_init.txt 'ls -la /etc/init.d /etc/rc*.d 2>/dev/null; echo "--- rc.local ---"; cat /etc/rc.local 2>/dev/null'
  # shell profiles
  runsh $f/shell_profiles.txt 'for f in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/environment /etc/profile.d/* /root/.bashrc /root/.profile /root/.bash_profile /home/*/.bashrc /home/*/.profile /home/*/.bash_profile /home/*/.zshrc; do [ -f "$f" ] && { echo "=== $f ($(stat -c %y "$f" 2>/dev/null)) ==="; cat "$f"; }; done'
  # suspicious one-liners in startup files
  runsh $f/suspicious_startup_patterns.txt 'grep -rnE "(curl|wget|nc |ncat|/dev/tcp|base64 -d|python -c|perl -e|bash -i|mkfifo|chmod \+x /tmp|eval )" /etc/profile /etc/profile.d /etc/bash.bashrc /etc/rc.local /etc/cron* /var/spool/cron /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile 2>/dev/null || echo "no matches"'
  # PAM, MOTD, udev, XDG autostart
  runsh $f/pam.txt 'ls -la /etc/pam.d; echo; grep -rn "pam_exec\|pam_python" /etc/pam.d 2>/dev/null || echo "no pam_exec/pam_python"'
  runsh $f/motd_scripts.txt 'ls -la /etc/update-motd.d 2>/dev/null'
  runsh $f/udev_rules.txt "find /etc/udev/rules.d /lib/udev/rules.d -type f -mtime -$DAYS -exec ls -l {} \\; 2>/dev/null; grep -rn 'RUN+=' /etc/udev/rules.d 2>/dev/null"
  runsh $f/xdg_autostart.txt 'ls -la /etc/xdg/autostart /root/.config/autostart /home/*/.config/autostart 2>/dev/null'
  runsh $f/anacron.txt 'cat /etc/anacrontab 2>/dev/null'
  ok "Persistence sweep complete"
}

# ---------- 05 filesystem ----------------------------------------------------
collect_filesystem() {
  info "Sweeping filesystem (last ${DAYS} days, SUID/SGID, world-writable)..."
  local f="05_filesystem"
  local EXCL=( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /var/lib/docker -o -path "$OUT" )
  runsh $f/suid_sgid.txt "find / -xdev \\( ${EXCL[*]} \\) -prune -o -type f \\( -perm -4000 -o -perm -2000 \\) -printf '%m %u:%g %TY-%Tm-%Td %p\\n' 2>/dev/null | sort -k4"
  runsh $f/capabilities.txt 'getcap -r / 2>/dev/null || echo "getcap not available"'
  runsh $f/hidden_in_tmp.txt 'find /tmp /var/tmp /dev/shm /run -name ".*" -not -name "." -not -name ".." 2>/dev/null -ls'
  runsh $f/executables_in_tmp.txt 'find /tmp /var/tmp /dev/shm -type f -perm /111 -ls 2>/dev/null'
  runsh $f/hashes_tmp_executables.txt 'find /tmp /var/tmp /dev/shm -type f -perm /111 -exec sha256sum {} + 2>/dev/null'
  if [[ $QUICK -eq 0 ]]; then
    runsh $f/recent_modified.txt "find / -xdev \\( ${EXCL[*]} \\) -prune -o -type f -mtime -$DAYS -printf '%TY-%Tm-%Td %TH:%TM:%TS  %u:%g  %m  %s  %p\\n' 2>/dev/null | sort -r | head -n 20000"
    runsh $f/recent_changed_ctime.txt "find / -xdev \\( ${EXCL[*]} \\) -prune -o -type f -ctime -$DAYS -printf '%CY-%Cm-%Cd %CH:%CM:%CS  %u:%g  %m  %s  %p\\n' 2>/dev/null | sort -r | head -n 20000"
    runsh $f/world_writable_files.txt "find / -xdev \\( ${EXCL[*]} \\) -prune -o -type f -perm -0002 -ls 2>/dev/null | head -n 5000"
    runsh $f/world_writable_dirs_no_sticky.txt "find / -xdev \\( ${EXCL[*]} \\) -prune -o -type d -perm -0002 ! -perm -1000 -ls 2>/dev/null | head -n 2000"
    runsh $f/unowned_files.txt "find / -xdev \\( ${EXCL[*]} \\) -prune -o \\( -nouser -o -nogroup \\) -ls 2>/dev/null | head -n 2000"
    runsh $f/hidden_dirs_outside_home.txt "find / -xdev \\( ${EXCL[*]} \\) -prune -o -type d -name '.*' -not -path '/home/*' -not -path '/root/*' -ls 2>/dev/null | head -n 2000"
    runsh $f/web_shell_candidates.txt "find /var/www /srv /usr/share/nginx /opt -type f \\( -name '*.php' -o -name '*.jsp' -o -name '*.aspx' -o -name '*.cgi' \\) -mtime -$DAYS -ls 2>/dev/null | head -n 2000; grep -rlE '(eval\\(base64_decode|system\\(\\\$_(GET|POST|REQUEST)|passthru\\(|shell_exec\\(\\\$_)' /var/www /srv 2>/dev/null | head -n 200"
    runsh $f/system_binary_mtime_anomalies.txt "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -mtime -$DAYS -printf '%TY-%Tm-%Td %TH:%TM  %u  %m  %p\\n' 2>/dev/null | sort -r"
  else
    log "Quick mode: skipped heavy filesystem sweeps"
  fi
  ok "Filesystem sweep complete"
}

# ---------- 06 logs ----------------------------------------------------------
collect_logs() {
  info "Collecting logs..."
  local f="06_logs"
  local dest="$OUT/$f/raw"
  mkdir -p "$dest"
  local LOGS=(
    /var/log/auth.log /var/log/auth.log.1 /var/log/secure /var/log/secure-* \
    /var/log/syslog /var/log/syslog.1 /var/log/messages /var/log/kern.log \
    /var/log/audit/audit.log /var/log/cron /var/log/cron.log /var/log/dpkg.log \
    /var/log/yum.log /var/log/dnf.log /var/log/apt/history.log /var/log/wtmp \
    /var/log/btmp /var/log/lastlog /var/log/faillog /var/log/ufw.log \
    /var/log/fail2ban.log /var/log/nginx/access.log /var/log/nginx/error.log \
    /var/log/apache2/access.log /var/log/apache2/error.log \
    /var/log/httpd/access_log /var/log/httpd/error_log
  )
  for l in "${LOGS[@]}"; do copy_file "$l" "$dest"; done
  if have journalctl; then
    local lines=20000; [[ $QUICK -eq 1 ]] && lines=3000
    runsh $f/journal_recent.txt "journalctl --no-pager -n $lines -o short-iso 2>/dev/null"
    runsh $f/journal_ssh.txt "journalctl --no-pager -u ssh -u sshd --since '-${DAYS}d' -o short-iso 2>/dev/null"
    runsh $f/journal_sudo.txt "journalctl --no-pager _COMM=sudo --since '-${DAYS}d' -o short-iso 2>/dev/null"
    runsh $f/journal_boots.txt 'journalctl --list-boots --no-pager 2>/dev/null'
  fi
  # quick triage views
  runsh $f/triage_failed_ssh.txt "grep -hE 'Failed password|Invalid user|authentication failure' /var/log/auth.log* /var/log/secure* 2>/dev/null | tail -n 2000"
  runsh $f/triage_failed_ssh_top_ips.txt "grep -hE 'Failed password' /var/log/auth.log* /var/log/secure* 2>/dev/null | grep -oE '([0-9]{1,3}\\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | head -n 30"
  runsh $f/triage_accepted_logins.txt "grep -hE 'Accepted (password|publickey|keyboard-interactive)' /var/log/auth.log* /var/log/secure* 2>/dev/null | tail -n 1000"
  runsh $f/triage_sudo_usage.txt "grep -hE 'sudo:.*(COMMAND|incorrect password)' /var/log/auth.log* /var/log/secure* 2>/dev/null | tail -n 1000"
  runsh $f/triage_new_users_groups.txt "grep -hE 'useradd|usermod|groupadd|new user|new group|passwd\\[' /var/log/auth.log* /var/log/secure* 2>/dev/null | tail -n 500"
  runsh $f/triage_log_tampering.txt "ls -la /var/log; echo; find /var/log -type f -size 0 -ls 2>/dev/null"
  ok "Logs collected"
}

# ---------- 07 packages ------------------------------------------------------
collect_packages() {
  info "Collecting package / software inventory..."
  local f="07_packages"
  if have dpkg;  then
    run $f/dpkg_list.txt dpkg -l
    runsh $f/dpkg_verify.txt 'dpkg -V 2>/dev/null | head -n 5000'
  fi
  if have rpm; then
    runsh $f/rpm_list.txt 'rpm -qa --last'
    runsh $f/rpm_verify.txt 'rpm -Va 2>/dev/null | head -n 5000'
  fi
  have pip3 && run $f/pip_list.txt pip3 list
  have snap && run $f/snap_list.txt snap list
  have flatpak && run $f/flatpak_list.txt flatpak list
  runsh $f/apt_sources.txt 'cat /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null; cat /etc/yum.repos.d/* 2>/dev/null'
  runsh $f/usr_local_opt.txt 'ls -laR /usr/local/bin /usr/local/sbin /opt 2>/dev/null | head -n 3000'
  ok "Package inventory collected"
}

# ---------- 08 containers ----------------------------------------------------
collect_containers() {
  if have docker; then
    info "Collecting Docker artifacts..."
    local f="08_containers"
    run $f/docker.txt docker ps -a --no-trunc
    run $f/docker.txt docker images --digests
    run $f/docker.txt docker network ls
    run $f/docker.txt docker volume ls
    runsh $f/docker_inspect.txt 'docker ps -aq | xargs -r docker inspect 2>/dev/null'
    runsh $f/docker_privileged.txt "docker ps -q | xargs -r docker inspect --format '{{.Name}} privileged={{.HostConfig.Privileged}} pid={{.HostConfig.PidMode}} net={{.HostConfig.NetworkMode}} mounts={{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' 2>/dev/null"
    ok "Docker artifacts collected"
  fi
  if have kubectl; then
    run 08_containers/kubectl.txt kubectl get pods -A -o wide
  fi
  if have crictl; then
    run 08_containers/crictl.txt crictl ps -a
  fi
}

# ---------- summary + seal ---------------------------------------------------
write_summary() {
  local s="$OUT/SUMMARY_TRIAGE.txt"
  {
    echo "============================================================"
    echo " QUICK TRIAGE SUMMARY   (host: $HOST  |  $(date -u +%FT%TZ))"
    echo " Incident Response Collector v$VERSION - coded by $AUTHOR"
    echo "============================================================"
    echo
    echo "[UID 0 accounts]"
    awk -F: '$3==0 {print "  " $1}' /etc/passwd 2>/dev/null
    echo
    echo "[Accounts with empty passwords]"
    awk -F: '($2=="") {print "  " $1}' /etc/shadow 2>/dev/null || echo "  (cannot read shadow)"
    echo
    echo "[Processes running from deleted / temp executables]"
    ls -l /proc/[0-9]*/exe 2>/dev/null | grep -E "\(deleted\)|/tmp/|/dev/shm/|/var/tmp/" | sed 's/^/  /' || true
    echo
    echo "[Executable files in /tmp, /var/tmp, /dev/shm]"
    find /tmp /var/tmp /dev/shm -type f -perm /111 2>/dev/null | sed 's/^/  /'
    echo
    echo "[LD_PRELOAD file]"
    [[ -s /etc/ld.so.preload ]] && sed 's/^/  /' /etc/ld.so.preload || echo "  none"
    echo
    echo "[Promiscuous interfaces]"
    ip -o link 2>/dev/null | grep -i promisc | sed 's/^/  /' || echo "  none"
    echo
    echo "[Listening sockets]"
    if have ss; then ss -tulpn 2>/dev/null | sed 's/^/  /'; fi
    echo
    echo "[Authorized SSH keys count per user]"
    for h in /root /home/*; do
      k="$h/.ssh/authorized_keys"
      [[ -f "$k" ]] && echo "  $k : $(grep -cvE '^\s*(#|$)' "$k") key(s)"
    done
    echo
    echo "[Top failed SSH source IPs]"
    grep -hE 'Failed password' /var/log/auth.log* /var/log/secure* 2>/dev/null \
      | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | head -n 10 | sed 's/^/  /'
    echo
    echo "[Cron entries mentioning download/exec tools]"
    grep -rnE '(curl|wget|nc |ncat|/dev/tcp|base64 -d|python -c|perl -e|bash -i)' /etc/cron* /var/spool/cron 2>/dev/null | sed 's/^/  /'
    echo
    echo "NOTE: This summary is an indicator list, not a verdict. Review the"
    echo "      full artifacts in each numbered folder before drawing conclusions."
  } > "$s" 2>&1
  log "Wrote summary"
}

seal_evidence() {
  info "Hashing all collected artifacts (SHA-256)..."
  ( cd "$OUT" && find . -type f ! -name 'SHA256SUMS.txt' -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS.txt 2>/dev/null )
  ok "Manifest written: SHA256SUMS.txt"

  if [[ $ARCHIVE -eq 1 ]]; then
    info "Creating sealed archive..."
    local parent; parent="$(dirname "$OUT")"
    local name; name="$(basename "$OUT")"
    if tar -C "$parent" -czf "$parent/$name.tar.gz" "$name" 2>/dev/null; then
      sha256sum "$parent/$name.tar.gz" | tee "$parent/$name.tar.gz.sha256" >/dev/null
      chmod 600 "$parent/$name.tar.gz" "$parent/$name.tar.gz.sha256" 2>/dev/null
      ok "Archive : $parent/$name.tar.gz"
      ok "SHA-256 : $(cut -d' ' -f1 "$parent/$name.tar.gz.sha256")"
    else
      err "Archive creation failed - folder left intact"
    fi
  fi
}

# ---------- main -------------------------------------------------------------
START=$(date +%s)
write_custody
log "Collection started by $EXAMINER (case: $CASE_ID)"

info "Host       : $HOST"
info "Case ID    : $CASE_ID"
info "Examiner   : $EXAMINER"
info "Output dir : $OUT"
echo

collect_volatile
collect_system
collect_users
collect_persistence
collect_filesystem
collect_logs
collect_packages
collect_containers
write_summary

END=$(date +%s)
echo "Duration: $((END-START))s" >> "$OUT/00_CHAIN_OF_CUSTODY.txt"
log "Collection finished in $((END-START))s"
seal_evidence

echo
printf '%s══════════════════════════════════════════════════════════════%s\n' "$G" "$N"
printf '%s  Collection complete in %ss%s\n' "$G$B" "$((END-START))" "$N"
printf '  Results : %s\n' "$OUT"
printf '  Triage  : %s/SUMMARY_TRIAGE.txt\n' "$OUT"
printf '  %sCoded by %s - Cyber Security Engineer%s\n' "$C" "$AUTHOR" "$N"
printf '%s══════════════════════════════════════════════════════════════%s\n' "$G" "$N"
