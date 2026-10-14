#!/usr/bin/env bash
# =============================================================================
#  Linux Security Auditor
#  coded by Mr Sabaz Ali Khan  (Cyber Security Engineer)
#
#  Read-only hardening audit for Linux hosts. Makes NO changes to the system.
#  Run as root for the most complete results.
#
#  Usage:  sudo ./linux_security_auditor.sh [-o report.txt] [-n] [-h]
#     -o FILE   write a plain-text report to FILE
#     -n        disable colors
#     -h        help
# =============================================================================

VERSION="1.0"
AUTHOR="Mr Sabaz Ali Khan"
REPORT=""
USE_COLOR=1

while getopts "o:nh" opt; do
  case "$opt" in
    o) REPORT="$OPTARG" ;;
    n) USE_COLOR=0 ;;
    h) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) exit 1 ;;
  esac
done

if [[ $USE_COLOR -eq 1 && -t 1 ]]; then
  R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[34m'; C=$'\e[36m'; W=$'\e[1m'; N=$'\e[0m'
else
  R=""; G=""; Y=""; B=""; C=""; W=""; N=""
fi

PASS=0; WARN=0; FAIL=0; INFO=0
IS_ROOT=0; [[ $EUID -eq 0 ]] && IS_ROOT=1

[[ -n "$REPORT" ]] && : > "$REPORT"

out() {
  printf '%b\n' "$1"
  if [[ -n "$REPORT" ]]; then
    printf '%b\n' "$1" | sed 's/\x1b\[[0-9;]*m//g' >> "$REPORT"
  fi
}

banner() {
  local art
  art=$(cat <<'BANNER'
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⠆⠀⠀⢠⡞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡾⡇⠀⠀⠀⡿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠟⣶⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣇⠹⣆⠀⢠⠃⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡏⡏⠀⠘⡼⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣦⡈⠓⢾⠀⣧⡀⠀⠀⠀⠀⠀⣤⣤⣴⣶⣦⢤⣄⡀⠀⠀⢸⠀⣧⠀⠀⢧⠘⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣿⣦⣼⠀⡿⡏⠙⠲⠤⣀⡀⠀⠈⠙⣆⠈⠓⣄⠙⢢⡀⠈⣆⠘⢇⠀⠸⡇⠘⣆⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⢻⠀⢸⣹⡀⠠⣀⠀⠉⠙⠲⢄⡈⣆⠀⠈⢣⡀⢱⣄⣸⢦⣤⣑⢄⡇⠀⠸⡆⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⡀⠘⣇⢻⣶⣌⠙⢦⡀⠀⠀⠉⠺⢦⠀⠨⡇⠀⠙⣶⣉⣴⠛⠻⠱⣄⠀⢱⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⣖⣉⣇⠀⠸⡄⠹⣌⠳⣦⡙⢶⣄⠀⠀⠀⠙⢆⣟⠀⡸⠫⢿⡜⣆⠀⠀⠘⢆⠈⡆⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣠⠽⣿⠀⠀⠹⡄⠈⢧⡈⠻⣆⠙⣧⣀⠀⠀⠀⠹⣄⡀⠀⡜⠳⣘⡄⠀⠀⠘⣇⡇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣾⣿⣛⠛⠛⠿⣦⡀⠀⠙⢤⠀⠱⣦⢽⣧⡈⢻⡇⠀⠀⢀⣹⣏⣼⡁⠀⢙⣧⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢈⡇⠀⠀⢳⡳⣀⠀⠀⢳⡄⠈⢷⣌⣷⣠⡿⣿⣫⣿⣾⣿⣄⠀⡴⠋⠙⠳⣶⣶⢬⣿⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣴⣯⣤⣤⣤⣤⣷⡈⢷⣦⡀⠙⢦⠀⣈⠛⢿⣾⣿⠋⢁⠔⠚⠻⢟⠣⠀⠔⠉⠙⢮⣙⣿⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣠⣾⠿⢭⡉⠀⠀⠀⠈⠉⠙⠛⣿⣦⡉⢿⣦⣌⢣⡈⢷⡀⡼⢿⡄⠈⠀⡠⠒⠚⠳⢄⠀⢀⠖⠙⢿⣿⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠘⠁⠀⠀⣠⣇⣠⣤⣤⣤⣤⡴⠚⢉⣿⣿⣦⡈⠙⣷⣽⣄⣿⠃⠀⠙⢷⣼⡁⠀⡀⠐⠒⠯⣉⠀⢠⠴⣿⣆⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣠⣴⡿⠛⠋⠉⠁⠉⢹⠟⠀⠀⠀⣠⣽⣿⣷⡀⠸⠿⢿⡇⠀⠀⠀⠀⢹⣷⣦⣇⠀⢀⠘⠙⠛⡇⠀⠸⣿⣿⡀⠀⠀⠀
⠀⠀⠀⠀⢀⣼⣯⣅⠀⠀⠀⠀⣀⡴⠋⠀⠐⠒⠉⠉⠉⠛⣿⣷⣄⡀⢸⣧⠀⠀⠀⠀⠀⢻⣿⣿⣿⣾⠀⠀⠀⠀⡄⠀⡇⠈⣧⠀⠀⠀
⠀⠀⠀⢀⠟⠁⠀⣸⣠⡴⠾⢿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠨⢟⣛⣿⡟⠉⢳⣄⠀⠀⠀⠀⢻⡈⠉⠻⣷⣀⠀⠀⢸⣼⣇⣧⡿⠀⠀⠀
⠀⠀⠀⠀⢀⡴⠞⠋⠀⠀⢠⠞⠀⠀⠀⠀⢀⣠⠤⢔⣾⣿⠿⠛⢿⢹⠁⠀⠀⠙⢷⡄⠀⠀⠀⠙⠻⣿⣿⡟⣟⠛⠁⣿⠀⣿⠁⠀⠀⠀
⠀⠀⠀⣰⠟⠁⠀⠀⢀⣠⠏⠀⠀⠀⣠⠖⠋⣠⣾⡟⠛⣧⠀⠀⠘⢿⡄⠀⠀⠀⠀⠳⠀⠀⠀⠀⠀⠈⢿⣇⠹⠀⠀⢸⡀⣿⠀⠀⠀⠀
⠀⠀⢰⣏⣄⠀⣠⣶⢿⠏⠀⠀⠀⠞⠁⣠⣾⡿⡏⠀⠀⠈⠳⣄⣀⣀⣻⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⢦⠀⠀⠘⢇⢹⠀⠀⠀⠀
⠀⠀⡿⠁⣰⡾⠛⠀⡜⠀⠀⠀⠀⢀⣼⡿⠃⠘⢳⡀⠀⠀⢠⠋⠳⢄⡀⠙⢦⣀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠙⠾⠀⠀⠀⠈⠋⣇⠀⠀⠀
⠀⠀⠁⣼⠛⠀⠀⣸⠃⠀⠀⠀⢀⣾⡟⣷⠀⠀⠀⠙⠒⠒⠚⢷⠖⠋⢉⡿⠋⠉⠓⢦⣄⠸⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⡆⠀⠀
⠀⠀⣸⠃⠀⢀⣴⡇⠀⠀⠀⢀⣾⡟⠉⠉⢧⡀⠀⠀⠘⣆⣀⠤⢷⣶⠟⠀⠀⠀⠀⠀⠈⠱⣄⠉⠳⢤⡀⠀⠀⠀⢰⡎⠉⠲⠄⢹⠲⡄
⠀⠀⣧⠞⣧⣾⢿⠁⠀⠀⠀⣼⡿⡁⠀⠀⠀⠈⠹⡟⠛⠙⣆⡤⣾⡟⠀⠀⠀⠀⠀⠀⠀⠀⠈⢳⡀⠀⠙⢦⡀⠀⢀⣿⣄⠀⠀⠀⠀⢸
⠀⢸⠃⣰⡟⠁⣾⠀⠀⠀⢸⣿⣤⠧⣄⠀⠀⠀⢀⣱⠤⠒⠁⢠⡿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢦⣵⡄⢻⠀⠸⡻⣿⣄⣤⠀⠀⡼
⠀⠉⢸⡟⠀⠀⡿⠀⠀⠀⣿⡇⠀⠀⠀⠉⢹⡏⠉⠈⣷⠤⠴⣿⢻⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢷⠀⢧⡀⠀⠾⠀⠀⢸⢠⠇
⠀⠀⡿⠁⠀⠀⡇⠀⠀⢰⡟⢱⣄⠀⠀⠀⠀⢣⠤⠚⠁⠀⢰⣿⠘⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠷⣄⡉⠳⢦⣀⡤⣾⡟⠀
⠀⢸⣇⡤⠤⣄⡇⠀⠀⣿⡏⠉⠈⠙⠒⡖⠒⠉⢷⡀⠀⣠⢾⡟⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠛⠉⢻⠖⠋⠀⠀
⠀⣼⠏⠀⢀⣿⡇⠀⢀⣿⡀⠀⠀⠀⠀⠙⣆⣀⠴⠋⠉⠑⢾⡇⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢹⠀⢀⣿⠏⣇⠀⢸⣿⢑⡤⣀⣀⣀⡴⠛⣇⠀⠀⠀⢀⣼⡇⠀⠸⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣼⡏⠀⣧⠀⣼⡿⠉⠀⠈⠉⢧⡀⠀⢈⡷⠒⠒⠫⣼⡇⠀⠀⢿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢠⣿⣠⢦⣿⠀⣿⣧⠀⠀⠀⠀⠀⢉⣞⠉⠀⠀⠀⠀⢸⣧⠀⠀⠈⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣿⠁⢸⣿⢰⣿⣏⡳⠤⣤⡤⠖⠉⠘⢦⡀⠀⠀⣠⡾⣿⠀⠀⠀⠸⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠋⠀⡞⣿⢸⣿⠀⠀⠀⠈⠣⡀⠀⢀⣠⠛⠉⠉⠉⠓⣿⡄⠀⠀⠀⠘⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢰⠇⡿⢸⣿⡄⠀⠀⠀⠀⢈⣽⡋⠀⠀⠀⠀⠀⠀⣿⡇⠀⠀⠀⠀⠈⢧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢿⣠⡇⢸⣿⠿⠓⠦⢶⡛⠉⠀⠙⠢⣤⣀⣀⣀⡤⣿⣿⡄⠀⠀⠀⠀⠀⠻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠸⢻⡇⣸⡇⠀⠀⠀⠀⠳⡀⠀⢀⡴⠛⠀⠀⠀⠀⠀⢸⣷⡀⠀⠀⠀⠀⠀⠹⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣾⠃⣿⡇⠀⠀⠀⠀⠀⢈⣿⣏⠀⠀⠀⠀⠀⠀⠀⢸⠿⣷⡀⠀⠀⠀⠀⠀⠈⠛⢶⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢠⡇⠀⣿⣿⣦⣤⣤⣶⠟⠁⠈⠈⠳⢤⣀⣀⣀⡤⠴⠚⠚⠛⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠳⢤⣄⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣾⠁⢸⣿⢟⠩⠃⠈⢧⠀⠀⠀⠀⢀⡼⠋⠀⠀⠀⠀⠀⠀⠀⠘⣿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⢶⡀⠀⠀⠀⠀⠀
⠀⠀⠀⢰⡿⠀⣾⡇⠀⠀⠀⠀⠈⢧⡀⠀⡰⠊⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠟⢿⣷⣄⠀⠀⠀⠀⠀⠀⣀⣀⣀⡠⠤⠤⣹⡄⠀⠀⠀⠀
⠀⣠⣴⡏⠀⢰⣿⣧⡀⠀⠀⠀⠀⠀⣹⠿⡀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡰⠯⠤⠤⠜⠛⠙⠓⠒⠛⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠴⠁⠸⢤⠴⠟⠛⠙⠛⠶⣶⡴⠖⠊⠁⠀⠙⠲⢤⣄⣀⣀⣀⣤⠴⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢳⡄⠀⠀⠀⠀⠀⣠⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠲⣴⡤⠴⠚⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
BANNER
)
  out "${C}${art}${N}"
  out ""
  out "${W}${R}  ╔══════════════════════════════════════════════════════════╗${N}"
  out "${W}${R}  ║${N}${W}          LINUX  SECURITY  AUDITOR   v${VERSION}                  ${R}║${N}"
  out "${W}${R}  ║${N}${G}          coded by ${AUTHOR}                    ${R}║${N}"
  out "${W}${R}  ║${N}${Y}          Cyber Security Engineer                         ${R}║${N}"
  out "${W}${R}  ╚══════════════════════════════════════════════════════════╝${N}"
  out ""
}

section() { out ""; out "${W}${B}[*] $1${N}"; out "${B}$(printf '%.0s─' {1..60})${N}"; }
pass()    { PASS=$((PASS+1)); out "  ${G}[ PASS ]${N} $1"; }
warn()    { WARN=$((WARN+1)); out "  ${Y}[ WARN ]${N} $1"; }
fail()    { FAIL=$((FAIL+1)); out "  ${R}[ FAIL ]${N} $1"; }
info()    { INFO=$((INFO+1)); out "  ${C}[ INFO ]${N} $1"; }
have()    { command -v "$1" >/dev/null 2>&1; }

# ---- helpers -----------------------------------------------------------------
sshd_val() {   # effective sshd setting (lowercased), falls back to config grep
  local key="$1" val=""
  if [[ $IS_ROOT -eq 1 ]] && have sshd; then
    val=$(sshd -T 2>/dev/null | awk -v k="$(echo "$key" | tr 'A-Z' 'a-z')" '$1==k{print $2; exit}')
  fi
  if [[ -z "$val" ]]; then
    val=$(grep -hiE "^\s*${key}\s+" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null \
          | awk '{print $2}' | head -n1)
  fi
  echo "$val" | tr 'A-Z' 'a-z'
}

perm_check() {  # path, max_octal_perm, expected_owner
  local f="$1" max="$2" owner="$3" p o
  [[ -e "$f" ]] || { info "$f not present"; return; }
  p=$(stat -c '%a' "$f"); o=$(stat -c '%U' "$f")
  if (( 8#$p <= 8#$max )) && [[ "$o" == "$owner" ]]; then
    pass "$f perms $p owner $o"
  else
    fail "$f perms $p owner $o (expected <= $max, owner $owner)"
  fi
}

sysctl_check() {  # key expected description
  local k="$1" exp="$2" d="$3" v
  v=$(sysctl -n "$k" 2>/dev/null)
  if [[ -z "$v" ]]; then info "$k unavailable"
  elif [[ "$v" == "$exp" ]]; then pass "$d ($k=$v)"
  else warn "$d ($k=$v, recommended $exp)"; fi
}

# ---- audit modules -----------------------------------------------------------
audit_system() {
  section "SYSTEM INFORMATION"
  info "Hostname : $(hostname 2>/dev/null)"
  info "Kernel   : $(uname -r)"
  [[ -r /etc/os-release ]] && info "OS       : $(. /etc/os-release; echo "$PRETTY_NAME")"
  info "Uptime   : $(uptime -p 2>/dev/null)"
  info "Date     : $(date)"
  if [[ $IS_ROOT -eq 1 ]]; then pass "Running as root (full audit coverage)"
  else warn "Not running as root: some checks will be limited"; fi
}

audit_users() {
  section "USERS & AUTHENTICATION"
  local uid0
  uid0=$(awk -F: '($3==0 && $1!="root"){print $1}' /etc/passwd)
  [[ -z "$uid0" ]] && pass "Only root has UID 0" || fail "Non-root UID 0 accounts: $uid0"

  if [[ -r /etc/shadow ]]; then
    local empty
    empty=$(awk -F: '($2==""){print $1}' /etc/shadow)
    [[ -z "$empty" ]] && pass "No accounts with empty passwords" || fail "Empty password accounts: $empty"
  else
    info "/etc/shadow not readable (run as root)"
  fi

  local nologin_sh
  nologin_sh=$(awk -F: '($3<1000 && $1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $7!~/(nologin|false)$/){print $1}' /etc/passwd)
  [[ -z "$nologin_sh" ]] && pass "System accounts have no login shell" || warn "System accounts with a shell: $(echo $nologin_sh)"

  local dupuid
  dupuid=$(cut -d: -f3 /etc/passwd | sort | uniq -d)
  [[ -z "$dupuid" ]] && pass "No duplicate UIDs" || fail "Duplicate UIDs: $dupuid"

  local sudoers
  sudoers=$(grep -rhE '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null)
  [[ -z "$sudoers" ]] && pass "No NOPASSWD sudo rules" || warn "NOPASSWD sudo rules present"

  if [[ -r /etc/login.defs ]]; then
    local maxd mind minl
    maxd=$(awk '/^PASS_MAX_DAYS/{print $2}' /etc/login.defs)
    mind=$(awk '/^PASS_MIN_DAYS/{print $2}' /etc/login.defs)
    [[ -n "$maxd" && "$maxd" -le 365 ]] && pass "PASS_MAX_DAYS=$maxd" || warn "PASS_MAX_DAYS=${maxd:-unset} (recommend <= 365)"
    [[ -n "$mind" && "$mind" -ge 1 ]]   && pass "PASS_MIN_DAYS=$mind" || warn "PASS_MIN_DAYS=${mind:-unset} (recommend >= 1)"
    local um
    um=$(awk '/^UMASK/{print $2}' /etc/login.defs)
    [[ "$um" =~ ^0?(27|77)$ ]] && pass "Default UMASK=$um" || warn "Default UMASK=${um:-unset} (recommend 027)"
  fi

  if grep -rqsE 'pam_(pwquality|cracklib)' /etc/pam.d/; then
    pass "Password quality module (pwquality/cracklib) configured"
  else
    warn "No password quality PAM module found"
  fi
  if grep -rqsE 'pam_(faillock|tally2)' /etc/pam.d/; then
    pass "Account lockout PAM module configured"
  else
    warn "No account lockout (faillock/tally2) configured"
  fi
  [[ -n "$TMOUT" ]] && pass "Shell TMOUT set ($TMOUT)" || info "Shell TMOUT not set in this session"
}

audit_ssh() {
  section "SSH CONFIGURATION"
  if [[ ! -f /etc/ssh/sshd_config ]]; then info "OpenSSH server not installed"; return; fi
  local v
  v=$(sshd_val PermitRootLogin)
  [[ "$v" == "no" || "$v" == "prohibit-password" || "$v" == "without-password" ]] \
    && pass "PermitRootLogin = $v" || fail "PermitRootLogin = ${v:-default(yes?)}"
  v=$(sshd_val PasswordAuthentication)
  [[ "$v" == "no" ]] && pass "PasswordAuthentication = no" || warn "PasswordAuthentication = ${v:-default(yes)} (prefer keys)"
  v=$(sshd_val PermitEmptyPasswords)
  [[ "$v" == "no" || -z "$v" ]] && pass "PermitEmptyPasswords = no" || fail "PermitEmptyPasswords = $v"
  v=$(sshd_val MaxAuthTries)
  [[ -n "$v" && "$v" -le 4 ]] && pass "MaxAuthTries = $v" || warn "MaxAuthTries = ${v:-default(6)} (recommend <= 4)"
  v=$(sshd_val X11Forwarding)
  [[ "$v" == "no" ]] && pass "X11Forwarding = no" || warn "X11Forwarding = ${v:-default}"
  v=$(sshd_val Protocol)
  [[ -z "$v" || "$v" == "2" ]] && pass "SSH protocol 2 only" || fail "SSH Protocol = $v"
  v=$(sshd_val ClientAliveInterval)
  [[ -n "$v" && "$v" -gt 0 ]] && pass "ClientAliveInterval = $v" || warn "ClientAliveInterval not set (idle sessions persist)"
  v=$(sshd_val LogLevel)
  [[ "$v" == "verbose" || "$v" == "info" ]] && pass "LogLevel = $v" || warn "LogLevel = ${v:-default}"
  v=$(sshd_val Port)
  [[ "$v" == "22" || -z "$v" ]] && info "SSH on default port 22" || info "SSH on port $v"
}

audit_files() {
  section "FILE PERMISSIONS & INTEGRITY"
  perm_check /etc/passwd 644 root
  perm_check /etc/group  644 root
  perm_check /etc/shadow 640 root
  perm_check /etc/gshadow 640 root
  perm_check /etc/ssh/sshd_config 644 root
  perm_check /etc/crontab 644 root

  if [[ $IS_ROOT -eq 1 ]]; then
    info "Scanning for world-writable files (this may take a moment)..."
    local ww
    ww=$(find / -xdev -type f -perm -0002 -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -n 20)
    [[ -z "$ww" ]] && pass "No world-writable files found" || { warn "World-writable files (first 20):"; echo "$ww" | while read -r f; do out "          $f"; done; }

    local wd
    wd=$(find / -xdev -type d -perm -0002 ! -perm -1000 -not -path '/proc/*' 2>/dev/null | head -n 10)
    [[ -z "$wd" ]] && pass "No world-writable dirs without sticky bit" || { warn "World-writable dirs without sticky bit:"; echo "$wd" | while read -r f; do out "          $f"; done; }

    local nu
    nu=$(find / -xdev \( -nouser -o -nogroup \) -not -path '/proc/*' 2>/dev/null | head -n 10)
    [[ -z "$nu" ]] && pass "No unowned files" || { warn "Unowned files found:"; echo "$nu" | while read -r f; do out "          $f"; done; }

    local suid
    suid=$(find / -xdev -type f -perm -4000 2>/dev/null | sort)
    info "SUID binaries: $(echo "$suid" | grep -c .)"
    local odd
    odd=$(echo "$suid" | grep -vE '/(sudo|su|passwd|chsh|chfn|gpasswd|newgrp|mount|umount|ping|ping6|pkexec|fusermount3?|ssh-keysign|unix_chkpwd|crontab|at|expiry|chage|dbus-daemon-launch-helper|polkit-agent-helper-1|Xorg\.wrap|pam_timestamp_check|newuidmap|newgidmap)$')
    [[ -z "$odd" ]] && pass "No unusual SUID binaries" || { warn "Review these SUID binaries:"; echo "$odd" | head -n 15 | while read -r f; do out "          $f"; done; }
  else
    info "Filesystem sweeps skipped (need root)"
  fi
}

audit_network() {
  section "NETWORK EXPOSURE"
  if have ss; then
    local l
    l=$(ss -tulnH 2>/dev/null | awk '{print $1" "$5}')
    info "Listening sockets: $(echo "$l" | grep -c .)"
    echo "$l" | while read -r line; do [[ -n "$line" ]] && out "          $line"; done
    local pub
    pub=$(ss -tlnH 2>/dev/null | awk '{print $4}' | grep -E '^(0\.0\.0\.0|\*|\[::\]|:::)' | sed 's/.*://' | sort -un | tr '\n' ' ')
    [[ -n "$pub" ]] && warn "TCP ports bound to all interfaces: $pub" || pass "No TCP services bound to all interfaces"
  elif have netstat; then
    info "Using netstat"; netstat -tuln 2>/dev/null | while read -r l; do out "          $l"; done
  else
    info "Neither ss nor netstat available"
  fi

  local fw="none"
  if have ufw && ufw status 2>/dev/null | grep -qi "active"; then fw="ufw"
  elif have firewall-cmd && firewall-cmd --state 2>/dev/null | grep -q running; then fw="firewalld"
  elif have nft && [[ $IS_ROOT -eq 1 ]] && [[ -n "$(nft list ruleset 2>/dev/null)" ]]; then fw="nftables"
  elif have iptables && [[ $IS_ROOT -eq 1 ]] && [[ $(iptables -S 2>/dev/null | wc -l) -gt 3 ]]; then fw="iptables"
  fi
  [[ "$fw" != "none" ]] && pass "Active firewall detected: $fw" || fail "No active firewall detected (or need root to verify)"

  sysctl_check net.ipv4.ip_forward 0 "IP forwarding disabled"
  sysctl_check net.ipv4.conf.all.accept_redirects 0 "ICMP redirects not accepted"
  sysctl_check net.ipv4.conf.all.send_redirects 0 "Send redirects disabled"
  sysctl_check net.ipv4.conf.all.accept_source_route 0 "Source routing disabled"
  sysctl_check net.ipv4.tcp_syncookies 1 "SYN cookies enabled"
  sysctl_check net.ipv4.conf.all.rp_filter 1 "Reverse path filtering"
  sysctl_check net.ipv4.icmp_echo_ignore_broadcasts 1 "Ignore ICMP broadcasts"
  sysctl_check net.ipv4.conf.all.log_martians 1 "Log martian packets"
}

audit_kernel() {
  section "KERNEL HARDENING"
  sysctl_check kernel.randomize_va_space 2 "ASLR fully enabled"
  sysctl_check kernel.dmesg_restrict 1 "dmesg restricted"
  sysctl_check kernel.kptr_restrict 2 "Kernel pointers hidden"
  sysctl_check fs.suid_dumpable 0 "SUID core dumps disabled"
  sysctl_check kernel.yama.ptrace_scope 1 "ptrace scope restricted"
  sysctl_check fs.protected_hardlinks 1 "Protected hardlinks"
  sysctl_check fs.protected_symlinks 1 "Protected symlinks"

  if have getenforce; then
    local se; se=$(getenforce 2>/dev/null)
    [[ "$se" == "Enforcing" ]] && pass "SELinux Enforcing" || warn "SELinux is $se"
  elif have aa-status && [[ $IS_ROOT -eq 1 ]]; then
    aa-status --enabled 2>/dev/null && pass "AppArmor enabled" || warn "AppArmor not enabled"
  elif [[ -d /sys/kernel/security/apparmor ]]; then
    pass "AppArmor present"
  else
    warn "No mandatory access control (SELinux/AppArmor) detected"
  fi

  if [[ -d /sys/firmware/efi ]]; then
    have mokutil && mokutil --sb-state 2>/dev/null | grep -qi enabled && pass "Secure Boot enabled" || info "UEFI system; Secure Boot state unknown/disabled"
  else
    info "Legacy BIOS boot (no Secure Boot)"
  fi

  local m
  for m in cramfs freevxfs jffs2 hfs hfsplus udf usb-storage; do
    if lsmod 2>/dev/null | grep -qw "${m//-/_}"; then warn "Kernel module loaded: $m"; fi
  done
}

audit_mounts() {
  section "FILESYSTEM MOUNT OPTIONS"
  local mp
  for mp in /tmp /var/tmp /dev/shm /home; do
    if findmnt -n "$mp" >/dev/null 2>&1; then
      local opts; opts=$(findmnt -n -o OPTIONS "$mp")
      local miss=""
      [[ "$mp" != "/home" && "$opts" != *noexec* ]] && miss+="noexec "
      [[ "$opts" != *nosuid* ]] && miss+="nosuid "
      [[ "$mp" != "/home" && "$opts" != *nodev* ]] && miss+="nodev "
      [[ -z "$miss" ]] && pass "$mp mounted with hardened options" || warn "$mp missing options: $miss"
    else
      info "$mp is not a separate mount"
    fi
  done
}

audit_services() {
  section "SERVICES & PACKAGES"
  local bad="telnet telnetd rsh-server rsh-client rlogin talk tftp tftp-server xinetd ypserv nis vsftpd squid avahi-daemon cups"
  local found=""
  for s in $bad; do
    if have systemctl && systemctl is-active --quiet "$s" 2>/dev/null; then found+="$s(active) "; fi
    if have dpkg && dpkg -s "$s" >/dev/null 2>&1; then found+="$s(pkg) "; fi
    if have rpm  && rpm -q "$s" >/dev/null 2>&1; then found+="$s(pkg) "; fi
  done
  [[ -z "$found" ]] && pass "No insecure/legacy services detected" || warn "Review legacy/unneeded services: $found"

  if have systemctl; then
    local cnt; cnt=$(systemctl list-units --type=service --state=running --no-legend 2>/dev/null | wc -l)
    info "Running services: $cnt"
  fi

  for svc in fail2ban auditd rsyslog syslog-ng chronyd ntpd systemd-timesyncd; do
    have systemctl && systemctl is-active --quiet "$svc" 2>/dev/null && info "Active: $svc"
  done
  have systemctl && {
    systemctl is-active --quiet fail2ban 2>/dev/null && pass "fail2ban running" || warn "fail2ban not running"
    systemctl is-active --quiet auditd 2>/dev/null && pass "auditd running" || warn "auditd not running (no audit trail)"
    if systemctl is-active --quiet rsyslog 2>/dev/null || systemctl is-active --quiet syslog-ng 2>/dev/null || systemctl is-active --quiet systemd-journald 2>/dev/null; then
      pass "System logging active"
    else
      fail "No system logging service active"
    fi
    if systemctl is-active --quiet chronyd 2>/dev/null || systemctl is-active --quiet ntpd 2>/dev/null || systemctl is-active --quiet systemd-timesyncd 2>/dev/null; then
      pass "Time synchronization active"
    else
      warn "No time synchronization service active"
    fi
  }
}

audit_updates() {
  section "PATCH STATUS"
  if have apt-get; then
    local n
    n=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst')
    [[ "$n" -eq 0 ]] && pass "No pending apt upgrades (per local cache)" || warn "$n package(s) pending upgrade (apt)"
    local sec
    sec=$(apt-get -s upgrade 2>/dev/null | grep '^Inst' | grep -ci security)
    [[ "$sec" -gt 0 ]] && fail "$sec pending SECURITY update(s)"
  elif have dnf; then
    local n; n=$(dnf -q check-update --security 2>/dev/null | grep -cE '^[A-Za-z0-9]')
    [[ "$n" -eq 0 ]] && pass "No pending security updates (dnf)" || fail "$n pending security update(s) (dnf)"
  elif have yum; then
    local n; n=$(yum -q check-update --security 2>/dev/null | grep -cE '^[A-Za-z0-9]')
    [[ "$n" -eq 0 ]] && pass "No pending security updates (yum)" || fail "$n pending security update(s) (yum)"
  else
    info "No supported package manager detected"
  fi
  [[ -f /var/run/reboot-required ]] && warn "System reboot required to apply updates" || pass "No reboot pending"
}

audit_cron() {
  section "SCHEDULED TASKS & PERSISTENCE"
  local f
  for f in /etc/cron.allow /etc/at.allow; do
    [[ -f "$f" ]] && pass "$f exists (restricted scheduling)" || info "$f not present"
  done
  local ww
  ww=$(find /etc/cron* /var/spool/cron -type f -perm -0002 2>/dev/null)
  [[ -z "$ww" ]] && pass "No world-writable cron files" || fail "World-writable cron files: $ww"

  if [[ $IS_ROOT -eq 1 ]]; then
    local ak
    ak=$(find /home /root -maxdepth 3 -name authorized_keys 2>/dev/null)
    [[ -n "$ak" ]] && info "authorized_keys files: $(echo "$ak" | tr '\n' ' ')" || info "No authorized_keys found"
    local rc
    rc=$(find /home /root -maxdepth 2 \( -name .rhosts -o -name .netrc -o -name .shosts \) 2>/dev/null)
    [[ -z "$rc" ]] && pass "No .rhosts/.netrc/.shosts files" || warn "Legacy trust files: $rc"
  fi
}

audit_logging() {
  section "LOGS & AUTH ACTIVITY"
  local log
  for log in /var/log/auth.log /var/log/secure; do
    if [[ -r "$log" ]]; then
      local fails
      fails=$(grep -ci "failed password" "$log" 2>/dev/null)
      [[ "$fails" -gt 50 ]] && warn "$fails failed password attempts in $log" || info "$fails failed password attempts in $log"
      local top
      top=$(grep -i "failed password" "$log" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | head -n 3)
      [[ -n "$top" ]] && { info "Top offending IPs:"; echo "$top" | while read -r l; do out "          $l"; done; }
    fi
  done
  have lastb && [[ $IS_ROOT -eq 1 ]] && info "Recent bad logins: $(lastb 2>/dev/null | grep -vc -e '^$' -e btmp)"
  [[ -d /var/log/journal ]] && pass "Persistent journald storage" || info "journald logs are volatile"
}

summary() {
  section "AUDIT SUMMARY"
  local total=$((PASS+WARN+FAIL))
  local score=0
  [[ $total -gt 0 ]] && score=$(( (PASS*100 + WARN*50) / total ))
  out "  ${G}Passed  : $PASS${N}"
  out "  ${Y}Warnings: $WARN${N}"
  out "  ${R}Failed  : $FAIL${N}"
  out "  ${C}Info    : $INFO${N}"
  out ""
  local grade col
  if   [[ $score -ge 90 ]]; then grade="A (Excellent)"; col=$G
  elif [[ $score -ge 75 ]]; then grade="B (Good)";      col=$G
  elif [[ $score -ge 60 ]]; then grade="C (Fair)";      col=$Y
  elif [[ $score -ge 40 ]]; then grade="D (Poor)";      col=$R
  else grade="F (Critical)"; col=$R; fi
  out "  ${W}Hardening score: ${col}${score}/100  Grade ${grade}${N}"
  out ""
  out "  ${C}Fix FAIL items first, then WARN items. This tool is read-only.${N}"
  [[ -n "$REPORT" ]] && out "  ${C}Report saved to: $REPORT${N}"
  out ""
  out "  ${G}Linux Security Auditor — coded by ${AUTHOR}${N}"
  out ""
}

# ---- main ---------------------------------------------------------------------
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This tool is for Linux systems only."; exit 1
fi

banner
audit_system
audit_users
audit_ssh
audit_files
audit_network
audit_kernel
audit_mounts
audit_services
audit_updates
audit_cron
audit_logging
summary

[[ $FAIL -gt 0 ]] && exit 2
exit 0
