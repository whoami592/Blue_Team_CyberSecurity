#!/usr/bin/env bash
# ==============================================================================
#  PhishGuard - Phishing Link & Malicious Content Detection Bot
#  Coded by Mr Sabaz Ali Khan | Cyber Security Engineer
#
#  Defensive tool. Scans URLs, text, emails, HTML and files for phishing and
#  malicious-content indicators using heuristic scoring. Includes bot modes
#  (interactive, directory watcher, feed tailer) with webhook/Telegram alerts.
# ==============================================================================

set -o pipefail

VERSION="1.0"
AUTHOR="Mr Sabaz Ali Khan"

LOG_DIR="${PHISHGUARD_LOG_DIR:-./phishguard_logs}"
LOG_FILE="$LOG_DIR/detections.csv"
QUARANTINE_DIR="$LOG_DIR/quarantine"
TIMEOUT=10
UA="Mozilla/5.0 (X11; Linux x86_64) PhishGuard/$VERSION"
ONLINE=false
QUARANTINE=false
INTERVAL=5

# ---------- colors ----------
if [[ -t 1 ]]; then
  RED=$'\e[1;31m'; GRN=$'\e[1;32m'; YEL=$'\e[1;33m'; CYN=$'\e[1;36m'
  BLU=$'\e[1;34m'; DIM=$'\e[2m'; RST=$'\e[0m'
else
  RED=""; GRN=""; YEL=""; CYN=""; BLU=""; DIM=""; RST=""
fi

# ---------- banner ----------
banner() {
  printf '%s' "$CYN"
  cat <<'BANNER'
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣤⣴⣶⠶⠶⠖⠚⠛⠛⠛⠛⠒⠶⠶⣶⣶⣤⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣴⡾⠟⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠙⠛⠷⣶⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⡾⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠿⣶⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⡾⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⢿⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣴⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣷⣄⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣰⣿⠋⠀⠀⠀⠀⢀⣠⣴⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠴⣒⡽⠟⣩⠏⢩⠉⢏⠙⠯⣑⠲⠦⣄⡀⠀⠀⠀⠀⠀⠀⠙⢶⣤⡀⠀⠀⠀⠀⠈⢿⣦⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣴⡟⠁⠀⠀⣠⢄⣶⣿⠟⠁⠀⠀⠀⠀⢀⣴⠞⠋⠀⣠⠞⠁⠀⣰⠋⠀⣼⠀⠀⢧⡀⠈⠙⢦⡀⠉⠓⠦⣀⡀⠀⠀⠀⠀⠹⣿⣷⣤⢤⡀⠀⠀⠹⣷⡀⠀⠀⠀⠀
⠀⠀⠀⢀⣾⠟⠀⠀⣴⡟⢠⣿⡿⢋⡄⠀⠀⠀⣠⠞⠃⠤⢄⣀⠞⠁⠀⠀⢰⡏⠀⠀⠿⠀⠀⠘⣧⠀⠀⠀⠙⣆⣀⠤⠄⠛⢦⡀⠀⠀⠐⡜⢿⣿⣆⢻⣦⡀⠀⠘⣿⡄⠀⠀⠀
⠀⠀⢀⣾⠏⠀⡠⣸⣿⠇⡾⢋⣴⡟⠀⠀⢠⠞⠃⠀⠀⠀⢠⠟⠙⠒⠒⠤⡞⠀⣤⣤⠶⣤⣤⡀⠘⠀⠐⠒⠊⠙⣧⠀⠀⠀⠀⠙⣄⠀⠀⠹⣶⣝⠻⡄⣿⣷⢠⡀⠘⣿⡄⠀⠀
⠀⠀⣼⠟⠀⣼⠁⣿⡟⣠⣾⣿⠟⠁⠀⡴⠋⠀⠀⠀⠀⢠⠏⠀⠀⠀⠀⠀⡇⠀⢻⣿⢶⢸⣿⡇⠀⠀⠀⠀⠀⠀⠘⣧⠀⠀⠀⠀⠈⢳⡀⠀⠙⢿⣷⣄⢸⣿⡇⣷⡀⠘⣿⡄⠀
⠀⣸⡿⠀⢸⣿⠀⣿⣽⡿⢋⡵⠀⢀⡾⠁⠀⠀⠀⠀⠀⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡾⠛⠁⠀⠀⠀⠀⠀⠀⠀⠸⡆⠀⠀⠀⠀⠀⠹⡄⠀⠸⣏⠿⣷⣿⠃⣿⣷⠀⢹⣧⠀
⠀⣿⠇⠀⣼⣿⡇⣼⢋⣴⡿⠁⠀⡼⠀⠉⠒⠶⠦⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠼⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⡀⠤⠴⠂⠈⠀⢹⡀⠀⢹⣷⣌⢻⡄⣿⣿⠀⠀⢿⡄
⢸⡟⠀⣴⢹⣿⡇⣱⣿⡿⠁⠀⣰⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⢴⣿⡷⠤⠀⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣷⠀⠀⣻⣿⣷⡀⣿⣿⠀⠀⢸⡇
⢸⡇⠀⣿⠘⣿⣿⣿⠏⣰⠀⠀⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⡆⠀⢻⠙⢿⣧⣿⡇⢠⡇⠀⣿
⣾⠁⠸⣿⡄⠹⡿⠃⣴⡟⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣾⣯⣿⣭⣥⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⢸⣧⠈⢻⡿⠀⣾⡇⠀⣿
⣿⠀⠀⣿⣷⡀⠇⣼⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⣿⡇⠀⢨⣿⣇⠀⠀⣿⣶⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡁⠀⠸⣿⣷⡈⠇⣼⣿⠇⠀⣿
⢿⡄⢀⢻⣿⣷⢸⣿⡟⢀⠀⠀⡄⠀⠀⠀⠀⠀⠀⠀⢠⣶⣶⣾⣿⣿⣿⣿⡿⠀⠀⠉⣿⡈⠀⠀⢹⣿⣿⣿⣿⣿⣶⣶⡄⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⢠⠸⣿⡇⣰⣿⡿⠀⠀⣿
⢸⡇⢸⡄⠻⣿⣼⣿⠁⣸⠀⠀⣷⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣷⠀⠀⢰⣿⡇⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⢸⠇⠀⣼⡀⢿⡇⣿⡟⢁⡇⠀⣿
⢸⣧⠀⣿⣄⠘⢿⡟⢠⣿⡇⠀⠹⡆⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀⢸⣿⡇⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀⠀⠀⠀⠀⢀⡿⠀⢀⣿⡇⢸⣿⠟⢠⣾⠇⢸⡇
⠀⣿⡄⠙⣿⣷⣌⠓⢸⣿⡗⢄⠀⢱⡀⣀⣤⠴⠖⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣄⢸⣿⡇⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⠓⠶⢤⣄⣀⣼⠁⢠⣾⣿⣧⠸⢁⣶⣿⠟⠀⣾⠃
⠀⢹⣷⠀⠈⢿⣿⣷⡸⣿⡇⠘⣦⡀⢣⡀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣿⣷⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠀⠀⠀⠀⣸⠃⣰⡏⢸⣿⡏⣴⣿⣿⠋⠀⣸⡿⠀
⠀⠀⢻⣦⠘⣦⠙⠿⣷⣿⣿⠀⣿⣧⠀⠳⡄⠀⠀⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⢀⡼⠁⣰⣿⠁⢸⣟⣼⡿⠛⣁⠇⢠⣿⠃⠀
⠀⠀⠈⢿⣆⠘⢿⣦⣈⠙⠿⣇⢸⣿⣧⢀⠈⠂⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠠⠋⢀⣠⣿⡿⢠⠿⠛⢁⣠⣶⠏⢠⣿⠃⠀⠀
⠀⠀⠀⠈⢿⣆⠈⠻⣿⣷⣶⣬⡀⢻⣿⡎⢳⣄⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⣠⡶⢋⣿⣿⢁⣡⣴⣶⣿⠿⠃⢠⣾⠋⠀⠀⠀
⠀⠀⠀⠀⠈⢻⣧⡀⠈⢙⠿⣿⣿⣷⣿⣷⡄⢿⣷⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢁⣼⣿⣵⣿⣿⠿⢟⠁⠀⣰⣿⠃⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠹⣷⣄⠈⢳⣤⣈⣉⠉⠙⠛⠆⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠱⠞⠛⠉⣉⣁⣠⡴⠃⢀⣴⡟⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠻⣦⡀⠈⠛⠿⣿⣿⣿⣿⣿⣿⣶⡿⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⢿⣷⣾⣿⣿⣿⣿⣿⠿⠟⠋⢀⣴⡿⠋⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠻⣦⣄⠀⠰⣬⣉⣉⣉⣉⣀⣤⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣤⣀⣉⣉⣉⣉⣩⠴⠀⢀⣴⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣷⣤⡈⠙⠛⠿⠿⢿⠿⠿⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠻⠿⠿⠿⠿⠟⠛⠁⣠⣶⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠿⣷⣦⣀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠀⠀⠀⠀⢀⣠⣶⠿⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠿⢶⣤⣄⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣀⣤⣴⠾⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠛⠛⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠿⠟⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
BANNER
  printf '%s' "$RST"
  printf '%s\n' "${YEL}  ╔══════════════════════════════════════════════════════════════╗${RST}"
  printf '%s\n' "${YEL}  ║${RST}  ${GRN}PhishGuard v$VERSION${RST} - Phishing Link & Malicious Content Bot     ${YEL}║${RST}"
  printf '%s\n' "${YEL}  ║${RST}  ${CYN}Coded by $AUTHOR${RST} | Cyber Security Engineer        ${YEL}║${RST}"
  printf '%s\n' "${YEL}  ╚══════════════════════════════════════════════════════════════╝${RST}"
  echo
}

usage() {
  cat <<EOF
Usage: $0 [options] <mode>

Scan modes:
  -u, --url URL            Analyze a single URL
  -f, --file FILE          Scan a file (email, HTML, script, text): URLs + content
  -l, --list FILE          Analyze a file containing one URL per line
  -s, --stdin              Read URLs from stdin (e.g. cat urls.txt | $0 -s)

Bot modes:
  -i, --interactive        Interactive bot prompt (paste URLs/text to check)
  -w, --watch DIR          Watch a directory; auto-scan every new/modified file
  -t, --tail FILE          Tail a feed file; analyze every new line (URLs/messages)

Options:
  -o, --online             Enable live checks (redirects, TLS, page content) via curl
  -q, --quarantine         Move flagged files (watch mode) into quarantine dir
  -n, --interval SEC       Poll interval for --watch (default $INTERVAL)
  -d, --log-dir DIR        Log directory (default $LOG_DIR)
  -h, --help               Show this help

Alerts (optional, environment variables):
  ALERT_WEBHOOK            Slack/Discord/generic JSON webhook URL
  TG_TOKEN, TG_CHAT        Telegram bot token and chat id

Verdict scale:  0-29 LIKELY SAFE | 30-59 SUSPICIOUS | 60+ PHISHING / MALICIOUS
EOF
}

# ---------- scoring state ----------
SCORE=0
REASONS=()
TOTAL=0
FLAGGED=0

add() { SCORE=$((SCORE + $1)); REASONS+=("[+$1] $2"); }

verdict() {
  local s="$1"
  if   (( s >= 60 )); then V="PHISHING / MALICIOUS"; VC="$RED"
  elif (( s >= 30 )); then V="SUSPICIOUS";           VC="$YEL"
  else                     V="LIKELY SAFE";          VC="$GRN"
  fi
}

# ---------- reference data ----------
BRANDS=(
  "paypal:paypal.com"
  "google:google.com|google.co.uk|googleapis.com|gstatic.com"
  "gmail:gmail.com"
  "microsoft:microsoft.com|live.com|microsoftonline.com|office.com|outlook.com"
  "office365:office.com|microsoft.com"
  "apple:apple.com|icloud.com"
  "icloud:icloud.com|apple.com"
  "amazon:amazon.com|amazon.co.uk|amazonaws.com"
  "facebook:facebook.com|fb.com"
  "instagram:instagram.com"
  "whatsapp:whatsapp.com|whatsapp.net"
  "netflix:netflix.com"
  "linkedin:linkedin.com"
  "twitter:twitter.com|x.com"
  "dropbox:dropbox.com"
  "binance:binance.com"
  "coinbase:coinbase.com"
  "metamask:metamask.io"
  "dhl:dhl.com"
  "fedex:fedex.com"
  "paytm:paytm.com"
  "easypaisa:easypaisa.com.pk"
  "jazzcash:jazzcash.com.pk"
  "hbl:hbl.com"
  "github:github.com"
)
SHORTENERS="bit.ly tinyurl.com t.co goo.gl ow.ly is.gd buff.ly rebrand.ly cutt.ly shorturl.at tiny.cc rb.gy t.ly bl.ink lnkd.in"
BAD_TLDS="zip mov tk ml ga cf gq xyz top click work support icu rest country buzz monster cyou cam loan men"
KEYWORDS="login signin sign-in verify verification account secure security update confirm banking password wallet suspend suspended unlock billing invoice payment authenticate recovery webscr"

reg_domain() {
  local IFS=.
  local -a p
  read -ra p <<<"$1"
  local n=${#p[@]}
  if (( n <= 2 )); then echo "$1"; return; fi
  local sl="${p[n-2]}" tl="${p[n-1]}"
  if [[ ${#tl} -eq 2 && "$sl" =~ ^(co|com|org|net|gov|edu|ac)$ ]]; then
    echo "${p[n-3]}.$sl.$tl"
  else
    echo "$sl.$tl"
  fi
}

brand_check() {
  local host="$1" reg norm entry b legit
  reg=$(reg_domain "$host")
  norm="${host//0/o}"; norm="${norm//1/l}"; norm="${norm//rn/m}"
  norm="${norm//vv/w}"; norm="${norm//5/s}"
  for entry in "${BRANDS[@]}"; do
    b="${entry%%:*}"; legit="${entry#*:}"
    if [[ "$norm" == *"$b"* ]]; then
      if ! [[ "$reg" =~ ^($legit)$ ]]; then
        echo "$b"; return 0
      fi
    fi
  done
  return 1
}

# ---------- URL analysis ----------
analyze_url() {
  local raw="$1" url scheme u auth host port path query reg tld kw hits n
  SCORE=0; REASONS=()
  url="${raw%%[[:space:]]*}"
  url="${url%[.,;:!?\)\]\>\"\']}"

  case "${url,,}" in
    javascript:*) add 50 "javascript: URI scheme (script execution)";  return ;;
    data:text/html*|data:*base64*) add 50 "data: URI payload (embedded content)"; return ;;
  esac

  if [[ "$url" =~ ^[a-zA-Z][a-zA-Z0-9+.-]*:// ]]; then
    scheme="${url%%://*}"; scheme="${scheme,,}"; u="${url#*://}"
  else
    scheme="none"; u="$url"
  fi

  auth="${u%%[/?#]*}"
  path="${u#"$auth"}"
  query=""; [[ "$path" == *\?* ]] && query="${path#*\?}"
  path="${path%%\?*}"; path="${path%%#*}"

  [[ "$auth" == *@* ]] && add 30 "'@' in authority (credentials trick hides real host)"
  host="${auth##*@}"
  port=""
  if [[ "$host" == *:* ]]; then port="${host##*:}"; host="${host%%:*}"; fi
  host="${host,,}"

  [[ "$scheme" == "http" ]] && add 10 "Unencrypted HTTP"
  [[ -n "$port" && "$port" != "80" && "$port" != "443" ]] && add 8 "Non-standard port ($port)"

  if [[ "$host" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
    add 35 "IP address used instead of a domain"
  elif [[ "$host" =~ ^(0x[0-9a-f]+|[0-9]{8,10})$ ]]; then
    add 35 "Obfuscated (hex/decimal) IP address"
  else
    reg=$(reg_domain "$host")
    tl_check=true
    n="${host//[^.]/}"
    (( ${#n} >= 4 )) && add 10 "Excessive subdomains (${#n} dots)"

    [[ "$host" == *xn--* ]] && add 25 "Punycode / IDN homograph domain"
    [[ "$host" =~ [^a-z0-9.-] ]] && add 20 "Non-ASCII or unusual characters in host"

    tld="${host##*.}"
    for t in $BAD_TLDS; do
      [[ "$tld" == "$t" ]] && { add 15 "High-abuse TLD (.$tld)"; break; }
    done
    for s in $SHORTENERS; do
      [[ "$reg" == "$s" ]] && { add 15 "URL shortener ($s) hides destination"; break; }
    done

    n="${host//[^-]/}"
    (( ${#n} >= 3 )) && add 10 "Many hyphens in hostname (${#n})"
    n="${host//[^0-9]/}"
    (( ${#n} >= 5 )) && add 8 "Many digits in hostname"

    hits=0
    for kw in $KEYWORDS; do [[ "$host" == *"$kw"* ]] && hits=$((hits+1)); done
    (( hits > 0 )) && add $(( hits > 3 ? 36 : hits * 12 )) "Phishing keywords in hostname ($hits)"

    if b=$(brand_check "$host"); then
      add 35 "Brand impersonation: '$b' not on its legitimate domain (registered: $reg)"
    fi
  fi

  hits=0
  local lpath="${path,,}${query,,}"
  for kw in $KEYWORDS; do [[ "$lpath" == *"$kw"* ]] && hits=$((hits+1)); done
  (( hits > 0 )) && add $(( hits * 5 > 15 ? 15 : hits * 5 )) "Phishing keywords in path/query ($hits)"

  (( ${#url} > 120 )) && add 10 "Very long URL (${#url} chars)"
  (( ${#url} > 75 && ${#url} <= 120 )) && add 8 "Long URL (${#url} chars)"

  n=$(grep -Eo '%[0-9a-fA-F]{2}' <<<"$url" | wc -l)
  (( n >= 3 )) && add 8 "Heavy percent-encoding ($n sequences)"
  [[ "$path" == *"//"* ]] && add 5 "Double slash inside path"
  [[ "${query,,}" =~ (redirect|url|next|goto|return)=https?(:|%3a) ]] && add 15 "Open-redirect style parameter"

  if [[ "${path,,}" =~ \.(pdf|docx?|xlsx?|jpe?g|png|txt)\.(exe|scr|js|bat|vbs|cmd|hta)$ ]]; then
    add 30 "Double file extension (disguised executable)"
  elif [[ "${path,,}" =~ \.(exe|scr|bat|cmd|js|vbs|hta|jar|msi|ps1|apk|iso|lnk|dll)$ ]]; then
    add 25 "Direct link to executable/script download"
  fi
}

# ---------- content analysis (HTML / email / script / text) ----------
content_scan() {
  local f="$1"
  chk() { grep -Eiaq -- "$1" "$f" 2>/dev/null && add "$2" "$3"; }

  chk "<input[^>]*type=[\"']?password"                               20 "Password input field (credential harvesting form)"
  chk "<iframe[^>]*(width|height)=[\"']?[01][\"' >]"                 25 "Hidden/zero-size iframe"
  chk "eval\(|atob\(|unescape\(|String\.fromCharCode|document\.write\(unescape" 20 "Obfuscated JavaScript (eval/atob/unescape)"
  chk "<meta[^>]*http-equiv=[\"']?refresh"                          10 "Meta-refresh redirect"
  chk "<form[^>]*action=[\"']?https?://"                             10 "Form posts to external URL"
  chk "oncontextmenu=[\"']?return false"                              8 "Right-click disabled (anti-inspection)"
  chk "href=[\"']?javascript:"                                       15 "javascript: link"
  chk "data:text/html(;base64)?,"                                    25 "Embedded data:text/html payload"
  chk "verify your (account|identity)|account (has been )?(suspended|locked|limited)|urgent action|within 24 hours|confirm your identity|unusual (sign.?in|activity)" 15 "Urgency / account-threat language"
  chk "(seed phrase|recovery phrase|private key|12.word)"            20 "Requests wallet seed/private key"
  chk "(sendBeacon|XMLHttpRequest|fetch\().*(password|passwd|pwd)"   15 "Script sends password field data"
  chk "powershell(\.exe)?[^|]*(-enc|-encodedcommand|-w(indowstyle)? hidden|downloadstring|iex|invoke-expression)" 40 "Malicious PowerShell pattern"
  chk "certutil[^|]*-urlcache|bitsadmin[^|]*/transfer|mshta(\.exe)?[[:space:]]+(https?|vbscript|javascript)|regsvr32[^|]*/i:http" 40 "Living-off-the-land download/exec (LOLBin)"
  chk "wscript\.shell|cscript[[:space:]]|cmd(\.exe)?[[:space:]]+/c[[:space:]]" 20 "Script host / shell execution"
  chk "AutoOpen|Document_Open|Workbook_Open|CreateObject\(\"WScript\.Shell\"\)" 35 "Office macro auto-execution"
  chk "[A-Za-z0-9+/]{200,}={0,2}"                                    12 "Large base64 blob (possible embedded payload)"
  chk "\.(pdf|docx?|xlsx?)\.(exe|scr|js|bat|vbs)"                    35 "Double-extension attachment reference"
  chk "(wget|curl)[^|;]*\|[[:space:]]*(ba)?sh"                       35 "Remote script piped to shell"
}

# ---------- live checks ----------
online_check() {
  local url="$1" tmp out code final redirs ssl ohost fhost
  command -v curl >/dev/null 2>&1 || { REASONS+=("[i] curl not found - online checks skipped"); return; }
  [[ "$url" =~ ^[a-zA-Z][a-zA-Z0-9+.-]*:// ]] || url="http://$url"
  tmp=$(mktemp)
  out=$(curl -sL -m "$TIMEOUT" --max-redirs 6 --max-filesize 3000000 -A "$UA" \
        -o "$tmp" -w '%{http_code}|%{url_effective}|%{num_redirects}|%{ssl_verify_result}' "$url" 2>/dev/null)
  IFS='|' read -r code final redirs ssl <<<"$out"
  if [[ -z "$code" || "$code" == "000" ]]; then
    REASONS+=("[i] Host unreachable / no response (offline, blocked, or taken down)")
    rm -f "$tmp"; return
  fi
  REASONS+=("[i] HTTP $code, $redirs redirect(s), final: $final")
  (( redirs >= 3 )) && add 10 "Long redirect chain ($redirs hops)"
  ohost=$(reg_domain "$(sed -E 's#^[a-z]+://##; s#[/?#:].*##' <<<"${url,,}")")
  fhost=$(reg_domain "$(sed -E 's#^[a-z]+://##; s#[/?#:].*##' <<<"${final,,}")")
  [[ -n "$fhost" && "$ohost" != "$fhost" ]] && add 10 "Redirects to a different domain ($fhost)"
  [[ "$final" == https://* && "$ssl" != "0" && -n "$ssl" ]] && add 20 "TLS certificate failed verification"
  content_scan "$tmp"
  rm -f "$tmp"
}

# ---------- reporting / alerts ----------
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/\\n}"
  printf '%s' "$s"
}

send_alert() {
  local msg="$1"
  if [[ -n "${ALERT_WEBHOOK:-}" ]]; then
    curl -s -m 8 -H 'Content-Type: application/json' \
      -d "{\"text\":\"$(json_escape "$msg")\",\"content\":\"$(json_escape "$msg")\"}" \
      "$ALERT_WEBHOOK" >/dev/null 2>&1
  fi
  if [[ -n "${TG_TOKEN:-}" && -n "${TG_CHAT:-}" ]]; then
    curl -s -m 8 "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
      --data-urlencode "chat_id=$TG_CHAT" --data-urlencode "text=$msg" >/dev/null 2>&1
  fi
}

report() {
  local kind="$1" target="$2" r
  verdict "$SCORE"
  TOTAL=$((TOTAL + 1))
  echo "${BLU}[$kind]${RST} $target"
  echo "   Risk score : ${VC}${SCORE}${RST}   Verdict : ${VC}${V}${RST}"
  if (( ${#REASONS[@]} > 0 )); then
    for r in "${REASONS[@]}"; do echo "   ${DIM}-${RST} $r"; done
  else
    echo "   ${DIM}- no indicators found${RST}"
  fi
  echo

  mkdir -p "$LOG_DIR"
  [[ -f "$LOG_FILE" ]] || echo "timestamp,type,target,score,verdict" >"$LOG_FILE"
  printf '%s,%s,"%s",%s,%s\n' "$(date '+%F %T')" "$kind" "${target//\"/\'}" "$SCORE" "$V" >>"$LOG_FILE"

  if (( SCORE >= 30 )); then
    FLAGGED=$((FLAGGED + 1))
    send_alert "PhishGuard ALERT [$V] score=$SCORE $kind: $target"
  fi
}

# ---------- handlers ----------
handle_url() {
  analyze_url "$1"
  $ONLINE && online_check "$1"
  report "URL" "$1"
}

extract_urls() {
  grep -Eoa "(https?|ftp)://[^[:space:]<>\"')]+|www\.[^[:space:]<>\"')]+" "$1" 2>/dev/null | sort -u
}

handle_file() {
  local f="$1" url
  [[ -f "$f" ]] || { echo "${RED}File not found: $f${RST}"; return 1; }
  SCORE=0; REASONS=()
  content_scan "$f"
  report "FILE" "$f"
  local file_score=$SCORE
  while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    handle_url "$url"
  done < <(extract_urls "$f")
  return $(( file_score >= 60 ? 2 : 0 ))
}

handle_text() {
  local text="$1" tmp url found=false
  tmp=$(mktemp); printf '%s\n' "$text" >"$tmp"
  while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    found=true; handle_url "$url"
  done < <(extract_urls "$tmp")
  if ! $found && [[ "$text" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}(/.*)?$ ]]; then
    found=true; handle_url "$text"
  fi
  SCORE=0; REASONS=()
  content_scan "$tmp"
  (( SCORE > 0 )) && report "TEXT" "${text:0:80}"
  $found || (( SCORE > 0 )) || echo "${GRN}No URLs or suspicious content detected.${RST}\n"
  rm -f "$tmp"
}

# ---------- bot modes ----------
interactive_bot() {
  echo "${GRN}PhishGuard bot ready.${RST} Paste a URL or message. Type ${YEL}exit${RST} to quit."
  local line
  while true; do
    read -r -p "${CYN}phishguard>${RST} " line || break
    [[ "$line" == "exit" || "$line" == "quit" ]] && break
    [[ -z "$line" ]] && continue
    handle_text "$line"
  done
}

watch_dir() {
  local dir="$1" marker f
  [[ -d "$dir" ]] || { echo "${RED}Not a directory: $dir${RST}"; exit 1; }
  marker=$(mktemp)
  echo "${GRN}Watching${RST} $dir every ${INTERVAL}s  (Ctrl-C to stop)"
  trap 'rm -f "$marker"; echo; summary; exit 0' INT TERM
  while true; do
    while IFS= read -r -d '' f; do
      [[ "$f" == "$LOG_DIR"* ]] && continue
      echo "${YEL}[new]${RST} $f"
      handle_file "$f"
      rc=$?
      if $QUARANTINE && (( rc == 2 )); then
        mkdir -p "$QUARANTINE_DIR"
        mv -- "$f" "$QUARANTINE_DIR/$(basename "$f").$(date +%s).quarantined" \
          && chmod 000 "$QUARANTINE_DIR"/*.quarantined 2>/dev/null \
          && echo "${RED}   -> quarantined${RST}"
      fi
    done < <(find "$dir" -type f -newer "$marker" -print0 2>/dev/null)
    touch "$marker"
    sleep "$INTERVAL"
  done
}

tail_feed() {
  local file="$1" line
  [[ -f "$file" ]] || : >"$file"
  echo "${GRN}Tailing${RST} $file  (Ctrl-C to stop)"
  trap 'echo; summary; exit 0' INT TERM
  tail -n0 -F "$file" 2>/dev/null | while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    handle_text "$line"
  done
}

summary() {
  echo "${CYN}Summary:${RST} analyzed=$TOTAL flagged=$FLAGGED log=$LOG_FILE"
}

# ---------- argument parsing ----------
MODE=""; ARG=""
if [[ $# -eq 0 ]]; then banner; usage; exit 0; fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    -u|--url)         MODE=url;   ARG="$2"; shift 2 ;;
    -f|--file)        MODE=file;  ARG="$2"; shift 2 ;;
    -l|--list)        MODE=list;  ARG="$2"; shift 2 ;;
    -s|--stdin)       MODE=stdin; shift ;;
    -i|--interactive) MODE=inter; shift ;;
    -w|--watch)       MODE=watch; ARG="$2"; shift 2 ;;
    -t|--tail)        MODE=tail;  ARG="$2"; shift 2 ;;
    -o|--online)      ONLINE=true; shift ;;
    -q|--quarantine)  QUARANTINE=true; shift ;;
    -n|--interval)    INTERVAL="$2"; shift 2 ;;
    -d|--log-dir)     LOG_DIR="$2"; LOG_FILE="$LOG_DIR/detections.csv"; QUARANTINE_DIR="$LOG_DIR/quarantine"; shift 2 ;;
    -h|--help)        banner; usage; exit 0 ;;
    *) echo "${RED}Unknown option: $1${RST}"; usage; exit 1 ;;
  esac
done

banner

case "$MODE" in
  url)   handle_url "$ARG" ;;
  file)  handle_file "$ARG" ;;
  list)
    [[ -f "$ARG" ]] || { echo "${RED}File not found: $ARG${RST}"; exit 1; }
    while IFS= read -r l; do [[ -z "$l" || "$l" == \#* ]] && continue; handle_url "$l"; done <"$ARG" ;;
  stdin)
    while IFS= read -r l; do [[ -z "$l" || "$l" == \#* ]] && continue; handle_url "$l"; done ;;
  inter) interactive_bot ;;
  watch) watch_dir "$ARG" ;;
  tail)  tail_feed "$ARG" ;;
  *)     usage; exit 1 ;;
esac

summary
exit $(( FLAGGED > 0 ? 2 : 0 ))
