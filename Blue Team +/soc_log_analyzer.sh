#!/usr/bin/env bash
# ==============================================================================
#  SOC Log Analyzer v1.0
#  Coded by Mr Sabaz Ali Khan  (Cyber Security Engineer)
#
#  Defensive log triage for SOC analysts. Analyzes:
#    - Auth logs   (/var/log/auth.log, /var/log/secure) : SSH brute force,
#                  root logins, sudo usage, account changes, off-hours logins
#    - Web logs    (Apache/Nginx combined format)       : SQLi, XSS, traversal,
#                  scanners, sensitive path probing, request spikes, 4xx/5xx
#    - Syslog      (generic)                            : errors, firewall
#                  blocks, OOM, segfaults, promiscuous mode
#
#  Usage:   ./soc_log_analyzer.sh -f <logfile> [-f <logfile> ...] [options]
#           ./soc_log_analyzer.sh --demo
# ==============================================================================

set -uo pipefail

VERSION="1.0"
THRESHOLD=5          # failed logins from one IP before flagged as brute force
WEB_ERR_THRESHOLD=50 # 4xx/5xx from one IP before flagged as scanning
WEB_RATE=100         # requests/minute from the whole log before flagged
TOP=10
OUTDIR="./soc_report_$(date +%Y%m%d_%H%M%S)"
FILES=()
DEMO=0
NOCOLOR=0

# ------------------------------------------------------------------------------
# Banner
# ------------------------------------------------------------------------------
show_banner() {
  printf '%s' "$CYN"
  cat <<'BANNER'
                          ▒▒▒▒▒▒
                        ▒▒▒▒▒▒▒▒▒▒
                      ▒▒▒▒      ▒▒▒▒
                      ▒▒▒▒      ▒▒▒▒
                      ▒▒▒▒      ▒▒▒▒                          ████████
                    ██████████████████                      ██▓▓▓▓▓▓▓▓██
                  ██▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██    ██████████████████▓▓████▓▓██
                  ██▓▓▓▓▓▓██████▓▓▓▓▓▓██  ██▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓████▓▓██
                  ██▓▓▓▓▓▓██████▓▓▓▓▓▓██  ██▓▓██▓▓████████████▓▓████▓▓██
                  ██▓▓▓▓▓▓▓▓██▓▓▓▓▓▓▓▓██  ██▓▓██▓▓██        ██▓▓▓▓▓▓▓▓██
                  ██▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██    ██  ██            ████████
                  ██▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██
                    ██████████████████
BANNER
  printf '%s' "$RST"
  printf '\n%s  SOC LOG ANALYZER v%s%s\n' "$BLD" "$VERSION" "$RST"
  printf '%s  Coded by Mr Sabaz Ali Khan - Cyber Security Engineer%s\n\n' "$GRN" "$RST"
}

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------
setup_colors() {
  if [[ $NOCOLOR -eq 1 ]]; then
    RED=""; YEL=""; GRN=""; CYN=""; MAG=""; BLD=""; RST=""
  else
    RED=$'\e[1;31m'; YEL=$'\e[1;33m'; GRN=$'\e[1;32m'
    CYN=$'\e[1;36m'; MAG=$'\e[1;35m'; BLD=$'\e[1m'; RST=$'\e[0m'
  fi
}

usage() {
  cat <<EOF
SOC Log Analyzer v$VERSION - coded by Mr Sabaz Ali Khan

Usage: $0 -f <logfile> [-f <logfile> ...] [options]

Options:
  -f FILE   Log file to analyze (repeatable; .gz supported)
  -t N      Failed-login threshold for brute force alert   (default: $THRESHOLD)
  -n N      Rows shown in top-N tables                     (default: $TOP)
  -o DIR    Output directory for report + IOC list
  --demo    Generate sample logs and analyze them
  --no-color  Disable colored output
  -h        Show this help

Examples:
  $0 -f /var/log/auth.log
  sudo $0 -f /var/log/auth.log -f /var/log/nginx/access.log -t 10
  $0 --demo
EOF
}

section() { printf '\n%s== %s ==%s\n' "$MAG" "$1" "$RST"; }

alert() {
  local sev=$1; shift
  local col
  case "$sev" in
    CRITICAL) col=$RED ;;
    HIGH)     col=$YEL ;;
    MEDIUM)   col=$CYN ;;
    *)        col=$GRN ;;
  esac
  printf '%s[%s]%s %s\n' "$col" "$sev" "$RST" "$*"
  printf '%s|%s\n' "$sev" "$*" >> "$FINDINGS"
}

ioc() { printf '%s\n' "$1" >> "$IOC"; }

extract_ips() {
  grep -oE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' | awk '{print $2}'
}

# Reads a file, transparently handling .gz
readlog() {
  case "$1" in
    *.gz) zcat -- "$1" ;;
    *)    cat -- "$1" ;;
  esac
}

bar() {
  # bar <value> <max> -> simple ascii bar
  local v=$1 m=$2 w=30 n
  (( m == 0 )) && m=1
  n=$(( v * w / m ))
  printf '%*s' "$n" '' | tr ' ' '#'
}

# ------------------------------------------------------------------------------
# Log type detection
# ------------------------------------------------------------------------------
is_web_log()  { head -n 200 "$1" | grep -qE '"(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH) [^"]+ HTTP/'; }
is_auth_log() { head -n 500 "$1" | grep -qE 'sshd\[|sudo:|pam_unix|Failed password|Accepted (password|publickey)'; }

# ------------------------------------------------------------------------------
# Auth log analysis
# ------------------------------------------------------------------------------
analyze_auth() {
  local f=$1
  section "SSH / AUTHENTICATION ANALYSIS  [$(basename "$f")]"

  local failed accepted invalid
  failed=$(grep -c 'Failed password' "$f")
  accepted=$(grep -c 'Accepted ' "$f")
  invalid=$(grep -c 'Invalid user' "$f")
  printf 'Failed passwords : %s\nAccepted logins  : %s\nInvalid users    : %s\n' \
    "$failed" "$accepted" "$invalid"

  # --- Top failed source IPs / brute force
  section "Top failed-login source IPs"
  local tmp_bf="$OUTDIR/.bf_ips"
  : > "$tmp_bf"
  grep 'Failed password' "$f" | extract_ips | sort | uniq -c | sort -rn | head -n "$TOP" |
  while read -r c ip; do
    printf '  %-6s %-16s %s\n' "$c" "$ip" "$(bar "$c" "$failed")"
  done

  grep 'Failed password' "$f" | extract_ips | sort | uniq -c | sort -rn |
  while read -r c ip; do
    if (( c >= THRESHOLD )); then
      echo "$ip" >> "$tmp_bf"
      alert HIGH "SSH brute force suspected from $ip ($c failed attempts)"
      ioc "$ip"
    fi
  done

  # --- Targeted usernames
  section "Most targeted usernames"
  grep -E 'Failed password|Invalid user' "$f" |
    sed -nE 's/.*(Failed password for (invalid user )?|Invalid user )([^ ]+) from.*/\3/p' |
    sort | uniq -c | sort -rn | head -n "$TOP" |
    while read -r c u; do printf '  %-6s %s\n' "$c" "$u"; done

  if grep -qE 'Failed password for (invalid user )?root ' "$f"; then
    local rc
    rc=$(grep -cE 'Failed password for (invalid user )?root ' "$f")
    alert MEDIUM "Direct attacks against root account ($rc failures) - consider PermitRootLogin no"
  fi

  # --- Brute force followed by success (possible compromise)
  section "Compromise indicators"
  local hit=0 ip
  if [[ -s $tmp_bf ]]; then
    while read -r ip; do
      [[ -z $ip ]] && continue
      if grep 'Accepted ' "$f" | grep -qF "from $ip "; then
        local user
        user=$(grep 'Accepted ' "$f" | grep -F "from $ip " | sed -nE 's/.*Accepted [a-z]+ for ([^ ]+) from.*/\1/p' | sort -u | paste -sd, -)
        alert CRITICAL "Successful login from brute-forcing IP $ip (user: $user) - POSSIBLE COMPROMISE"
        hit=1
      fi
    done < <(sort -u "$tmp_bf")
  fi
  (( hit == 0 )) && printf '  No success-after-brute-force pattern found.\n'

  if grep -qE 'Accepted [a-z]+ for root ' "$f"; then
    local n
    n=$(grep -cE 'Accepted [a-z]+ for root ' "$f")
    alert HIGH "Direct root SSH logins accepted ($n)"
    grep -E 'Accepted [a-z]+ for root ' "$f" | extract_ips | sort -u | while read -r ip; do ioc "$ip"; done
  fi

  # --- Off-hours successful logins (00:00-05:59)
  local off
  off=$(grep 'Accepted ' "$f" | awk '{split($3,t,":"); if (t[1]+0 < 6) print}' | wc -l)
  if (( off > 0 )); then
    alert MEDIUM "$off successful login(s) during off-hours (00:00-05:59)"
    grep 'Accepted ' "$f" | awk '{split($3,t,":"); if (t[1]+0 < 6) print "    " $0}' | head -n 5
  fi

  # --- Sudo
  section "Privilege escalation (sudo)"
  local sudo_cnt
  sudo_cnt=$(grep -c 'sudo:.*COMMAND=' "$f")
  printf 'Sudo commands executed: %s\n' "$sudo_cnt"
  grep 'sudo:.*COMMAND=' "$f" | sed -nE 's/.*sudo: +([^ ]+) :.*/\1/p' |
    sort | uniq -c | sort -rn | head -n 5 | while read -r c u; do printf '  %-6s %s\n' "$c" "$u"; done

  local sudo_fail
  sudo_fail=$(grep -cE 'sudo:.*(authentication failure|incorrect password|NOT in sudoers)' "$f")
  (( sudo_fail > 0 )) && alert MEDIUM "Sudo failures / unauthorized sudo attempts: $sudo_fail"

  if grep -E 'sudo:.*COMMAND=' "$f" | grep -qiE 'COMMAND=.*(/bin/(ba)?sh|nc |ncat|wget|curl .*\| *(ba)?sh|chmod [0-7]*777|visudo|passwd|useradd)'; then
    alert HIGH "Sensitive sudo commands detected (shell/netcat/wget/useradd/passwd):"
    grep -E 'sudo:.*COMMAND=' "$f" | grep -iE 'COMMAND=.*(/bin/(ba)?sh|nc |ncat|wget|curl .*\| *(ba)?sh|chmod [0-7]*777|visudo|passwd|useradd)' | head -n 5 | sed 's/^/    /'
  fi

  # --- Account changes
  section "Account & group changes"
  local acct
  acct=$(grep -E 'useradd|new user|usermod|userdel|groupadd|passwd\[.*password changed|added to group' "$f" | wc -l)
  if (( acct > 0 )); then
    alert MEDIUM "Account/group modifications detected ($acct events)"
    grep -E 'useradd|new user|usermod|userdel|groupadd|password changed|added to group' "$f" | head -n 8 | sed 's/^/    /'
  else
    printf '  None detected.\n'
  fi

  # --- Hourly failed login distribution
  section "Failed logins by hour"
  local max
  max=$(grep 'Failed password' "$f" | awk '{split($3,t,":"); h[t[1]]++} END{m=0; for(i in h) if(h[i]>m) m=h[i]; print m}')
  grep 'Failed password' "$f" | awk '{split($3,t,":"); h[t[1]]++} END{for(i in h) print i, h[i]}' | sort |
    while read -r h c; do printf '  %s:00  %-5s %s\n' "$h" "$c" "$(bar "$c" "${max:-1}")"; done
}

# ------------------------------------------------------------------------------
# Web log analysis (Apache / Nginx combined)
# ------------------------------------------------------------------------------
SQLI_RE="union([[:space:]+]|%20)+(all([[:space:]+]|%20)+)?select|information_schema|(%27|')([[:space:]+]|%20)*(or|and)([[:space:]+]|%20)+[0-9a-z]+=[0-9a-z]+|sleep\(|benchmark\(|xp_cmdshell|0x[0-9a-f]{8,}"
XSS_RE="<script|%3cscript|onerror=|onload=|javascript:|alert\(|document\.cookie"
TRAV_RE="\.\./|\.\.%2f|%2e%2e|/etc/passwd|/etc/shadow|boot\.ini|win\.ini"
CMDI_RE="(;|%3b|\|\||&&)[[:space:]+]*(cat|ls|id|whoami|wget|curl|nc|bash|sh)([[:space:]+]|%20)|/bin/(ba)?sh|cmd\.exe|powershell"
SCAN_UA_RE="sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz|hydra|wpscan|acunetix|nessus|openvas|zgrab|nuclei|burp"
SENS_RE="wp-login\.php|xmlrpc\.php|\.env|\.git/|phpmyadmin|/admin|/manager/html|\.htaccess|\.bak|\.sql|config\.php|id_rsa|/cgi-bin/"

web_pattern() {
  # web_pattern <file> <label> <regex> <severity>
  local f=$1 label=$2 re=$3 sev=$4 n
  n=$(grep -Eaic -- "$re" "$f")
  if (( n > 0 )); then
    alert "$sev" "$label attempts detected: $n request(s)"
    grep -Eai -- "$re" "$f" | awk '{print $1}' | sort | uniq -c | sort -rn | head -n 5 |
      while read -r c ip; do printf '    %-6s %s\n' "$c" "$ip"; ioc "$ip"; done
    grep -Eai -- "$re" "$f" | head -n 2 | cut -c1-160 | sed 's/^/    e.g. /'
  fi
}

analyze_web() {
  local f=$1
  section "WEB ACCESS LOG ANALYSIS  [$(basename "$f")]"

  local total
  total=$(wc -l < "$f")
  printf 'Total requests: %s\n' "$total"

  section "Top client IPs"
  awk '{print $1}' "$f" | sort | uniq -c | sort -rn | head -n "$TOP" |
    while read -r c ip; do printf '  %-7s %s\n' "$c" "$ip"; done

  section "Status code breakdown"
  awk '{print $9}' "$f" | grep -E '^[1-5][0-9]{2}$' | sort | uniq -c | sort -rn |
    while read -r c s; do printf '  %-4s %s\n' "$s" "$c"; done

  section "HTTP methods"
  awk -F'"' '{split($2,a," "); print a[1]}' "$f" | sort | uniq -c | sort -rn | head -n 6 |
    while read -r c m; do printf '  %-8s %s\n' "$m" "$c"; done
  if grep -Eq '"(TRACE|CONNECT|PROPFIND|DEBUG) ' "$f"; then
    alert MEDIUM "Unusual HTTP methods in use (TRACE/CONNECT/PROPFIND/DEBUG)"
  fi

  section "Attack pattern detection"
  web_pattern "$f" "SQL injection"      "$SQLI_RE"    CRITICAL
  web_pattern "$f" "Cross-site scripting" "$XSS_RE"   HIGH
  web_pattern "$f" "Path traversal / LFI" "$TRAV_RE"  CRITICAL
  web_pattern "$f" "Command injection"  "$CMDI_RE"    CRITICAL
  web_pattern "$f" "Scanner/attack-tool user-agent" "$SCAN_UA_RE" HIGH

  section "Sensitive path probing"
  grep -Eai -- "$SENS_RE" "$f" | awk '{print $1}' | sort | uniq -c | sort -rn | head -n 5 |
    while read -r c ip; do
      printf '  %-6s %s\n' "$c" "$ip"
      (( c >= THRESHOLD )) && { alert MEDIUM "Sensitive-path probing from $ip ($c requests)"; ioc "$ip"; }
    done

  section "Error-rate scanning (4xx/5xx per IP)"
  awk '$9 ~ /^[45][0-9][0-9]$/ {c[$1]++} END{for(i in c) print c[i], i}' "$f" | sort -rn | head -n 5 |
    while read -r c ip; do
      printf '  %-6s %s\n' "$c" "$ip"
      (( c >= WEB_ERR_THRESHOLD )) && { alert HIGH "Possible scanning / forced browsing from $ip ($c error responses)"; ioc "$ip"; }
    done

  section "Request-rate spikes (per minute)"
  awk '{print substr($4,2,17)}' "$f" | sort | uniq -c | sort -rn | head -n 5 |
    while read -r c m; do
      printf '  %-6s %s\n' "$c" "$m"
      (( c >= WEB_RATE )) && alert MEDIUM "Traffic spike: $c requests in minute $m (possible DoS / automated tool)"
    done

  section "Top requested URLs returning 404"
  awk '$9==404 {print $7}' "$f" | sort | uniq -c | sort -rn | head -n 5 |
    while read -r c u; do printf '  %-6s %s\n' "$c" "$u"; done
}

# ------------------------------------------------------------------------------
# Generic syslog analysis
# ------------------------------------------------------------------------------
analyze_generic() {
  local f=$1
  section "GENERAL SYSLOG INDICATORS  [$(basename "$f")]"

  local kw label n
  declare -A KW=(
    ["segfault"]="Segmentation faults"
    ["Out of memory|oom-killer"]="Out-of-memory kills"
    ["promiscuous mode"]="NIC promiscuous mode (possible sniffer)"
    ["Permission denied"]="Permission denied events"
    ["Connection refused"]="Connection refused events"
    ["kernel:.*(error|fail)"]="Kernel errors"
    ["CRON.*\(root\).*CMD.*(wget|curl|nc |bash -i)"]="Suspicious root cron jobs"
    ["Started .*(miner|xmr)|xmrig|minerd"]="Crypto-miner indicators"
  )
  for kw in "${!KW[@]}"; do
    n=$(grep -Eaic -- "$kw" "$f")
    label=${KW[$kw]}
    if (( n > 0 )); then
      printf '  %-45s %s\n' "$label" "$n"
      case "$label" in
        *promiscuous*|*miner*|*cron*) alert HIGH "$label: $n event(s)" ;;
        *Out-of-memory*|*Segmentation*) alert MEDIUM "$label: $n event(s)" ;;
      esac
    fi
  done

  if grep -q 'UFW BLOCK\|IN=.*OUT=.*SRC=' "$f"; then
    section "Firewall blocks - top sources"
    grep -oE 'SRC=([0-9]{1,3}\.){3}[0-9]{1,3}' "$f" | cut -d= -f2 | sort | uniq -c | sort -rn | head -n "$TOP" |
      while read -r c ip; do printf '  %-6s %s\n' "$c" "$ip"; (( c >= THRESHOLD * 4 )) && ioc "$ip"; done
    section "Firewall blocks - top targeted ports"
    grep -oE 'DPT=[0-9]+' "$f" | cut -d= -f2 | sort | uniq -c | sort -rn | head -n 5 |
      while read -r c p; do printf '  port %-6s %s\n' "$p" "$c"; done
  fi
}

# ------------------------------------------------------------------------------
# Demo data
# ------------------------------------------------------------------------------
make_demo() {
  local d="$OUTDIR/demo"
  mkdir -p "$d"
  {
    for i in $(seq 1 40); do
      printf 'Oct 13 03:%02d:%02d srv sshd[1201]: Failed password for invalid user admin from 185.220.101.7 port 4%04d ssh2\n' $((i % 60)) $((i % 60)) "$i"
    done
    for u in root oracle test ubuntu; do
      for i in 1 2 3; do
        printf 'Oct 13 04:1%d:2%d srv sshd[1210]: Failed password for %s from 185.220.101.7 port 5%03d ssh2\n' "$i" "$i" "$u" "$i"
      done
    done
    printf 'Oct 13 04:30:11 srv sshd[1230]: Accepted password for deploy from 185.220.101.7 port 50111 ssh2\n'
    printf 'Oct 13 09:02:40 srv sshd[1300]: Accepted publickey for sabaz from 10.0.0.5 port 50222 ssh2\n'
    printf 'Oct 13 09:10:01 srv sudo:    sabaz : TTY=pts/0 ; PWD=/home/sabaz ; USER=root ; COMMAND=/usr/bin/apt update\n'
    printf 'Oct 13 04:33:01 srv sudo:   deploy : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash\n'
    printf 'Oct 13 04:35:19 srv useradd[1402]: new user: name=backdoor, UID=1002, GID=1002\n'
    printf 'Oct 13 05:10:00 srv kernel: device eth0 entered promiscuous mode\n'
    for i in 1 2 3 4 5 6; do
      printf 'Oct 13 11:0%d:00 srv sshd[1500]: Failed password for sabaz from 203.0.113.9 port 6%03d ssh2\n' "$i" "$i"
    done
  } > "$d/auth.log"

  {
    for i in $(seq 1 130); do
      printf '198.51.100.23 - - [13/Oct/2026:10:15:%02d +0500] "GET /products?id=%d HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n' $((i % 60)) "$i"
    done
    printf '45.155.205.9 - - [13/Oct/2026:10:20:01 +0500] "GET /item.php?id=1%%27%%20OR%%201=1-- HTTP/1.1" 500 210 "-" "sqlmap/1.7"\n'
    printf '45.155.205.9 - - [13/Oct/2026:10:20:02 +0500] "GET /item.php?id=1+UNION+SELECT+1,2,3-- HTTP/1.1" 500 210 "-" "sqlmap/1.7"\n'
    printf '45.155.205.9 - - [13/Oct/2026:10:20:03 +0500] "GET /download?f=../../../../etc/passwd HTTP/1.1" 403 150 "-" "Mozilla/5.0"\n'
    printf '45.155.205.9 - - [13/Oct/2026:10:20:04 +0500] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 400 "-" "Mozilla/5.0"\n'
    printf '45.155.205.9 - - [13/Oct/2026:10:20:05 +0500] "GET /ping?host=8.8.8.8;cat%%20/etc/passwd HTTP/1.1" 200 90 "-" "curl/8.0"\n'
    for p in wp-login.php xmlrpc.php .env .git/config phpmyadmin/ admin/ config.php.bak; do
      printf '192.0.2.77 - - [13/Oct/2026:10:25:10 +0500] "GET /%s HTTP/1.1" 404 120 "-" "Nikto/2.5"\n' "$p"
    done
    for i in $(seq 1 60); do
      printf '192.0.2.77 - - [13/Oct/2026:10:26:%02d +0500] "GET /x%d HTTP/1.1" 404 120 "-" "Mozilla/5.0"\n' $((i % 60)) "$i"
    done
  } > "$d/access.log"

  FILES=("$d/auth.log" "$d/access.log")
}

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------
summary() {
  section "EXECUTIVE SUMMARY"
  local crit high med score rating col
  crit=$(grep -c '^CRITICAL|' "$FINDINGS" 2>/dev/null || true)
  high=$(grep -c '^HIGH|' "$FINDINGS" 2>/dev/null || true)
  med=$(grep -c '^MEDIUM|' "$FINDINGS" 2>/dev/null || true)
  crit=${crit:-0}; high=${high:-0}; med=${med:-0}
  score=$(( crit * 10 + high * 5 + med * 2 ))

  if   (( crit > 0 )); then rating="CRITICAL"; col=$RED
  elif (( high > 0 )); then rating="HIGH";     col=$YEL
  elif (( med  > 0 )); then rating="MEDIUM";   col=$CYN
  else                      rating="LOW";      col=$GRN; fi

  printf 'Critical findings : %s\nHigh findings     : %s\nMedium findings   : %s\n' "$crit" "$high" "$med"
  printf 'Risk score        : %s\n' "$score"
  printf 'Overall rating    : %s%s%s\n' "$col" "$rating" "$RST"

  if [[ -s $IOC ]]; then
    sort -u "$IOC" -o "$IOC"
    section "INDICATORS OF COMPROMISE (IPs to investigate / block)"
    sed 's/^/  /' "$IOC"
  fi

  section "RECOMMENDED ACTIONS"
  (( crit > 0 )) && cat <<'EOF'
  1. Treat flagged hosts/accounts as compromised: isolate, rotate credentials, review sessions.
  2. Block listed IOC IPs at the firewall / WAF and hunt for them across other log sources.
  3. Patch or virtually-patch vulnerable web endpoints hit by injection attempts.
EOF
  (( high > 0 )) && cat <<'EOF'
  - Enforce key-based SSH auth, disable root login, deploy fail2ban / rate limiting.
  - Put a WAF in front of public web apps and restrict admin paths by IP.
EOF
  printf '  - Review the full report and keep it with the incident ticket.\n'
  printf '\nGenerated: %s | Analyst tool: SOC Log Analyzer v%s (Mr Sabaz Ali Khan)\n' "$(date '+%F %T')" "$VERSION"
}

# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------
main() {
  local f ran
  for f in "${FILES[@]}"; do
    printf '\n%s##### Analyzing: %s #####%s\n' "$BLD" "$f" "$RST"
    local src="$f"
    if [[ $f == *.gz ]]; then
      src="$OUTDIR/.$(basename "${f%.gz}")"
      zcat -- "$f" > "$src"
    fi
    ran=0
    if is_auth_log "$src"; then analyze_auth "$src"; ran=1; fi
    if is_web_log  "$src"; then analyze_web  "$src"; ran=1; fi
    analyze_generic "$src"
    (( ran == 0 )) && printf '%s[i]%s Log type not recognized as auth/web; only generic checks were run.\n' "$YEL" "$RST"
  done
  summary
}

# --- Argument parsing
while [[ $# -gt 0 ]]; do
  case "$1" in
    -f) FILES+=("${2:-}"); shift 2 ;;
    -t) THRESHOLD="${2:-5}"; shift 2 ;;
    -n) TOP="${2:-10}"; shift 2 ;;
    -o) OUTDIR="${2:-$OUTDIR}"; shift 2 ;;
    --demo) DEMO=1; shift ;;
    --no-color) NOCOLOR=1; shift ;;
    -h|--help) setup_colors; show_banner; usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

setup_colors
show_banner

[[ $THRESHOLD =~ ^[0-9]+$ && $TOP =~ ^[0-9]+$ ]] || { echo "Error: -t and -n must be numbers."; exit 1; }

mkdir -p "$OUTDIR" || { echo "Cannot create $OUTDIR"; exit 1; }
FINDINGS="$OUTDIR/.findings"; IOC="$OUTDIR/ioc_ips.txt"
: > "$FINDINGS"; : > "$IOC"

if (( DEMO == 1 )); then
  make_demo
  printf '%s[demo]%s Sample logs generated in %s/demo\n' "$YEL" "$RST" "$OUTDIR"
fi

if [[ ${#FILES[@]} -eq 0 ]]; then
  echo "Error: no log file given."; usage; exit 1
fi
for f in "${FILES[@]}"; do
  [[ -r $f ]] || { echo "Error: cannot read '$f' (try sudo)."; exit 1; }
done

REPORT="$OUTDIR/soc_report.txt"
main 2>&1 | tee >(sed -u 's/\x1b\[[0-9;]*m//g' > "$REPORT")
sleep 0.3
printf '\n%s[+]%s Report : %s\n%s[+]%s IOC list: %s\n' "$GRN" "$RST" "$REPORT" "$GRN" "$RST" "$IOC"
