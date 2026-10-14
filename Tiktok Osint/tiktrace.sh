#!/usr/bin/env bash
# ============================================================
#  TikTrace - TikTok Public Profile OSINT Tracer
#  coded by Mr Sabaz Ali Khan (Cyber Security Engineer)
#  Uses ONLY publicly available profile data. For lawful OSINT,
#  research and awareness use. No login, no scraping of private data.
# ============================================================

VERSION="1.0"
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
OUTDIR="./tiktrace_reports"
DELAY=3
USERS=()
JSON_OUT=0

R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; W=$'\e[97m'; N=$'\e[0m'

banner() {
printf '%s' "$C"
cat <<'BANNER'
⠀⠀⠀⠀⠀⠀⠀⢀⠆⠀⢀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡀⠀⠰⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢠⡏⠀⢀⣾⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢷⡀⠀⢹⣄⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣰⡟⠀⠀⣼⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣧⠀⠀⢻⣆⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢠⣿⠁⠀⣸⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣇⠀⠈⣿⡆⠀⠀⠀⠀
⠀⠀⠀⠀⣾⡇⠀⢀⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⡀⠀⢸⣿⠀⠀⠀⠀
⠀⠀⠀⢸⣿⠀⠀⣸⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣇⠀⠀⣿⡇⠀⠀⠀
⠀⠀⠀⣿⣿⠀⠀⣿⣿⣧⣤⣤⣤⣤⣤⣤⡀⠀⣀⠀⠀⣀⠀⢀⣤⣤⣤⣤⣤⣤⣼⣿⣿⠀⠀⣿⣿⠀⠀⠀
⠀⠀⢸⣿⡏⠀⠀⠀⠙⢉⣉⣩⣴⣶⣤⣙⣿⣶⣯⣦⣴⣼⣷⣿⣋⣤⣶⣦⣍⣉⡉⠋⠀⠀⠀⢸⣿⡇⠀⠀
⠀⠀⢿⣿⣷⣤⣶⣶⠿⠿⠛⠋⣉⡉⠙⢛⣿⣿⣿⣿⣿⣿⣿⣿⡛⠛⢉⣉⠙⠛⠿⠿⣶⣶⣤⣾⣿⡿⠀⠀
⠀⠀⠀⠙⠻⠋⠉⠀⠀⠀⣠⣾⡿⠟⠛⣻⣿⣿⣿⣿⣿⣿⣿⣿⣟⠛⠻⢿⣷⣄⠀⠀⠀⠉⠙⠟⠋⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣤⣾⠿⠋⢀⣠⣾⠟⢫⣿⣿⣿⣿⣿⣿⡍⠻⣷⣄⡀⠙⠿⣷⣤⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣠⣴⡿⠛⠁⠀⢸⣿⣿⠋⠀⢸⣿⣿⣿⣿⣿⣿⡗⠀⠙⣿⣿⡇⠀⠈⠛⢿⣦⣄⠀⠀⠀⠀⠀
⢀⠀⣀⣴⣾⠟⠋⠀⠀⠀⠀⢸⣿⣿⠀⠀⢸⣿⣿⣿⣿⣿⣿⡇⠀⠀⣿⣿⡇⠀⠀⠀⠀⠙⠻⣷⣦⣀⠀⣀
⢸⣿⣿⠋⠁⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠈⣿⣿⣿⣿⣿⣿⠁⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠈⠙⣿⣿⡟
⢸⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀⢹⣿⣿⣿⣿⡏⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⡇
⢸⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀⠀⢿⣿⣿⡿⠀⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⡇
⠀⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀⠀⠈⠿⠿⠁⠀⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀
⠀⢻⣿⡄⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠇⠀⠀⠀⠀⠀⠀⠀⢀⣿⡟⠀
⠀⠘⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⠃⠀
⠀⠀⠸⣷⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⣾⠏⠀⠀
⠀⠀⠀⢻⡆⠀⠀⠀⠀⠀⠀⠀⠸⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⠇⠀⠀⠀⠀⠀⠀⠀⢰⡟⠀⠀⠀
⠀⠀⠀⠀⢷⠀⠀⠀⠀⠀⠀⠀⠀⢿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡿⠀⠀⠀⠀⠀⠀⠀⠀⡾⠀⠀⠀⠀
⠀⠀⠀⠀⠈⢧⠀⠀⠀⠀⠀⠀⠀⠸⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⠇⠀⠀⠀⠀⠀⠀⠀⡸⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⡆⠀⠀⠀⠀⠀⠀⠀⠀⢰⡟⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢳⠀⠀⠀⠀⠀⠀⠀⠀⡞⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠣⠀⠀⠀⠀⠀⠀⠜⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
BANNER
printf '%s' "$N"
printf '%s        T I K T R A C E  v%s  -  TikTok Public Profile Tracer%s\n' "$W" "$VERSION" "$N"
printf '%s             coded by Mr Sabaz Ali Khan%s\n\n' "$Y" "$N"
}

usage() {
cat <<EOF
Usage: $0 [options]
  -u <username>   Trace a single TikTok username (with or without @)
  -f <file>       Trace many usernames from a file (one per line)
  -o <dir>        Output directory for reports (default: $OUTDIR)
  -d <seconds>    Delay between requests in batch mode (default: $DELAY)
  -j              Also save raw parsed JSON per user
  -h              Show this help

Examples:
  $0 -u tiktok
  $0 -f users.txt -d 5 -j
EOF
}

need() { command -v "$1" >/dev/null 2>&1 || { echo "${R}[!] Missing dependency: $1${N}"; exit 1; }; }

fmt_num() { # 1234567 -> 1,234,567
  printf "%s" "$1" | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta'
}

# fallback extractor when jq is missing
raw_field() { printf '%s' "$1" | grep -o "\"$2\":\"\?[^,\"}]*" | head -1 | sed 's/^[^:]*:"\?//'; }

trace_user() {
  local user="${1#@}"
  user=$(printf '%s' "$user" | tr -cd 'A-Za-z0-9._')
  [ -z "$user" ] && { echo "${R}[!] Invalid username${N}"; return 1; }

  echo "${C}[*] Tracing @${user} ...${N}"
  local html http
  html=$(curl -sL --max-time 25 -A "$UA" -H "Accept-Language: en-US,en;q=0.9" \
         -w '\n__HTTP__%{http_code}' "https://www.tiktok.com/@${user}")
  http=${html##*__HTTP__}
  html=${html%$'\n'__HTTP__*}

  if [ "$http" = "404" ]; then
    echo "${G}[+] @${user} does not exist (username may be available).${N}"; return 0
  elif [ "$http" != "200" ]; then
    echo "${R}[!] HTTP $http - blocked, rate limited or network issue.${N}"; return 1
  fi

  local blob
  blob=$(printf '%s' "$html" | sed 's#</script>#\n#g' | grep '__UNIVERSAL_DATA_FOR_REHYDRATION__' | sed 's/^.*<script[^>]*>//' | head -1)
  if [ -z "$blob" ]; then
    echo "${Y}[?] Profile page loaded but no embedded data found (TikTok may have changed layout or served a captcha).${N}"
    return 1
  fi

  local id nick bio verified private region lang followers following hearts videos friends created bio_link status
  if command -v jq >/dev/null 2>&1; then
    local d='.["__DEFAULT_SCOPE__"]["webapp.user-detail"]'
    status=$(jq -r "$d.statusCode // 0" <<<"$blob")
    if [ "$status" != "0" ]; then
      echo "${G}[+] @${user}: no public profile (status $status) - not found, banned or unavailable.${N}"; return 0
    fi
    local u="$d.userInfo.user" s="$d.userInfo.stats"
    id=$(jq -r "$u.id // \"-\"" <<<"$blob")
    nick=$(jq -r "$u.nickname // \"-\"" <<<"$blob")
    bio=$(jq -r "$u.signature // \"-\"" <<<"$blob" | tr '\n' ' ')
    verified=$(jq -r "$u.verified // false" <<<"$blob")
    private=$(jq -r "$u.privateAccount // false" <<<"$blob")
    region=$(jq -r "$u.region // \"-\"" <<<"$blob")
    lang=$(jq -r "$u.language // \"-\"" <<<"$blob")
    created=$(jq -r "$u.createTime // 0" <<<"$blob")
    bio_link=$(jq -r "$u.bioLink.link // \"-\"" <<<"$blob")
    followers=$(jq -r "$s.followerCount // 0" <<<"$blob")
    following=$(jq -r "$s.followingCount // 0" <<<"$blob")
    hearts=$(jq -r "$s.heartCount // 0" <<<"$blob")
    videos=$(jq -r "$s.videoCount // 0" <<<"$blob")
    friends=$(jq -r "$s.friendCount // 0" <<<"$blob")
    [ "$JSON_OUT" = 1 ] && { mkdir -p "$OUTDIR"; jq "$d.userInfo" <<<"$blob" > "$OUTDIR/${user}.json"; }
  else
    echo "${Y}[i] jq not found - using basic parser (install jq for best results).${N}"
    id=$(raw_field "$blob" id); nick=$(raw_field "$blob" nickname); bio=$(raw_field "$blob" signature)
    verified=$(raw_field "$blob" verified); private=$(raw_field "$blob" privateAccount)
    region=$(raw_field "$blob" region); lang=$(raw_field "$blob" language)
    created=$(raw_field "$blob" createTime); bio_link="-"
    followers=$(raw_field "$blob" followerCount); following=$(raw_field "$blob" followingCount)
    hearts=$(raw_field "$blob" heartCount); videos=$(raw_field "$blob" videoCount); friends=$(raw_field "$blob" friendCount)
  fi

  local created_h="-"
  if [[ "$created" =~ ^[0-9]+$ ]] && [ "$created" -gt 0 ]; then
    created_h=$(date -u -d "@$created" '+%Y-%m-%d %H:%M UTC' 2>/dev/null || date -u -r "$created" '+%Y-%m-%d %H:%M UTC' 2>/dev/null || echo "-")
  fi

  # simple engagement ratio
  local ratio="-"
  if [[ "$followers" =~ ^[0-9]+$ ]] && [ "${followers:-0}" -gt 0 ]; then
    ratio=$(awk -v h="${hearts:-0}" -v f="$followers" 'BEGIN{printf "%.1f likes per follower", h/f}')
  fi

  # heuristic flags
  local flags=()
  [ "$verified" = "true" ] && flags+=("verified account")
  [ "$private" = "true" ] && flags+=("private account")
  [[ "$videos" =~ ^[0-9]+$ ]] && [ "$videos" -eq 0 ] && flags+=("no videos posted")
  [[ "$followers" =~ ^[0-9]+$ ]] && [[ "$following" =~ ^[0-9]+$ ]] && [ "$following" -gt $((followers*10+500)) ] && flags+=("follows far more than followers (possible bot/follow-for-follow)")
  [ "$bio" = "-" ] || [ -z "$bio" ] && flags+=("empty bio")
  [ ${#flags[@]} -eq 0 ] && flags+=("none")

  local report
  report=$(cat <<EOF
==================== TikTrace Report ====================
Target        : @${user}
Profile URL   : https://www.tiktok.com/@${user}
User ID       : ${id}
Nickname      : ${nick}
Bio           : ${bio}
Bio link      : ${bio_link}
Verified      : ${verified}
Private       : ${private}
Region (pub.) : ${region}
Language      : ${lang}
Account date  : ${created_h}
Followers     : $(fmt_num "${followers:-0}")
Following     : $(fmt_num "${following:-0}")
Likes (total) : $(fmt_num "${hearts:-0}")
Videos        : $(fmt_num "${videos:-0}")
Friends       : $(fmt_num "${friends:-0}")
Engagement    : ${ratio}
Flags         : $(IFS='; '; echo "${flags[*]}")
Scanned       : $(date -u '+%Y-%m-%d %H:%M:%S UTC')
---------------------------------------------------------
Pivot (manual, public sources):
  Same username elsewhere: instagram.com/${user}  x.com/${user}  github.com/${user}
  Archive               : web.archive.org/web/*/tiktok.com/@${user}
=========================================================
Report generated by TikTrace - coded by Mr Sabaz Ali Khan
EOF
)
  echo "${W}${report}${N}"
  mkdir -p "$OUTDIR"
  printf '%s\n' "$report" > "$OUTDIR/${user}.txt"
  echo "${G}[+] Saved: $OUTDIR/${user}.txt${N}\n"
}

main() {
  while getopts ":u:f:o:d:jh" opt; do
    case $opt in
      u) USERS+=("$OPTARG") ;;
      f) [ -r "$OPTARG" ] || { echo "${R}[!] Cannot read $OPTARG${N}"; exit 1; }
         while IFS= read -r l; do [ -n "$l" ] && USERS+=("$l"); done < "$OPTARG" ;;
      o) OUTDIR="$OPTARG" ;;
      d) DELAY="$OPTARG" ;;
      j) JSON_OUT=1 ;;
      h) banner; usage; exit 0 ;;
      *) banner; usage; exit 1 ;;
    esac
  done

  banner
  need curl
  [ ${#USERS[@]} -eq 0 ] && { usage; exit 1; }

  local i=0
  for u in "${USERS[@]}"; do
    [ $i -gt 0 ] && sleep "$DELAY"
    trace_user "$u"
    i=$((i+1))
  done
  echo "${C}[*] Done. ${i} target(s) processed. - coded by Mr Sabaz Ali Khan${N}"
}

main "$@"
