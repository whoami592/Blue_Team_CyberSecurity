#!/usr/bin/env bash
# =============================================================================
#  AximoBot v1.0.0
#  Telegram feed-forwarder: RSS, YouTube, Reddit, Twitter/X, TikTok, Instagram,
#  Facebook, VK and Telegram channels -> Telegram chats / channels.
#  Media, custom templates, include/exclude filters, auto-translation and
#  ChatGPT summarize / rephrase.
#
#  Coded by Mr Sabaz Ali Khan  (Cyber Security Engineer)
#
#  Use only on public content and within authorized engagements.
# =============================================================================
set -uo pipefail
shopt -u patsub_replacement 2>/dev/null || true

VERSION="1.0.0"
BASE_DIR="${AXIMO_HOME:-$HOME/.aximobot}"
CONF="$BASE_DIR/config.env"
SRC="$BASE_DIR/sources.tsv"
SEEN="$BASE_DIR/seen.db"
LOG="$BASE_DIR/aximobot.log"
LOCK="$BASE_DIR/run.lock"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/aximo.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; C=$'\033[36m'; B=$'\033[1m'; N=$'\033[0m'

banner() {
  cat <<'BANNER'
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⣾⣿⣿⣿⣿⣶⣶⣶⣤⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⣿⣿⣿⣿⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⡄⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⠿⠿⠿⠿⣿⣦⣄⠀⠀⠀⠀⠀⢼⣿⣿⡿⠋⠉⠀⠈⢙⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠈⠙⠛⠁⠀⠀⠀⢀⣼⠟⠋⠀⠀⠀⠀⢀⣼⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣷⣶⣾⣿⣿⣷⣶⣄⠀⠀⠀⠀⠸⠃⣠⣴⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⠿⢿⣿⣿⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠻⠿⣿⣿⣿⠿⠟⠋⠉⢻⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⠁⠀⠀⠈⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣧⣄⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠤⢤⣤⣤⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⡉⠁⠀⠀⠰⣤⣀⠀⠀⢀⣴⡶⠀⠀⠀⠀⣿⣿⡏⢸⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣧⠹⣿⣷⣤⣀⣀⣀⣼⣿⣿⣿⣿⣿⣦⣀⣤⣤⣾⣿⡟⢀⣿⣿⣿⣿⣿⣿⣿⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⣿⣿⣧⠘⣿⡿⠿⠿⠿⣿⣿⣇⣀⣹⣿⠿⠿⠟⠛⣿⡟⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣷⡘⢿⡶⢤⣀⣀⣀⣉⣉⣁⣀⣀⣠⣴⣾⡟⢁⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡌⠁⠀⠀⠈⠻⣿⣿⣿⡟⠛⠉⢹⠟⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣄⡀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⣀⣤⣴⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆⠀⠀⠀⠀⣿⣿⣿⡇⠀⠀⠈⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣶⣤
⢀⣤⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⠀⠀⢻⣿⣿⡇⠀⠀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣄⣸⣿⣿⣧⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
BANNER
  printf '%s\n' "${C}${B}   █████╗ ██╗  ██╗██╗███╗   ███╗ ██████╗ ██████╗  ██████╗ ████████╗${N}"
  printf '%s\n' "${C}${B}  ██╔══██╗╚██╗██╔╝██║████╗ ████║██╔═══██╗██╔══██╗██╔═══██╗╚══██╔══╝${N}"
  printf '%s\n' "${C}${B}  ███████║ ╚███╔╝ ██║██╔████╔██║██║   ██║██████╔╝██║   ██║   ██║   ${N}"
  printf '%s\n' "${C}${B}  ██╔══██║ ██╔██╗ ██║██║╚██╔╝██║██║   ██║██╔══██╗██║   ██║   ██║   ${N}"
  printf '%s\n' "${C}${B}  ██║  ██║██╔╝ ██╗██║██║ ╚═╝ ██║╚██████╔╝██████╔╝╚██████╔╝   ██║   ${N}"
  printf '%s\n' "${C}${B}  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝   ${N}"
  printf '%s\n' "${Y}        Telegram Feed Forwarder  |  v${VERSION}${N}"
  printf '%s\n' "${G}${B}        >>> Coded by Mr Sabaz Ali Khan <<<${N}"
  printf '%s\n\n' "${Y}        Cyber Security Engineer${N}"
}

log()  { printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG" >&2; }
die()  { printf '%s[!] %s%s\n' "$R" "$*" "$N" >&2; exit 1; }
info() { printf '%s[+] %s%s\n' "$G" "$*" "$N"; }

# ------------------------------------------------------------------ setup ---
check_deps() {
  local miss=() d
  for d in curl jq xmllint sha1sum; do command -v "$d" >/dev/null 2>&1 || miss+=("$d"); done
  if ((${#miss[@]})); then
    die "Missing: ${miss[*]}  (Debian/Ubuntu: sudo apt install curl jq libxml2-utils coreutils)"
  fi
}

load_conf() {
  BOT_TOKEN=""; DEFAULT_CHAT=""
  RSSHUB_URL="https://rsshub.app"; NITTER_URL=""
  OPENAI_API_KEY=""; OPENAI_MODEL="gpt-4o-mini"; OPENAI_BASE="https://api.openai.com/v1"
  INTERVAL=300; MAX_PER_SOURCE=5; BACKFILL=0
  USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AximoBot/${VERSION}"
  # shellcheck disable=SC1090
  [[ -f "$CONF" ]] && source "$CONF"
  [[ -n "${AXIMO_BOT_TOKEN:-}" ]] && BOT_TOKEN="$AXIMO_BOT_TOKEN"
  [[ -n "${AXIMO_OPENAI_KEY:-}" ]] && OPENAI_API_KEY="$AXIMO_OPENAI_KEY"
  return 0
}

cmd_init() {
  mkdir -p "$BASE_DIR"; touch "$SRC" "$SEEN" "$LOG"
  if [[ ! -f "$CONF" ]]; then
    cat >"$CONF" <<'EOF'
# AximoBot configuration  (Coded by Mr Sabaz Ali Khan)
BOT_TOKEN=""                 # from @BotFather
DEFAULT_CHAT=""              # numeric chat id or @channelusername (bot must be admin)
RSSHUB_URL="https://rsshub.app"   # self-host RSSHub for TikTok/Instagram/Twitter/Facebook/VK reliability
NITTER_URL=""                # optional Nitter instance, e.g. https://nitter.example.com
OPENAI_API_KEY=""            # optional, enables ai=summarize / ai=rephrase
OPENAI_MODEL="gpt-4o-mini"
OPENAI_BASE="https://api.openai.com/v1"
INTERVAL=300                 # seconds between polling cycles
MAX_PER_SOURCE=5             # max new posts forwarded per source per cycle
BACKFILL=0                   # how many latest posts to forward on a source's first run
EOF
    chmod 600 "$CONF"
  fi
  info "Initialized in $BASE_DIR  -> edit $CONF"
}

need_ready() {
  [[ -d "$BASE_DIR" ]] || die "Run: $0 init"
  check_deps; load_conf
  [[ -n "$BOT_TOKEN" ]] || die "BOT_TOKEN not set in $CONF"
}

# ---------------------------------------------------------------- sources ---
cmd_add() {
  local type="" target="" chat="-" inc="-" exc="-" lang="-" ai="-" tpl="-"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --type) type="$2"; shift 2;;      --target) target="$2"; shift 2;;
      --chat) chat="$2"; shift 2;;      --include) inc="$2"; shift 2;;
      --exclude) exc="$2"; shift 2;;    --lang) lang="$2"; shift 2;;
      --ai) ai="$2"; shift 2;;          --template) tpl="$2"; shift 2;;
      *) die "Unknown option: $1";;
    esac
  done
  [[ -n "$type" && -n "$target" ]] || die "Need --type and --target"
  case "$type" in rss|youtube|reddit|twitter|tiktok|instagram|facebook|vk|telegram) ;;
    *) die "type must be: rss youtube reddit twitter tiktok instagram facebook vk telegram";; esac
  case "$ai" in -|summarize|rephrase) ;; *) die "--ai must be summarize or rephrase";; esac
  local id; id=$(( $(awk -F'\t' 'BEGIN{m=0} $1+0>m{m=$1+0} END{print m}' "$SRC" 2>/dev/null) + 1 ))
  tpl=${tpl//$'\t'/ }; tpl=${tpl//$'\n'/\\n}
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$type" "$target" "$chat" "$inc" "$exc" "$lang" "$ai" "$tpl" >>"$SRC"
  info "Added source #$id ($type: $target)"
}

cmd_list() {
  { printf 'ID\tTYPE\tTARGET\tCHAT\tINCLUDE\tEXCLUDE\tLANG\tAI\tTEMPLATE\n'; cat "$SRC"; } | column -t -s $'\t'
}

cmd_remove() {
  [[ -n "${1:-}" ]] || die "Usage: remove <id>"
  awk -F'\t' -v id="$1" '$1!=id' "$SRC" >"$TMP/s" && mv "$TMP/s" "$SRC"
  info "Removed source #$1"
}

feed_url() {
  local type=$1 t=$2 cid
  case "$type" in
    rss) echo "$t";;
    youtube)
      if [[ "$t" == UC* ]]; then echo "https://www.youtube.com/feeds/videos.xml?channel_id=$t"
      elif [[ "$t" == PL* ]]; then echo "https://www.youtube.com/feeds/videos.xml?playlist_id=$t"
      else
        cid=$(curl -fsSL --max-time 25 -A "$USER_AGENT" "https://www.youtube.com/@${t#@}" 2>/dev/null \
              | grep -o '"channelId":"UC[^"]*"' | head -1 | cut -d'"' -f4)
        [[ -n "$cid" ]] && echo "https://www.youtube.com/feeds/videos.xml?channel_id=$cid"
      fi;;
    reddit)
      case "$t" in u/*) echo "https://www.reddit.com/user/${t#u/}/.rss";;
                   r/*) echo "https://www.reddit.com/$t/.rss";;
                   *)   echo "https://www.reddit.com/r/$t/.rss";; esac;;
    twitter)
      if [[ -n "$NITTER_URL" ]]; then echo "${NITTER_URL%/}/${t#@}/rss"
      else echo "${RSSHUB_URL%/}/twitter/user/${t#@}"; fi;;
    telegram)  echo "${RSSHUB_URL%/}/telegram/channel/${t#@}";;
    tiktok)    echo "${RSSHUB_URL%/}/tiktok/user/@${t#@}";;
    instagram) echo "${RSSHUB_URL%/}/instagram/user/${t#@}";;
    facebook)  echo "${RSSHUB_URL%/}/facebook/page/$t";;
    vk)        echo "${RSSHUB_URL%/}/vk/user/$t";;
  esac
}

# ---------------------------------------------------------------- helpers ---
html2text() {
  tr '\r\n' '  ' | sed -E \
    -e 's#<br ?/?>#\n#gI' -e 's#</p>#\n\n#gI' -e 's#<[^>]*>##g' \
    -e 's/&nbsp;/ /g' -e 's/&lt;/</g' -e 's/&gt;/>/g' -e 's/&quot;/"/g' \
    -e "s/&#0?39;/'/g" -e 's/&amp;/\&/g' | cat -s | sed -E 's/^[[:space:]]+//;s/[[:space:]]+$//'
}
esc_html() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }
trunc()    { local s=$1 n=$2; ((${#s} > n)) && s="${s:0:n}…"; printf '%s' "$s"; }
sha()      { printf '%s' "$1" | sha1sum | cut -d' ' -f1; }

translate() {
  local text=$1 lang=$2 out
  out=$(curl -fsS --max-time 20 -G "https://translate.googleapis.com/translate_a/single" \
        --data-urlencode "client=gtx" --data-urlencode "sl=auto" --data-urlencode "tl=$lang" \
        --data-urlencode "dt=t" --data-urlencode "q=$(trunc "$text" 1800)" 2>/dev/null \
        | jq -r '[.[0][]?[0]] | join("")' 2>/dev/null)
  [[ -n "$out" ]] && printf '%s' "$out" || printf '%s' "$text"
}

ai_process() {
  local mode=$1 text=$2 prompt out
  [[ -n "$OPENAI_API_KEY" ]] || { printf '%s' "$text"; return; }
  case "$mode" in
    summarize) prompt="Summarize the following social/news post in 2-3 concise sentences. Keep the original language. Output only the summary.";;
    rephrase)  prompt="Rephrase the following post in clear, neutral wording. Keep meaning and language. Output only the rewritten text.";;
    *) printf '%s' "$text"; return;;
  esac
  out=$(jq -n --arg m "$OPENAI_MODEL" --arg p "$prompt" --arg t "$(trunc "$text" 6000)" \
        '{model:$m,temperature:0.3,messages:[{role:"system",content:$p},{role:"user",content:$t}]}' \
      | curl -fsS --max-time 60 "${OPENAI_BASE%/}/chat/completions" \
        -H "Authorization: Bearer $OPENAI_API_KEY" -H "Content-Type: application/json" -d @- 2>/dev/null \
      | jq -r '.choices[0].message.content // empty' 2>/dev/null)
  [[ -n "$out" ]] && printf '%s' "$out" || printf '%s' "$text"
}

tg() { local m=$1; shift; curl -sS --max-time 60 "https://api.telegram.org/bot${BOT_TOKEN}/${m}" "$@" 2>/dev/null; }

tg_ok() {  # returns 0 if ok, handles 429
  local resp=$1 wait
  [[ "$(jq -r '.ok' <<<"$resp" 2>/dev/null)" == "true" ]] && return 0
  wait=$(jq -r '.parameters.retry_after // empty' <<<"$resp" 2>/dev/null)
  [[ -n "$wait" ]] && { log "Rate limited, sleeping ${wait}s"; sleep "$((wait + 1))"; }
  log "Telegram error: $(jq -r '.description // "unknown"' <<<"$resp" 2>/dev/null)"
  return 1
}

send_one() {  # chat text media kind
  local chat=$1 text=$2 media=$3 kind=$4 resp
  if [[ -n "$media" && "$kind" == "photo" && ${#text} -le 1000 ]]; then
    resp=$(tg sendPhoto -d "chat_id=$chat" -d parse_mode=HTML --data-urlencode "caption=$text" --data-urlencode "photo=$media")
    tg_ok "$resp" && return 0
  elif [[ -n "$media" && "$kind" == "video" && ${#text} -le 1000 ]]; then
    resp=$(tg sendVideo -d "chat_id=$chat" -d parse_mode=HTML --data-urlencode "caption=$text" --data-urlencode "video=$media")
    tg_ok "$resp" && return 0
  fi
  resp=$(tg sendMessage -d "chat_id=$chat" -d parse_mode=HTML --data-urlencode "text=$(trunc "$text" 4000)")
  tg_ok "$resp"
}

send_all() {  # chats(comma-sep) text media kind
  local chats=$1 text=$2 media=$3 kind=$4 c rc=1
  IFS=',' read -ra arr <<<"$chats"
  for c in "${arr[@]}"; do
    c=${c// /}; [[ -n "$c" ]] || continue
    send_one "$c" "$text" "$media" "$kind" && rc=0
    sleep 1
  done
  return $rc
}

# ----------------------------------------------------------- feed parsing ---
xp() { xmllint --recover --noout --xpath "$1" "$FEED" 2>/dev/null; }
xv() { xmllint --recover --xpath "$1" "$FEED" 2>/dev/null; }

process_source() {
  local line=$1 id type target chat inc exc lang ai tpl
  IFS=$'\t' read -r id type target chat inc exc lang ai tpl <<<"$line"
  [[ -z "${id:-}" ]] && return 0
  [[ "$chat" == "-" || -z "$chat" ]] && chat="$DEFAULT_CHAT"
  [[ "$inc" == "-" ]] && inc=""; [[ "$exc" == "-" ]] && exc=""
  [[ "$lang" == "-" ]] && lang=""; [[ "$ai" == "-" ]] && ai=""
  [[ "$tpl" == "-" || -z "$tpl" ]] && tpl='<b>{title}</b>\n\n{summary}\n\n🔗 {link}\n📡 {source}'
  [[ -n "$chat" ]] || { log "#$id: no chat configured"; return 0; }

  local url; url=$(feed_url "$type" "$target")
  [[ -n "$url" ]] || { log "#$id: cannot resolve feed for $type:$target"; return 0; }

  FEED="$TMP/feed_$id.xml"
  if ! curl -fsSL --max-time 40 -A "$USER_AGENT" "$url" -o "$FEED" 2>/dev/null; then
    log "#$id: fetch failed ($url)"; return 0
  fi

  local n; n=$(xv "count(//*[local-name()='item' or local-name()='entry'])")
  n=${n%.*}; [[ "$n" =~ ^[0-9]+$ ]] || n=0
  ((n > 0)) || { log "#$id: no items"; return 0; }

  local marker="$BASE_DIR/.init_$id" first=0 i
  [[ -f "$marker" ]] || first=1

  local base guid link title raw date media kind key
  # first run: mark everything seen except the newest BACKFILL items
  if ((first)); then
    for ((i = n; i >= 1; i--)); do
      ((i <= BACKFILL)) && continue
      base="(//*[local-name()='item' or local-name()='entry'])[$i]"
      guid=$(xv "string($base/*[local-name()='guid' or local-name()='id'][1])")
      link=$(xv "string($base/*[local-name()='link'][1])")
      [[ -z "$link" ]] && link=$(xv "string($base/*[local-name()='link'][1]/@href)")
      echo "$(sha "$id|${guid:-$link}")" >>"$SEEN"
    done
    touch "$marker"
  fi

  local limit=$n; ((limit > MAX_PER_SOURCE)) && limit=$MAX_PER_SOURCE
  ((first && BACKFILL > 0 && limit > BACKFILL)) && limit=$BACKFILL
  local sent=0
  for ((i = limit; i >= 1; i--)); do
    base="(//*[local-name()='item' or local-name()='entry'])[$i]"
    guid=$(xv "string($base/*[local-name()='guid' or local-name()='id'][1])")
    link=$(xv "string($base/*[local-name()='link'][1])")
    [[ -z "$link" ]] && link=$(xv "string($base/*[local-name()='link'][1]/@href)")
    key=$(sha "$id|${guid:-$link}")
    grep -qxF "$key" "$SEEN" 2>/dev/null && continue

    title=$(xv "string($base/*[local-name()='title'][1])" | html2text)
    raw=$(xv "string($base/*[local-name()='description' or local-name()='summary' or local-name()='encoded' or (local-name()='content' and not(@url))][1])")
    date=$(xv "string($base/*[local-name()='pubDate' or local-name()='published' or local-name()='updated' or local-name()='date'][1])")
    local body; body=$(printf '%s' "$raw" | html2text)

    # ---- filters (case-insensitive regex on title+body)
    local hay="$title $body"
    if [[ -n "$inc" ]] && ! grep -Eiq -- "$inc" <<<"$hay"; then echo "$key" >>"$SEEN"; continue; fi
    if [[ -n "$exc" ]] &&   grep -Eiq -- "$exc" <<<"$hay"; then echo "$key" >>"$SEEN"; continue; fi

    # ---- media discovery
    media=$(xv "string($base//*[local-name()='enclosure' or local-name()='content' or local-name()='thumbnail'][@url][1]/@url)")
    [[ -z "$media" ]] && media=$(grep -oiE '<video[^>]+src="[^"]+"|<source[^>]+src="[^"]+"' <<<"$raw" | head -1 | sed -E 's/.*src="([^"]+)".*/\1/')
    [[ -z "$media" ]] && media=$(grep -oiE '<img[^>]+src="[^"]+"' <<<"$raw" | head -1 | sed -E 's/.*src="([^"]+)".*/\1/')
    media=${media//&amp;/&}
    kind=""
    if [[ -n "$media" ]]; then
      case "${media%%\?*}" in
        *.mp4|*.mov|*.webm|*.m4v) kind="video";;
        *) kind="photo";;
      esac
    fi

    # ---- translate / AI
    local ttl="$title" sum; sum=$(trunc "$body" 1500)
    if [[ -n "$lang" ]]; then ttl=$(translate "$ttl" "$lang"); sum=$(translate "$sum" "$lang"); fi
    local aitxt=""
    if [[ -n "$ai" ]]; then aitxt=$(ai_process "$ai" "$title"$'\n\n'"$body"); sum="$aitxt"; fi
    sum=$(trunc "$sum" 700)

    # ---- template render
    local out=$tpl
    out=${out//\\n/$'\n'}
    out=${out//\{title\}/$(printf '%s' "$ttl" | esc_html)}
    out=${out//\{summary\}/$(printf '%s' "$sum" | esc_html)}
    out=${out//\{link\}/$(printf '%s' "$link" | esc_html)}
    out=${out//\{source\}/$(printf '%s' "$type:$target" | esc_html)}
    out=${out//\{date\}/$(printf '%s' "$date" | esc_html)}
    out=${out//\{ai\}/$(printf '%s' "$aitxt" | esc_html)}

    if send_all "$chat" "$out" "$media" "$kind"; then
      echo "$key" >>"$SEEN"; ((sent++))
      log "#$id sent: $(trunc "$title" 70)"
    else
      log "#$id failed (will retry next cycle): $(trunc "$title" 70)"
    fi
  done
  ((sent > 0)) && log "#$id ($type:$target) forwarded $sent post(s)"
  return 0
}

run_cycle() {
  local line
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    process_source "$line"
  done <"$SRC"
}

cmd_once() { need_ready; run_cycle; info "Cycle complete."; }

cmd_run() {
  need_ready
  if command -v flock >/dev/null 2>&1; then
    exec 9>"$LOCK"; flock -n 9 || die "AximoBot already running"
  fi
  log "AximoBot started (interval ${INTERVAL}s)"
  trap 'log "Stopping."; exit 0' INT TERM
  while true; do
    load_conf; run_cycle
    sleep "$INTERVAL"
  done
}

cmd_test() {  # dry-run: show what a source would forward, no sending
  need_ready
  local line; line=$(awk -F'\t' -v id="${1:-}" '$1==id' "$SRC")
  [[ -n "$line" ]] || die "Usage: test <id>"
  local id type target; IFS=$'\t' read -r id type target _ <<<"$line"
  local url; url=$(feed_url "$type" "$target"); info "Feed URL: $url"
  FEED="$TMP/t.xml"; curl -fsSL --max-time 40 -A "$USER_AGENT" "$url" -o "$FEED" || die "Fetch failed"
  local n; n=$(xv "count(//*[local-name()='item' or local-name()='entry'])"); n=${n%.*}
  info "Items found: $n"
  local i; for ((i = 1; i <= n && i <= 5; i++)); do
    echo " - $(xv "string((//*[local-name()='item' or local-name()='entry'])[$i]/*[local-name()='title'][1])" | html2text | head -c 100)"
  done
}

cmd_ping() {
  need_ready
  local chat=${1:-$DEFAULT_CHAT}; [[ -n "$chat" ]] || die "Usage: ping <chat_id>"
  send_one "$chat" "<b>AximoBot online</b> ✅"$'\n'"Coded by Mr Sabaz Ali Khan" "" "" && info "Sent." || die "Failed (check token/chat/admin rights)"
}

usage() {
  cat <<EOF
${B}Usage:${N} $0 <command>

  init                         create ~/.aximobot and config
  add --type T --target X [--chat ID[,ID]] [--include RE] [--exclude RE]
      [--lang xx] [--ai summarize|rephrase] [--template 'HTML with {title} {summary} {link} {source} {date} {ai}']
  list                         show sources
  remove <id>                  delete a source
  test <id>                    dry-run a source (no sending)
  ping [chat]                  send a test message
  once                         run a single polling cycle
  run                          run forever (every INTERVAL seconds)

${B}Types:${N} rss youtube reddit twitter tiktok instagram facebook vk telegram

${B}Examples:${N}
  $0 add --type rss --target https://feeds.bbci.co.uk/news/world/rss.xml --chat @mychannel --lang en
  $0 add --type youtube --target @SomeChannel --ai summarize
  $0 add --type reddit --target r/netsec --include 'CVE|ransomware|0day' --exclude 'meme'
  $0 add --type telegram --target somechannel --chat -1001234567890 --lang en
  $0 add --type twitter --target cisagov --template '<b>{title}</b>\n{link}'

${Y}Note:${N} TikTok/Instagram/Twitter/Facebook/VK/Telegram go through RSSHub (set RSSHUB_URL,
self-hosting recommended). Respect each platform's terms and only monitor public content
within authorized scope.
EOF
}

main() {
  local cmd=${1:-help}; shift || true
  banner
  case "$cmd" in
    init)   cmd_init;;
    add)    need_ready; cmd_add "$@";;
    list)   [[ -d "$BASE_DIR" ]] || die "Run init first"; cmd_list;;
    remove) [[ -d "$BASE_DIR" ]] || die "Run init first"; cmd_remove "$@";;
    test)   cmd_test "$@";;
    ping)   cmd_ping "$@";;
    once)   cmd_once;;
    run)    cmd_run;;
    *)      usage;;
  esac
}
main "$@"
