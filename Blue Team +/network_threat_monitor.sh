#!/usr/bin/env bash
# ==============================================================================
#  Network Threat Monitor (NTM) v1.0
#  Coded by Mr Sabaz Ali Khan  |  Cyber Security Engineer
#
#  Defensive host/network monitoring: watches the local connection table, ARP
#  cache, listeners and (optionally) live SYN traffic for signs of compromise
#  or hostile activity. Use only on systems you own or are authorized to monitor.
# ==============================================================================

set -uo pipefail

VERSION="1.0"
AUTHOR="Mr Sabaz Ali Khan"

# ------------------------------ Colors ----------------------------------------
if [[ -t 1 ]]; then
  R=$'\033[1;31m'; G=$'\033[1;32m'; Y=$'\033[1;33m'; B=$'\033[1;34m'
  C=$'\033[1;36m'; M=$'\033[1;35m'; W=$'\033[1;37m'; N=$'\033[0m'
else
  R=""; G=""; Y=""; B=""; C=""; M=""; W=""; N=""
fi

# ------------------------------ Banner ----------------------------------------
print_banner() {
  printf '%s' "$C"
  cat <<'BANNER'
⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠒⠒⠶⠤⢤⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣤⠶⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠴⠖⣛⣭⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⢾⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠲⢤⡀⠀⠀⠀⠀⠀
⠀⠀⢀⡴⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⣀⣀⣤⡴⠚⢉⣤⣶⣞⣉⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠶⢋⣴⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢦⡀⠀⠀⠀
⠀⢠⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣴⣶⣾⣿⣿⣿⣿⣿⠿⠋⠁⣠⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣦⣤⣀⣴⠞⢁⣴⣿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣄⠀⠀
⢠⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⡿⠛⠁⢀⣤⣾⡿⣿⣿⣿⣿⠿⢛⣿⣿⣿⣿⣿⣿⡿⠋⢀⣴⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⡄⠀
⠼⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⣠⣶⠟⢫⣵⣾⣿⡿⠋⠀⣴⣿⣿⣿⣿⡿⠛⠁⢀⡴⢋⣼⣿⣿⣿⣿⣶⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢷⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠃⠀⣠⡾⠋⢀⡼⣻⣿⡿⠋⢀⡾⣹⣿⣿⡿⠛⠉⢀⣠⠞⢋⣰⣿⣿⣿⣿⣿⡿⣿⣿⣿⣷⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⡇
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣫⡾⠁⣠⣾⠟⠀⢀⡞⢱⣿⡿⠁⢠⣿⡴⠟⠋⠁⢀⣠⠴⠋⢁⡴⣿⣿⣿⣿⣿⠟⠁⢠⣿⣿⣿⣿⣿⣿⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⣠⣿⢡⣾⣿⠏⠀⣀⣾⠴⠞⣻⠷⠚⠉⠀⠀⢀⣤⠖⠋⠀⣠⡴⣫⣾⣿⣿⣿⠟⢁⡴⢻⣿⠿⠿⢿⣿⣿⣿⣿⣿⣶⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⢰⣿⣿⣿⣟⡵⠖⠋⠉⠀⠀⠀⠁⠀⢀⣶⡶⠞⠉⣀⣠⠶⣛⣥⣾⠿⣋⡽⠋⢁⣴⠋⠀⣼⣿⣀⣀⣤⣤⣬⣽⣿⣿⣿⣿⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠇
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⣼⣿⠇⠐⡞⠘⣿⡿⠋⠀⠀⠐⠋⠁⠀⠀⠀⠞⠋⢁⣤⠶⢛⣩⣶⡿⢟⣋⡤⠞⣋⡤⠞⢋⡾⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⢸⣿⡟⠀⢸⣧⡴⠋⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⢠⡞⠉⣠⣾⣿⡿⠟⠛⢉⣡⡴⠞⠉⠀⢀⡾⠁⢀⣿⣷⠏⡉⠿⣥⡀⠀⠀⠈⢉⣙⠛⠿⢿⣿⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⢸⢻⡇⠀⠘⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⠋⣠⠟⢠⣾⠟⠋⢁⣤⣶⡟⢋⡟⠁⠀⠀⢠⠞⠁⣠⣾⣿⡟⠀⠀⠀⢾⣧⡀⠄⠀⠀⠀⠀⠒⣶⣬⣝⣿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣿⡇⠀⣸⠟⠁⣠⠞⢁⡤⢤⠀⠀⠰⠂⠀⢀⣀⡴⠞⠋⢀⡟⠁⣠⣶⣿⣿⠃⠀⢸⡄⠀⣠⠾⢋⣠⡾⣿⣿⣟⡀⠀⠀⠹⢤⠛⠙⢶⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢁⡟⠃⠐⢃⢠⡾⢧⡄⠀⡴⠋⢀⡿⠋⣀⣀⣭⠖⣀⣤⠷⠾⢶⣾⣿⣯⣤⣼⣧⠤⠴⠒⣋⣥⣶⠿⣯⣜⠋⠻⣌⠙⢀⠀⠀⠈⢧⡀⠰⣿⣌⠉⢉⣛⠻⢿⣿⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣧⡞⠀⠀⢠⡾⠟⠀⡞⢀⣼⣁⣴⣋⡴⠞⠋⣉⣴⢞⣁⣤⡴⠋⠉⠀⠠⠆⠀⢀⣠⣴⣶⡿⠛⠉⠀⣠⠞⠉⠻⢦⡈⠙⢺⣄⠀⠀⠀⠉⠀⣷⣼⣦⡀⢀⣀⣀⣈⠙⢿⣿⣿⡆⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠉⠀⠀⠀⠆⠀⠀⣸⢷⣾⣿⣿⣿⣿⣟⣉⣹⡿⠟⠉⠁⢀⣤⢤⡶⠒⠛⠛⠛⢛⣻⣿⣁⣀⢀⣠⣴⠀⠀⠀⠀⠀⣹⣦⡘⠉⠳⣄⠀⠀⠀⢹⡝⢦⡻⣤⣤⣾⣿⣿⣿⣾⣿⣿⡄⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⢀⣾⢯⣿⣿⣿⣿⣿⣿⡿⠋⡽⠁⣠⡤⠖⠋⠀⠀⢀⣠⣤⣶⣚⣋⣭⣴⣾⠿⢻⡿⠁⠄⠀⠀⣀⣴⣿⠋⢳⣦⡀⠙⢦⣀⠀⠀⠹⣼⣷⡟⠻⢿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇⠀⠀⠀⠈⠟⣷⣾⣿⣿⣿⣾⣿⡿⢱⡾⠁⠀⠀⠀⠀⠐⣾⡾⠋⠉⣈⣩⠽⠟⠋⣁⣤⣾⣋⣀⣠⣤⠶⠟⠉⣼⠋⠀⠀⠉⢷⣀⡾⠈⠀⠀⠀⣿⡈⣧⠠⢤⡈⠛⢿⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀⢀⣴⣿⡿⠟⠛⣛⣻⡭⠞⠋⠀⠀⠀⠀⠀⠀⢈⣿⠽⣻⠟⠛⠛⠛⠋⢉⣩⣵⣾⣿⠋⠁⠀⠀⣠⠞⠁⠀⠀⠀⠀⢈⣿⠁⠀⠀⢰⡆⠘⣿⠙⣿⣿⣉⡁⣄⠹⣿⣿⣿⣧⠀⠀⠀⠀⡇
⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠁⠀⠀⠀⠀⣰⠟⢉⡍⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⣀⣠⡴⠞⠁⣴⣿⠶⠦⠴⠶⠖⢛⣿⣿⣿⣿⣶⡀⠀⠀⠉⠀⠀⠀⣀⣤⡾⠛⣿⡀⠀⠀⠀⠳⢸⠛⠷⠿⣿⣿⣿⣿⣤⣹⣿⣿⣿⠀⠀⠀⠀⡇
⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⣿⡿⠋⠀⠀⢀⣀⡴⠛⣡⠞⠋⠀⠀⠀⠀⣀⣠⠴⠖⢋⣽⠟⠉⠁⠀⢀⣀⣠⣋⣤⣴⣖⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⠳⣶⠶⣶⡶⠟⠋⠁⠀⠀⢸⡇⠀⠀⠀⠀⢻⡶⢶⠀⣿⣯⡻⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⡧
⠀⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⠃⠈⠉⠛⠉⠙⠛⣿⡍⣡⡾⠃⠀⠀⣀⡤⠖⢋⣉⣤⡶⠿⠛⠁⠀⢀⣠⡬⠛⠯⣅⣀⠉⠉⣉⣉⣻⣿⣿⣿⣿⣿⣿⣿⣿⡄⢹⡿⠋⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠐⠈⣷⠾⠀⣿⡏⠳⡌⢻⣿⣿⣿⣿⡇⠀⠀⠀⡇
⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⡏⠀⠀⠀⢀⣴⣿⠇⣿⠛⢉⣤⠴⠚⠉⠁⣠⣶⡟⠋⠁⠀⠀⣀⣤⡾⠿⣷⣟⡉⠙⠛⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠻⣮⠁⠀⠀⢀⡀⠀⠀⢀⣠⡿⠀⠀⠀⢠⡿⣻⠀⠀⣿⡻⣦⠹⣆⢻⣿⣿⣿⡇⠀⠀⠀⡇
⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⢰⣿⠟⠁⠚⠁⠈⠉⠀⠀⢀⣤⠾⣻⠟⠁⢀⣠⠶⣚⣩⣭⣙⣛⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠉⠛⠟⠛⠛⠛⠒⠛⠉⢹⠇⠀⢀⡴⣯⣴⠏⢀⡇⣿⣿⣿⣷⡌⠈⢿⣿⣿⡇⠀⠀⠀⡇
⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣇⠀⢀⠀⠏⠀⠀⠀⠀⠀⣠⣶⡿⠟⠁⠘⠁⣠⣶⣿⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡟⠀⠀⠘⣷⡿⠇⠀⢸⠁⣿⠹⣿⣿⣷⣄⢸⣿⣿⠇⠀⠀⠀⡇
⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣆⡀⠀⣀⣀⣠⣤⠴⢺⣿⠏⠀⠀⢠⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠋⠻⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡾⠀⠀⠀⣰⠇⠀⠀⠀⠛⢀⣿⡀⠙⣿⣿⣿⣾⣿⣿⠀⠀⠀⠀⣿
⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣯⡉⠁⠀⠀⠀⠀⢀⣀⠐⣣⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠛⠉⠀⠀⠀⠈⠉⠙⠲⠶⠤⢤⣤⣤⣤⣴⡾⠁⠀⣠⣴⡏⠀⠀⠀⢀⡶⣸⡟⢷⡀⠘⣿⣿⣿⣿⡟⠀⠀⠀⠀⡟
⠀⠀⠀⠀⠈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⢶⣤⣤⣀⠻⣶⣭⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠛⠋⠉⠀⠘⢷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡼⠋⠀⠀⣴⢟⡿⠀⠀⠀⠀⠘⢡⣿⣿⣆⢷⡀⢻⣿⣿⣿⠃⠀⠀⠀⠀⡇
⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣿⣿⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠛⠉⠁⢻⣦⠀⠀⠀⠀⠀⠀⠙⢷⣄⠀⠀⠀⠀⠀⠀⢀⣠⠞⠉⠀⠀⠀⣸⠷⠞⠁⠀⠀⠀⠀⠀⣼⠻⣿⣿⣿⣧⢸⣿⣿⡟⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢿⣅⠀⠀⠀⠀⠀⠀⠈⠳⣦⡀⠀⠀⠀⠀⠀⠈⠳⢦⣀⣀⡤⠞⠋⠀⠀⠀⠀⢀⡴⠋⠀⠀⠀⠀⠀⠀⠀⢰⡏⠀⣿⣿⣿⣿⢸⣿⡿⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠟⠋⠁⠀⠀⠹⣷⣄⣀⠀⠀⠀⠀⠀⠈⠛⣦⡀⠀⢀⣀⡤⠶⠚⠋⠁⠀⠀⠀⠀⠀⠀⠐⣫⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⠇⡆⢹⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣟⠂⠀⠀⠀⠀⣀⣬⠿⠚⠋⠁⠀⠀⠀⠀⠀⠀⣠⠄⢀⣄⣋⡴⠋⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⠀⡇⣸⣿⣿⣿⣿⠋⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠉⠀⠻⢦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣶⣤⠖⠋⠉⠀⠀⠀⠀⢀⣠⣤⡖⢀⣶⢻⡏⠚⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⢿⣿⣿⡀⠇⣿⣿⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠋⠀⠀⠀⠀⠈⠙⠻⠷⢦⣄⡀⠤⠀⠀⢀⣴⠟⠀⠀⠀⠀⠀⠀⣠⣴⣏⣀⡿⠛⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⡿⢡⢸⣿⣿⡇⣸⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠹⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠓⠲⣶⠟⠁⠀⠀⠀⠀⠀⠀⣸⣿⣽⡿⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣾⣿⡅⢸⢸⣿⣿⣿⣿⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠉⠳⢦⣄⣀⠀⠀⠀⠀⠀⠀⠀⢀⡾⠃⠀⠀⠀⠀⢀⣀⣀⡾⢿⡶⢏⡴⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⡾⣿⢣⣿⣿⣷⠀⢸⣿⣿⣿⣿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠉⠙⠳⠶⣤⣤⣀⣠⣿⡼⠃⠀⠀⣀⣶⠋⣠⠿⢶⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣶⣿⣿⠟⣰⢏⣿⣿⣿⣿⢧⣿⣿⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⢫⠟⠋⠀⠀⢀⣴⣻⣯⡟⣁⡶⠋⠀⠀⠀⠀⠀⠀⠀⢀⣤⢾⡿⢩⣿⣿⣿⡿⠠⣯⣾⣿⣿⣿⣿⣿⡿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠇
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⡏⠀⠀⠀⢰⡏⣸⣃⣤⡟⠁⠀⠀⠀⠀⠀⠀⣀⣴⣾⣿⠳⠏⣰⣿⣿⣿⣿⣁⣴⣿⣿⣿⣿⣿⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡆
⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⢯⣛⠶⢤⣤⣤⣤⠀⠀⠀⠐⢚⡿⠀⠀⠀⠀⠈⢻⣿⣏⣽⠃⠀⠀⠀⠀⠀⣠⡼⠋⣼⣿⡟⢃⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⠀
⠸⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠶⣤⣉⠉⠉⠛⠛⠛⢻⣇⠀⠀⠀⠀⠀⢿⣾⣿⠁⠀⠀⠀⠀⢀⣾⡿⢀⣾⣿⣿⣴⣿⣿⣿⣿⣿⣿⣿⡿⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡇⠀
⠀⢻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠲⠦⣄⣀⢘⡟⠀⠀⠀⣠⠀⣿⠉⠙⠦⠀⠀⠀⠀⣾⣿⣷⣿⣿⣿⣿⣿⣿⣿⡿⠿⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡟⠀⠀
⠀⠀⠙⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠛⠒⠶⠤⢿⣶⣿⠀⠀⠀⠀⠀⠀⠰⣿⣿⠿⠿⠟⠛⠛⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠏⠀⠀⠀
⠀⠀⠀⠀⠙⠶⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠴⠋⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠉⠙⠓⠶⠦⠤⠤⠤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⡤⠤⠤⠴⠶⠒⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀
BANNER
  printf '%s\n' "$N"
  local l1 l2
  l1="NETWORK THREAT MONITOR  v${VERSION}  -  Bash Edition"
  l2="Coded by ${AUTHOR}  |  Cyber Security Engineer"
  printf '%s  ╔════════════════════════════════════════════════════════════════╗%s\n' "$R" "$N"
  printf '%s  ║%s%s%-64s%s%s║%s\n' "$R" "$N" "$W" " $l1" "$N" "$R" "$N"
  printf '%s  ║%s%s%-64s%s%s║%s\n' "$R" "$N" "$Y" " $l2" "$N" "$R" "$N"
  printf '%s  ╚════════════════════════════════════════════════════════════════╝%s\n\n' "$R" "$N"
}

# ------------------------------ Defaults --------------------------------------
INTERVAL=30                 # seconds between cycles in watch mode
WATCH=0                     # 1 = continuous monitoring
SCAN=0                      # 1 = live SYN sniffing for port-scan detection (root)
SCAN_WINDOW=10              # seconds to sniff per cycle
SCAN_PORT_THRESHOLD=15      # distinct dest ports from one source => port scan
CONN_THRESHOLD=50           # connections from one remote IP => flood/abuse
SYNRECV_THRESHOLD=20        # half-open connections from one IP => SYN flood
COOLDOWN=300                # seconds before the same alert is repeated
IFACE=""                    # interface for sniffing (auto-detected)
LOG_DIR="${NTM_LOG_DIR:-./ntm_logs}"
BLOCKLIST=""                # file with one malicious IP per line
SUSPICIOUS_PORTS="4444 5555 1337 31337 12345 54321 6667 6697 9001 9050 2222 8333 3333"
DO_BASELINE=0

# ------------------------------ State -----------------------------------------
declare -A LAST_ALERT=()
declare -A LEVEL_COUNT=([CRITICAL]=0 [HIGH]=0 [MEDIUM]=0 [INFO]=0)
CYCLE=0

usage() {
  cat <<EOF
Usage: sudo $0 [options]

  -w              Watch mode (loop forever)
  -i SECONDS      Interval between cycles (default: $INTERVAL)
  -s              Enable live SYN sniffing for port-scan detection (needs root + tcpdump)
  -I IFACE        Interface to sniff (default: auto)
  -b              Save/refresh baseline (listening ports + gateway MAC) and exit
  -B FILE         IP blocklist file (one IP per line, # comments allowed)
  -l DIR          Log directory (default: $LOG_DIR)
  -c N            Connections-per-IP flood threshold (default: $CONN_THRESHOLD)
  -p N            Distinct-ports scan threshold (default: $SCAN_PORT_THRESHOLD)
  -h              Show this help

Examples:
  sudo $0 -b                      # record a clean baseline first
  sudo $0 -w -i 20 -s -B bad.txt  # continuous monitoring with scan detection
EOF
}

# ------------------------------ Helpers ---------------------------------------
need() { command -v "$1" >/dev/null 2>&1; }

setup_logging() {
  mkdir -p "$LOG_DIR" 2>/dev/null || { echo "${R}Cannot create $LOG_DIR${N}"; exit 1; }
  ALERT_LOG="$LOG_DIR/alerts.log"
  BASE_LISTEN="$LOG_DIR/baseline_listeners.txt"
  BASE_GW="$LOG_DIR/baseline_gateway_mac.txt"
}

alert() {
  # alert LEVEL KEY MESSAGE
  local level="$1" key="$2" msg="$3" now color ts
  now=$(date +%s)
  if (( now - ${LAST_ALERT[$key]:-0} < COOLDOWN )); then return; fi
  LAST_ALERT[$key]=$now
  case "$level" in
    CRITICAL) color="$R" ;;
    HIGH)     color="$M" ;;
    MEDIUM)   color="$Y" ;;
    *)        color="$B" ;;
  esac
  ts=$(date '+%Y-%m-%d %H:%M:%S')
  printf '%s[%s] [%-8s]%s %s\n' "$color" "$ts" "$level" "$N" "$msg"
  printf '[%s] [%s] %s\n' "$ts" "$level" "$msg" >> "$ALERT_LOG"
  LEVEL_COUNT[$level]=$(( ${LEVEL_COUNT[$level]} + 1 ))
}

is_private() {
  [[ "$1" =~ ^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|::1$|fe80:|fc|fd) ]]
}

# Emits "remote_ip remote_port local_port state" for all non-listening TCP sockets
conn_table() {
  ss -Hnt 2>/dev/null | awk '
    { st=$1; l=$4; r=$5
      lp=l; sub(/.*:/,"",lp)
      rp=r; sub(/.*:/,"",rp)
      ri=r; sub(/:[0-9]+$/,"",ri); gsub(/[\[\]]/,"",ri)
      print ri, rp, lp, st }'
}

# ------------------------------ Checks ----------------------------------------
check_blocklist() {
  [[ -n "$BLOCKLIST" && -f "$BLOCKLIST" ]] || return
  local bad
  bad=$(grep -Fx -f <(grep -Ev '^\s*(#|$)' "$BLOCKLIST") <(conn_table | awk '{print $1}' | sort -u) 2>/dev/null)
  local ip
  for ip in $bad; do
    alert CRITICAL "block:$ip" "Connection with BLOCKLISTED IP $ip detected"
  done
}

check_suspicious_ports() {
  local ri rp lp st p
  while read -r ri rp lp st; do
    [[ -z "$ri" ]] && continue
    is_private "$ri" && continue
    for p in $SUSPICIOUS_PORTS; do
      if [[ "$rp" == "$p" ]]; then
        alert HIGH "sp-out:$ri:$rp" "Outbound connection to suspicious port $rp on $ri (possible C2 / backdoor / tunnel)"
      elif [[ "$lp" == "$p" ]]; then
        alert HIGH "sp-in:$ri:$lp" "Inbound connection from $ri to suspicious local port $lp"
      fi
    done
  done < <(conn_table)
}

check_conn_flood() {
  local cnt ip
  while read -r cnt ip; do
    [[ -z "$ip" ]] && continue
    case "$ip" in 127.*|::1|"*"|"") continue ;; esac
    if (( cnt >= CONN_THRESHOLD )); then
      alert HIGH "flood:$ip" "Connection flood: $ip holds $cnt concurrent connections (threshold $CONN_THRESHOLD)"
    fi
  done < <(conn_table | awk '{c[$1]++} END{for(i in c) print c[i], i}')
}

check_syn_flood() {
  local cnt ip
  while read -r cnt ip; do
    [[ -z "$ip" ]] && continue
    if (( cnt >= SYNRECV_THRESHOLD )); then
      alert CRITICAL "synflood:$ip" "Possible SYN flood: $cnt half-open connections from $ip"
    fi
  done < <(ss -Hnt state syn-recv 2>/dev/null | awk '{r=$4; sub(/:[0-9]+$/,"",r); gsub(/[\[\]]/,"",r); c[r]++} END{for(i in c) print c[i], i}')
}

snapshot_listeners() {
  ss -Hntuln 2>/dev/null | awk '{l=$5; p=l; sub(/.*:/,"",p); print $1"/"p}' | sort -u
}

check_listeners() {
  [[ -f "$BASE_LISTEN" ]] || return
  local new
  new=$(comm -13 "$BASE_LISTEN" <(snapshot_listeners))
  local l
  for l in $new; do
    alert HIGH "listen:$l" "NEW listening service not in baseline: $l (possible backdoor/bind shell)"
  done
}

check_arp() {
  need ip || return
  # Same MAC claimed by multiple IPs => possible ARP spoofing / MITM
  local dups
  dups=$(ip -4 neigh show 2>/dev/null | awk '/lladdr/ && $NF!="FAILED" {m[$5]=m[$5]" "$1; c[$5]++} END{for(k in c) if(c[k]>1) print k":"m[k]}')
  local d
  while IFS= read -r d; do
    [[ -z "$d" ]] && continue
    alert MEDIUM "arpdup:${d%%:*}" "ARP anomaly: MAC ${d%%:*} claimed by multiple IPs —${d#*:} (possible ARP spoofing)"
  done <<< "$dups"

  # Gateway MAC change vs baseline
  local gw mac old
  gw=$(ip route show default 2>/dev/null | awk '{print $3; exit}')
  [[ -z "$gw" ]] && return
  mac=$(ip neigh show "$gw" 2>/dev/null | awk '/lladdr/{print $5; exit}')
  [[ -z "$mac" ]] && return
  if [[ -f "$BASE_GW" ]]; then
    old=$(awk -v g="$gw" '$1==g{print $2}' "$BASE_GW")
    if [[ -n "$old" && "$old" != "$mac" ]]; then
      alert CRITICAL "gwmac" "Gateway $gw MAC changed $old -> $mac (likely ARP poisoning / MITM)"
    fi
  fi
}

check_promisc() {
  need ip || return
  local i
  for i in $(ip -o link show 2>/dev/null | awk -F': ' '/PROMISC/{print $2}'); do
    alert MEDIUM "promisc:$i" "Interface $i is in PROMISCUOUS mode (sniffer running?)"
  done
}

check_scan() {
  (( SCAN )) || return
  need tcpdump || { alert INFO "notcpdump" "tcpdump not installed; skipping scan detection"; return; }
  (( EUID == 0 )) || { alert INFO "noroot" "Not root; skipping SYN sniffing"; return; }
  local iface="${IFACE:-$(ip route show default 2>/dev/null | awk '{print $5; exit}')}"
  iface="${iface:-any}"
  local out
  out=$(timeout "$SCAN_WINDOW" tcpdump -nn -l -q -i "$iface" \
        'tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn' 2>/dev/null | awk -v th="$SCAN_PORT_THRESHOLD" '
    $2=="IP" || $2=="IP6" {
      src=$3; sub(/\.[0-9]+$/,"",src)
      dst=$5; sub(/:$/,"",dst); dp=dst; sub(/.*\./,"",dp)
      k=src SUBSEP dp
      if (!(k in seen)) { seen[k]=1; n[src]++ }
    }
    END { for (s in n) if (n[s] >= th) print n[s], s }')
  local cnt ip
  while read -r cnt ip; do
    [[ -z "$ip" ]] && continue
    alert CRITICAL "scan:$ip" "PORT SCAN detected from $ip — $cnt distinct ports probed in ${SCAN_WINDOW}s on $iface"
  done <<< "$out"
}

# ------------------------------ Baseline --------------------------------------
save_baseline() {
  snapshot_listeners > "$BASE_LISTEN"
  local gw mac
  gw=$(ip route show default 2>/dev/null | awk '{print $3; exit}')
  if [[ -n "$gw" ]]; then
    mac=$(ip neigh show "$gw" 2>/dev/null | awk '/lladdr/{print $5; exit}')
    [[ -n "$mac" ]] && echo "$gw $mac" > "$BASE_GW"
  fi
  echo "${G}[+] Baseline saved in $LOG_DIR ($(wc -l < "$BASE_LISTEN") listeners)${N}"
}

# ------------------------------ Summary ---------------------------------------
summary() {
  local est
  est=$(ss -Hnt state established 2>/dev/null | wc -l)
  printf '%s── Cycle %d complete | established: %s | CRIT:%d HIGH:%d MED:%d INFO:%d ──%s\n' \
    "$C" "$CYCLE" "$est" "${LEVEL_COUNT[CRITICAL]}" "${LEVEL_COUNT[HIGH]}" "${LEVEL_COUNT[MEDIUM]}" "${LEVEL_COUNT[INFO]}" "$N"
}

run_cycle() {
  CYCLE=$((CYCLE + 1))
  printf '%s[*] Scan cycle %d @ %s%s\n' "$W" "$CYCLE" "$(date '+%H:%M:%S')" "$N"
  check_blocklist
  check_suspicious_ports
  check_conn_flood
  check_syn_flood
  check_listeners
  check_arp
  check_promisc
  check_scan
  summary
}

# ------------------------------ Main ------------------------------------------
while getopts ":wi:sI:bB:l:c:p:h" opt; do
  case "$opt" in
    w) WATCH=1 ;;
    i) INTERVAL="$OPTARG" ;;
    s) SCAN=1 ;;
    I) IFACE="$OPTARG" ;;
    b) DO_BASELINE=1 ;;
    B) BLOCKLIST="$OPTARG" ;;
    l) LOG_DIR="$OPTARG" ;;
    c) CONN_THRESHOLD="$OPTARG" ;;
    p) SCAN_PORT_THRESHOLD="$OPTARG" ;;
    h) print_banner; usage; exit 0 ;;
    *) print_banner; usage; exit 1 ;;
  esac
done

print_banner

for dep in ss ip awk; do
  need "$dep" || { echo "${R}[!] Missing dependency: $dep${N}"; exit 1; }
done
(( EUID == 0 )) || echo "${Y}[!] Not running as root — process info and SYN sniffing are limited.${N}"

setup_logging
trap 'echo; echo "${G}[+] Stopped. Alerts logged to $ALERT_LOG${N}"; exit 0' INT TERM

if (( DO_BASELINE )); then
  save_baseline
  exit 0
fi

[[ -f "$BASE_LISTEN" ]] || echo "${Y}[!] No baseline found — run '$0 -b' on a clean system to enable new-listener detection.${N}"

echo "${G}[+] Monitoring started | interval=${INTERVAL}s | scan-detect=$([[ $SCAN -eq 1 ]] && echo ON || echo OFF) | log=$ALERT_LOG${N}"
echo

while true; do
  run_cycle
  (( WATCH )) || break
  echo
  sleep "$INTERVAL"
done
