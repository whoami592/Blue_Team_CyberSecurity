#!/usr/bin/env python3
# ============================================================
#   ██████╗ ██╗  ██╗ ██████╗  ██████╗ ██╗  ██╗
#   ██╔══██╗██║  ██║██╔═══██╗██╔═══██╗██║ ██╔╝
#   ██████╔╝███████║██║   ██║██║   ██║█████╔╝
#   ██╔══██╗██╔══██║██║   ██║██║   ██║██╔═██╗
#   ██║  ██║██║  ██║╚██████╔╝╚██████╔╝██║  ██╗
#   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝
#        WIFI PASSWORD VIEWER v2.0
#     Coded by: CYBER SECURITY ENGINEER
#              MR. SABAZ ALI KHAN
# ============================================================

import subprocess
import sys
import time
from datetime import datetime

# ---------- COLORS (Hacker Terminal Style) ----------
if sys.platform == "win32":
    subprocess.run("", shell=True)  # enable ANSI on Windows
    class C:
        GREEN  = "\033[92m"
        CYAN   = "\033[96m"
        RED    = "\033[91m"
        YELLOW = "\033[93m"
        MAGENTA= "\033[95m"
        WHITE  = "\033[97m"
        DIM    = "\033[90m"
        BOLD   = "\033[1m"
        RESET  = "\033[0m"
else:
    class C:
        GREEN  = "\033[92m"; CYAN = "\033[96m"; RED = "\033[91m"
        YELLOW = "\033[93m"; MAGENTA = "\033[95m"; WHITE = "\033[97m"
        DIM = "\033[90m"; BOLD = "\033[1m"; RESET = "\033[0m"

BANNER = f"""{C.GREEN}{C.BOLD}
  ██╗    ██╗██╗███████╗██╗     ██████╗
  ██║    ██║██║██╔════╝██║    ██╔═══██╗
  ██║ █╗ ██║██║█████╗  ██║    ██║   ██║
  ██║███╗██║██║██╔══╝  ██║    ██║   ██║
  ╚███╔███╔╝██║██║     ███████╗╚██████╔╝
   ╚══╝╚══╝ ╚═╝╚═╝     ╚══════╝ ╚═════╝
        P A S S W O R D   V I E W E R
{C.RESET}{C.DIM}  ────────────────────────────────────────────
   [+] Coded by : MR. SABAZ ALI KHAN
   [+] Role     : Cyber Security Engineer
   [+] Status   : {C.RED}ANONYMOUS MODE ACTIVE{C.DIM}
   [+] Date     : {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}
  ────────────────────────────────────────────{C.RESET}"""


def get_profiles():
    """Saved WiFi profiles ki list nikalo"""
    data = subprocess.run(["netsh", "wlan", "show", "profiles"],
                          capture_output=True, text=True).stdout
    profiles = []
    for line in data.split("\n"):
        if "All User Profile" in line or "सभी उपयोगकर्ता प्रोफ़ाइल" in line:
            name = line.split(":")[1].strip()
            if name:
                profiles.append(name)
    return profiles


def get_password(profile):
    """Ek profile ka password extract karo"""
    data = subprocess.run(
        ["netsh", "wlan", "show", "profile", f"name={profile}", "key=clear"],
        capture_output=True, text=True).stdout
    for line in data.split("\n"):
        if "Key Content" in line or "मुख्य सामग्री" in line:
            return line.split(":")[1].strip()
    return None


def hacker_typing(text, delay=0.02):
    for ch in text:
        print(ch, end="", flush=True)
        time.sleep(delay)
    print()


def loading_animation():
    frames = ["|", "/", "-", "\\"]
    print(f"{C.CYAN}  [*] Scanning WiFi profiles... {C.RESET}", end="")
    for f in frames * 4:
        print(f"\r  [*] Scanning WiFi profiles... {C.MAGENTA}{f}{C.RESET}", end="")
        time.sleep(0.1)
    print()


def main():
    print(BANNER)
    loading_animation()

    profiles = get_profiles()
    if not profiles:
        print(f"{C.RED}  [!] Koi saved WiFi profile nahi mila!{C.RESET}")
        return

    print(f"{C.GREEN}  [+] {len(profiles)} WiFi profiles found!\n{C.RESET}")
    print(f"{C.DIM}  ┌────────────────────────────────────────────┐{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}     NO.   SSID NAME                  PASSWORD{C.RESET}")
    print(f"{C.DIM}  └────────────────────────────────────────────┘{C.RESET}")

    for i, p in enumerate(profiles, 1):
        pwd = get_password(p)
        if pwd:
            print(f"{C.GREEN}     {i:<4} {p[:25]:<25} {C.RED}{C.BOLD}{pwd}{C.RESET}")
        else:
            print(f"{C.YELLOW}     {i:<4} {p[:25]:<25} [OPEN NETWORK]{C.RESET}")

    print(f"\n{C.MAGENTA}  ═══════════════════════════════════════════{C.RESET}")
    hacker_typing(f"{C.GREEN}  [*] TASK COMPLETE — SESSION TERMINATED{C.RESET}")
    print(f"{C.DIM}     ~ Anonymous never dies ~{C.RESET}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.RED}  [!] Aborted by user.{C.RESET}")
    input(f"{C.DIM}  Press Enter to exit...{C.RESET}")
