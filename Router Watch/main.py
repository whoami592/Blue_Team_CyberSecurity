"""
RouterWatch - Wi-Fi Connected Devices Monitor
Coded by Mr Sabaz Ali Khan

Monitors devices on the local network you are connected to.
Uses standard OS ping + ARP/neighbor tables; no third-party packages required.
"""

import concurrent.futures
import datetime
import os
import platform
import re
import socket
import subprocess
import time


APP_NAME = "RouterWatch"
VERSION = "1.0.0"
SCAN_TIMEOUT = 1.2


def clear_screen():
    os.system("cls" if platform.system() == "Windows" else "clear")


def get_local_ip():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except OSError:
        return "127.0.0.1"


def get_network_prefix():
    ip = get_local_ip()
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return ".".join(parts[:3]) + "."
    return "192.168.1."


def ping_device(ip):
    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", "1", "-w", "700", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=SCAN_TIMEOUT + 0.5,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def get_neighbor_table():
    """Return raw ARP/neighbor table output."""
    commands = [["arp", "-a"]]

    if platform.system() != "Windows":
        commands.append(["ip", "neigh"])

    for command in commands:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                errors="ignore",
                timeout=3,
            )
            if result.stdout.strip():
                return result.stdout
        except (OSError, subprocess.TimeoutExpired):
            pass

    return ""


def parse_neighbors(raw):
    """
    Parse common Windows arp -a and Linux ip neigh / arp output.
    Returns {ip: mac}.
    """
    devices = {}

    mac_pattern = r"([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})"
    ip_pattern = r"(\d{1,3}(?:\.\d{1,3}){3})"

    for line in raw.splitlines():
        ip_match = re.search(ip_pattern, line)
        mac_match = re.search(mac_pattern, line)
        if not ip_match or not mac_match:
            continue

        ip = ip_match.group(1)
        mac = mac_match.group(1).replace("-", ":").upper()

        if mac == "FF:FF:FF:FF:FF:FF":
            continue

        devices[ip] = mac

    return devices


def scan_network():
    """
    Ping the local /24 network concurrently, then read the neighbor table.
    This is intended for the user's own/local LAN.
    """
    prefix = get_network_prefix()
    ips = [f"{prefix}{i}" for i in range(1, 255)]

    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as executor:
        results = list(executor.map(ping_device, ips))

    online_ips = {ip for ip, alive in zip(ips, results) if alive}

    neighbors = parse_neighbors(get_neighbor_table())

    # Combine ping results with ARP/neighbor information.
    all_ips = sorted(
        online_ips | set(neighbors.keys()),
        key=lambda x: tuple(int(n) for n in x.split("."))
    )

    devices = []
    for ip in all_ips:
        devices.append({
            "ip": ip,
            "mac": neighbors.get(ip, "Unknown"),
            "status": "ONLINE" if ip in online_ips else "SEEN",
        })

    return devices


def print_header():
    print("=" * 82)
    print(f"{APP_NAME} v{VERSION} - Wi-Fi Connected Devices Monitor")
    print("Coded by Mr Sabaz Ali Khan")
    print("=" * 82)


def display(devices, scan_seconds):
    clear_screen()
    print_header()

    print(f"\nLocal IP      : {get_local_ip()}")
    print(f"Network       : {get_network_prefix()}0/24")
    print(f"Devices found : {len(devices)}")
    print(f"Scan time     : {scan_seconds:.1f}s")
    print(f"Last scan     : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    print("\n" + "-" * 82)
    print(f"{'#':<5}{'IP Address':<20}{'MAC Address':<25}{'Status':<12}")
    print("-" * 82)

    if not devices:
        print("No devices detected.")
    else:
        for number, device in enumerate(devices, 1):
            print(
                f"{number:<5}"
                f"{device['ip']:<20}"
                f"{device['mac']:<25}"
                f"{device['status']:<12}"
            )

    print("-" * 82)
    print("\n[R] Rescan   [A] Auto refresh   [Q] Quit")


def run_scan():
    start = time.perf_counter()
    devices = scan_network()
    elapsed = time.perf_counter() - start
    return devices, elapsed


def main():
    auto_refresh = False

    while True:
        try:
            devices, elapsed = run_scan()
            display(devices, elapsed)

            if auto_refresh:
                print("\nAuto refresh: every 10 seconds. Press Ctrl+C to stop.")
                time.sleep(10)
                continue

            choice = input("\nChoice: ").strip().lower()

            if choice == "q":
                print("\nRouterWatch closed.")
                break
            elif choice == "r":
                continue
            elif choice == "a":
                auto_refresh = True
            else:
                print("Invalid option.")
                time.sleep(1)

        except KeyboardInterrupt:
            if auto_refresh:
                auto_refresh = False
                print("\nAuto refresh stopped.")
                time.sleep(1)
            else:
                print("\n\nRouterWatch stopped.")
                break
        except Exception as exc:
            print(f"\nError: {exc}")
            input("Press Enter to continue...")


if __name__ == "__main__":
    main()
