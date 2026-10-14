# 📡 RouterWatch – Wi-Fi Connected Devices Monitor

**RouterWatch** is a lightweight Python tool for monitoring devices visible on your own local Wi-Fi/LAN.

### Features

- 📶 Detects the computer's local IP
- 🌐 Automatically identifies the local `/24` network
- 📱 Scans local IP addresses
- 🟢 Shows online devices
- 🧾 Shows IP address and MAC address when available
- 🔄 Manual rescan
- ♻️ Auto-refresh mode
- 🪟 Windows support
- 🐧 Linux support
- 🍎 macOS support where the standard `arp` command is available
- 📦 No third-party Python packages required

## Requirements

- Python 3.9 or newer
- Your computer connected to the Wi-Fi/LAN you want to monitor

## Installation

Open CMD/PowerShell/Terminal inside the project folder:

```bash
python --version
python main.py
```

On some Linux systems:

```bash
python3 main.py
```

No `pip install` is necessary.

## Controls

- `R` — scan again
- `A` — auto-refresh every 10 seconds
- `Q` — quit

## Important limitation

RouterWatch does **not** log in to your router. It discovers devices from your computer's local network using ping and the operating system's ARP/neighbor table.

Therefore:

- A device may be connected to Wi-Fi but not respond to ping.
- Some devices may appear as `SEEN` because they are present in the neighbor table but did not answer the current ping.
- MAC addresses may be unavailable depending on the OS/network.
- The tool currently assumes a normal `/24` IPv4 LAN such as `192.168.1.0/24`.
- For an exact router client list, a router-specific API/DHCP client table integration is needed.

Use RouterWatch only on networks you own or are authorized to monitor.

## Project structure

```text
RouterWatch/
├── main.py
├── requirements.txt
└── README.md
```

## Author

**Mr Sabaz Ali Khan**

RouterWatch — local network visibility project.
