# WiFiReconX

**Professional Wi-Fi Information Gathering & Reconnaissance Toolkit**  
**Coded by Mr Sabaz Ali Khan**

## Features
- Windows Wi-Fi discovery via `netsh`
- Linux wireless discovery via `iwlist`
- SSID / BSSID information
- Channel and signal information
- WPA/WPA2/WPA3/Open security classification
- Wireless interface details
- Local IP and gateway information
- TXT / JSON / CSV export
- Interactive terminal menu

## Run on Windows
Open Command Prompt or PowerShell in this folder:

```powershell
python main.py
```

For best results, run the terminal as Administrator.

## Install dependency

```powershell
python -m pip install -r requirements.txt
```

## Run on Kali Linux

```bash
sudo apt update
sudo apt install wireless-tools net-tools python3-pip
python3 -m pip install -r requirements.txt
sudo python3 main.py
```

## Important
Use WiFiReconX only for networks and devices you own or have explicit authorization to assess. The project is intended for defensive security, inventory, and educational lab use. It does not perform password cracking, credential theft, deauthentication, or unauthorized access.
