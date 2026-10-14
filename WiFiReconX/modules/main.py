#!/usr/bin/env python3
"""
WiFiReconX – Professional Wi-Fi Information Gathering & Reconnaissance Toolkit
Coded by Mr Sabaz Ali Khan
Version: 1.0 - Windows Compatible
"""

import subprocess
import re
import json
import csv
import sys
import os
import time
import platform
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import socket
import ipaddress

# Try to import netifaces, fallback if not available
try:
    import netifaces
    HAS_NETIFACES = True
except ImportError:
    HAS_NETIFACES = False
    print("[!] netifaces not found, using fallback methods")

class WiFiReconX:
    """Professional Wi-Fi Information Gathering & Reconnaissance Toolkit"""
    
    def __init__(self):
        self.scan_results = []
        self.interface_info = {}
        self.system = platform.system()
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.banner = """
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   ██╗    ██╗██╗███████╗██╗██████╗ ███████╗ ██████╗ ███╗   ██╗  ║
║   ██║    ██║██║██╔════╝██║██╔══██╗██╔════╝██╔═══██╗████╗  ██║  ║
║   ██║ █╗ ██║██║█████╗  ██║██████╔╝█████╗  ██║   ██║██╔██╗ ██║  ║
║   ██║███╗██║██║██╔══╝  ██║██╔══██╗██╔══╝  ██║   ██║██║╚██╗██║  ║
║   ╚███╔███╔╝██║██║     ██║██║  ██║███████╗╚██████╔╝██║ ╚████║  ║
║    ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝  ║
║                                                                  ║
║   WiFiReconX - Professional Wi-Fi Reconnaissance Toolkit        ║
║   Coded by Mr Sabaz Ali Khan                                    ║
║   Version: 1.0 - Windows Compatible                             ║
╚══════════════════════════════════════════════════════════════════╝
        """
    
    def print_banner(self):
        """Print the toolkit banner"""
        print(self.banner)
        print("\n[+] Initializing WiFiReconX...")
        print(f"[+] System: {self.system}")
        print(f"[+] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 70)
    
    def check_dependencies(self) -> bool:
        """Check if required tools are installed"""
        if self.system == "Windows":
            # On Windows, check for netsh command
            try:
                subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                             capture_output=True, text=True, check=False)
                return True
            except Exception:
                print("[-] Windows WiFi commands not available")
                return False
        else:
            # Linux - check for wireless tools
            required_tools = ['iwlist', 'iwconfig', 'ifconfig']
            missing_tools = []
            
            for tool in required_tools:
                if not self._check_command_exists(tool):
                    missing_tools.append(tool)
            
            if missing_tools:
                print(f"[-] Missing tools: {', '.join(missing_tools)}")
                print("[!] Install using: sudo apt-get install wireless-tools")
                return False
        return True
    
    def _check_command_exists(self, command: str) -> bool:
        """Check if a command exists"""
        try:
            subprocess.run(['which', command], capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError:
            return False
    
    def get_wireless_interfaces(self) -> List[str]:
        """Get list of wireless interfaces"""
        if self.system == "Windows":
            return self._get_windows_interfaces()
        else:
            return self._get_linux_interfaces()
    
    def _get_windows_interfaces(self) -> List[str]:
        """Get wireless interfaces on Windows"""
        interfaces = []
        try:
            result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                # Parse interface names
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Name' in line and ':' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            iface = parts[1].strip()
                            if iface:
                                interfaces.append(iface)
        except Exception as e:
            print(f"[-] Error getting Windows interfaces: {e}")
        return interfaces
    
    def _get_linux_interfaces(self) -> List[str]:
        """Get wireless interfaces on Linux"""
        try:
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            interfaces = re.findall(r'^(\w+)\s+', result.stdout, re.MULTILINE)
            wireless_interfaces = []
            for iface in interfaces:
                if 'no wireless extensions' not in result.stdout.split(iface)[1].split('\n')[0]:
                    wireless_interfaces.append(iface)
            return wireless_interfaces
        except Exception as e:
            print(f"[-] Error getting wireless interfaces: {e}")
            return []
    
    def get_interface_info(self, interface: str) -> Dict:
        """Get detailed information about a wireless interface"""
        info = {
            'interface': interface,
            'mac': None,
            'ip': None,
            'mode': None,
            'tx_power': None,
            'driver': None
        }
        
        if self.system == "Windows":
            return self._get_windows_interface_info(interface)
        else:
            return self._get_linux_interface_info(interface)
    
    def _get_windows_interface_info(self, interface: str) -> Dict:
        """Get Windows interface info"""
        info = {'interface': interface, 'mac': None, 'ip': None, 
                'mode': 'Managed', 'tx_power': 'N/A', 'driver': 'N/A'}
        try:
            # Get interface details
            result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                current_iface = None
                for i, line in enumerate(lines):
                    if 'Name' in line and ':' in line:
                        parts = line.split(':')
                        if len(parts) >= 2 and parts[1].strip() == interface:
                            current_iface = i
                            break
                
                if current_iface is not None:
                    for line in lines[current_iface:current_iface+10]:
                        if 'MAC' in line and ':' in line:
                            parts = line.split(':')
                            if len(parts) >= 2:
                                info['mac'] = parts[1].strip()
                        elif 'IP' in line and ':' in line and 'IPv4' in line:
                            parts = line.split(':')
                            if len(parts) >= 2:
                                info['ip'] = parts[1].strip()
        except Exception as e:
            print(f"[-] Error getting Windows interface info: {e}")
        return info
    
    def _get_linux_interface_info(self, interface: str) -> Dict:
        """Get Linux interface info"""
        info = {
            'interface': interface,
            'mac': None,
            'ip': None,
            'mode': None,
            'tx_power': None,
            'driver': None
        }
        
        try:
            # Get MAC and IP
            ifconfig = subprocess.run(['ifconfig', interface], capture_output=True, text=True)
            mac_match = re.search(r'ether\s+([0-9a-fA-F:]{17})', ifconfig.stdout)
            if mac_match:
                info['mac'] = mac_match.group(1)
            
            ip_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', ifconfig.stdout)
            if ip_match:
                info['ip'] = ip_match.group(1)
            
            # Get wireless specific info
            iwconfig = subprocess.run(['iwconfig', interface], capture_output=True, text=True)
            mode_match = re.search(r'Mode:(\w+)', iwconfig.stdout)
            if mode_match:
                info['mode'] = mode_match.group(1)
            
            tx_match = re.search(r'Tx-Power=(\d+)', iwconfig.stdout)
            if tx_match:
                info['tx_power'] = tx_match.group(1) + ' dBm'
            
        except Exception as e:
            print(f"[-] Error getting interface info: {e}")
        
        return info
    
    def scan_networks(self, interface: str) -> List[Dict]:
        """Scan for Wi-Fi networks"""
        if self.system == "Windows":
            return self._scan_windows_networks()
        else:
            return self._scan_linux_networks(interface)
    
    def _scan_windows_networks(self) -> List[Dict]:
        """Scan networks on Windows using netsh"""
        networks = []
        
        try:
            print("[+] Scanning Wi-Fi networks on Windows...")
            print("[+] Please wait...")
            
            # First, make sure we have fresh data
            subprocess.run(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'], 
                         capture_output=True, text=True)
            
            # Get networks with BSSID info
            result = subprocess.run(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'], 
                                  capture_output=True, text=True)
            
            if result.returncode != 0:
                print("[-] Scan failed")
                return []
            
            output = result.stdout
            # Parse networks
            network_blocks = output.split('\n\n')
            
            current_network = {}
            for block in network_blocks:
                if not block.strip():
                    continue
                
                if 'SSID' in block and 'BSSID' not in block:
                    # New network
                    if current_network:
                        networks.append(current_network)
                    current_network = self._parse_windows_network(block)
                elif current_network and 'BSSID' in block:
                    # Add BSSID info
                    self._parse_windows_bssid(block, current_network)
            
            if current_network:
                networks.append(current_network)
            
            print(f"[+] Found {len(networks)} networks")
            return networks
            
        except Exception as e:
            print(f"[-] Error scanning networks: {e}")
            return []
    
    def _parse_windows_network(self, block: str) -> Dict:
        """Parse Windows network block"""
        network = {
            'ssid': 'Unknown',
            'bssid': 'N/A',
            'channel': 'N/A',
            'signal_strength': 'N/A',
            'signal_percent': 'N/A',
            'encryption': ['Unknown'],
            'security_type': 'Unknown',
            'mode': 'Infrastructure'
        }
        
        lines = block.split('\n')
        for line in lines:
            if 'SSID' in line and ':' in line:
                parts = line.split(':')
                if len(parts) >= 2:
                    network['ssid'] = parts[1].strip() or 'Hidden'
            elif 'Authentication' in line and ':' in line:
                parts = line.split(':')
                if len(parts) >= 2:
                    auth = parts[1].strip()
                    if 'WPA3' in auth:
                        network['encryption'] = ['WPA3']
                        network['security_type'] = 'WPA3 (High)'
                    elif 'WPA2' in auth:
                        network['encryption'] = ['WPA2']
                        network['security_type'] = 'WPA2-PSK (Medium)'
                    elif 'WPA' in auth:
                        network['encryption'] = ['WPA']
                        network['security_type'] = 'WPA-PSK (Medium)'
                    elif 'Open' in auth:
                        network['encryption'] = ['Open']
                        network['security_type'] = 'Open (None)'
                    else:
                        network['encryption'] = [auth]
                        network['security_type'] = auth
            elif 'Encryption' in line and ':' in line:
                if 'WEP' in line:
                    network['encryption'].append('WEP')
        
        return network
    
    def _parse_windows_bssid(self, block: str, network: Dict):
        """Parse BSSID information from Windows output"""
        lines = block.split('\n')
        for line in lines:
            if 'BSSID' in line and ':' in line:
                parts = line.split(':')
                if len(parts) >= 2:
                    network['bssid'] = parts[1].strip()
            elif 'Signal' in line and ':' in line:
                parts = line.split(':')
                if len(parts) >= 2:
                    signal = parts[1].strip().replace('%', '')
                    try:
                        signal_int = int(signal)
                        network['signal_percent'] = f"{signal_int}%"
                        # Convert percentage to quality (0-100)
                        network['signal_strength'] = f"{signal_int}/100"
                    except ValueError:
                        pass
            elif 'Channel' in line and ':' in line:
                parts = line.split(':')
                if len(parts) >= 2:
                    network['channel'] = parts[1].strip()
    
    def _scan_linux_networks(self, interface: str) -> List[Dict]:
        """Scan networks on Linux using iwlist"""
        networks = []
        
        try:
            print(f"[+] Scanning networks on interface: {interface}")
            print("[+] Please wait... (30 seconds)")
            
            result = subprocess.run(['sudo', 'iwlist', interface, 'scan'], 
                                  capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"[-] Scan failed: {result.stderr}")
                return []
            
            output = result.stdout
            cells = output.split('Cell ')
            
            for cell in cells[1:]:
                network = self._parse_linux_cell(cell)
                if network:
                    networks.append(network)
            
            print(f"[+] Found {len(networks)} networks")
            return networks
            
        except Exception as e:
            print(f"[-] Error scanning networks: {e}")
            return []
    
    def _parse_linux_cell(self, cell: str) -> Optional[Dict]:
        """Parse a cell entry from iwlist output"""
        try:
            network = {}
            
            bssid_match = re.search(r'Address: ([0-9a-fA-F:]{17})', cell)
            if bssid_match:
                network['bssid'] = bssid_match.group(1).upper()
            
            essid_match = re.search(r'ESSID:"([^"]*)"', cell)
            if essid_match:
                network['ssid'] = essid_match.group(1) if essid_match.group(1) else 'Hidden'
            else:
                network['ssid'] = 'Hidden'
            
            channel_match = re.search(r'Channel:(\d+)', cell)
            if channel_match:
                network['channel'] = int(channel_match.group(1))
            
            quality_match = re.search(r'Quality=(\d+)/(\d+)', cell)
            if quality_match:
                quality = int(quality_match.group(1))
                max_quality = int(quality_match.group(2))
                network['signal_strength'] = f"{quality}/{max_quality}"
                network['signal_percent'] = f"{(quality/max_quality)*100:.1f}%"
            
            encryption = []
            if 'Encryption key:on' in cell:
                encryption.append('WEP')
            elif 'Encryption key:off' in cell:
                encryption.append('Open')
            
            if 'WPA2' in cell:
                encryption.append('WPA2')
            if 'WPA' in cell and 'WPA2' not in cell:
                encryption.append('WPA')
            if 'WPA3' in cell:
                encryption.append('WPA3')
            if 'IEEE 802.1X' in cell:
                encryption.append('Enterprise')
            
            network['encryption'] = encryption if encryption else ['Open']
            network['security_type'] = self._get_security_level(encryption)
            
            mode_match = re.search(r'Mode:(\w+)', cell)
            if mode_match:
                network['mode'] = mode_match.group(1)
            
            freq_match = re.search(r'Frequency:([\d.]+) GHz', cell)
            if freq_match:
                network['frequency'] = freq_match.group(1) + ' GHz'
            
            return network
            
        except Exception as e:
            print(f"[-] Error parsing cell: {e}")
            return None
    
    def _get_security_level(self, encryption: List[str]) -> str:
        """Determine security level based on encryption types"""
        if 'WPA3' in encryption:
            return 'WPA3 (High)'
        elif 'WPA2' in encryption and 'Enterprise' in encryption:
            return 'WPA2-Enterprise (High)'
        elif 'WPA2' in encryption:
            return 'WPA2-PSK (Medium)'
        elif 'WPA' in encryption and 'Enterprise' in encryption:
            return 'WPA-Enterprise (Medium)'
        elif 'WPA' in encryption:
            return 'WPA-PSK (Medium)'
        elif 'WEP' in encryption:
            return 'WEP (Low)'
        else:
            return 'Open (None)'
    
    def get_local_network_info(self) -> Dict:
        """Get local network information"""
        info = {
            'hostname': socket.gethostname(),
            'ip_addresses': [],
            'gateway': None,
            'dns_servers': []
        }
        
        try:
            if self.system == "Windows":
                # Windows - use ipconfig
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    current_iface = None
                    for line in lines:
                        if 'Wireless' in line or 'Wi-Fi' in line:
                            current_iface = line.strip()
                        elif 'IPv4 Address' in line and ':' in line:
                            parts = line.split(':')
                            if len(parts) >= 2:
                                ip = parts[1].strip()
                                if current_iface:
                                    info['ip_addresses'].append({
                                        'interface': current_iface,
                                        'ip': ip,
                                        'netmask': 'N/A'
                                    })
            else:
                # Linux - use ifconfig
                if HAS_NETIFACES:
                    for interface in netifaces.interfaces():
                        addrs = netifaces.ifaddresses(interface)
                        if netifaces.AF_INET in addrs:
                            for addr in addrs[netifaces.AF_INET]:
                                if addr['addr'] != '127.0.0.1':
                                    info['ip_addresses'].append({
                                        'interface': interface,
                                        'ip': addr['addr'],
                                        'netmask': addr.get('netmask', 'N/A')
                                    })
                    
                    # Get gateway
                    gateways = netifaces.gateways()
                    if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                        info['gateway'] = gateways['default'][netifaces.AF_INET][0]
            
        except Exception as e:
            print(f"[-] Error getting network info: {e}")
        
        return info
    
    def display_results(self, networks: List[Dict], interface_info: Dict):
        """Display scan results in a formatted table"""
        print("\n" + "=" * 80)
        print(f"{'WiFiReconX - Scan Results':^80}")
        print("=" * 80)
        
        # Interface info
        print(f"\n[+] Interface Information:")
        print(f"    Interface: {interface_info.get('interface', 'N/A')}")
        print(f"    MAC Address: {interface_info.get('mac', 'N/A')}")
        print(f"    IP Address: {interface_info.get('ip', 'N/A')}")
        print(f"    Mode: {interface_info.get('mode', 'N/A')}")
        print(f"    TX Power: {interface_info.get('tx_power', 'N/A')}")
        print(f"    Driver: {interface_info.get('driver', 'N/A')}")
        
        # Network stats
        if networks:
            print(f"\n[+] Found {len(networks)} networks")
            
            # Display in table format
            print("\n" + "-" * 100)
            print(f"{'#':<4} {'SSID':<30} {'BSSID':<20} {'Channel':<8} {'Security':<20} {'Signal':<10}")
            print("-" * 100)
            
            for idx, net in enumerate(networks, 1):
                ssid = net.get('ssid', 'Unknown')[:28] + '..' if len(net.get('ssid', '')) > 30 else net.get('ssid', 'Unknown')
                bssid = net.get('bssid', 'N/A')
                channel = net.get('channel', 'N/A')
                security = net.get('security_type', 'Unknown')[:18] + '..' if len(net.get('security_type', '')) > 20 else net.get('security_type', 'Unknown')
                signal = net.get('signal_percent', 'N/A')
                
                print(f"{idx:<4} {ssid:<30} {bssid:<20} {channel:<8} {security:<20} {signal:<10}")
            
            print("-" * 100)
            
            # Detailed view option
            print("\n[+] Options:")
            print("    1. Show detailed view")
            print("    2. Export results")
            print("    3. Continue to main menu")
            print("    4. Exit")
            
            choice = input("\n[?] Enter your choice (1-4): ").strip()
            
            if choice == '1':
                self.show_detailed_view(networks)
            elif choice == '2':
                self.export_results(networks)
            elif choice == '4':
                self.exit_toolkit()
    
    def show_detailed_view(self, networks: List[Dict]):
        """Show detailed view of networks"""
        print("\n" + "=" * 80)
        print("DETAILED NETWORK VIEW")
        print("=" * 80)
        
        for idx, net in enumerate(networks, 1):
            print(f"\n[{idx}] Network Details:")
            print(f"    SSID: {net.get('ssid', 'Unknown')}")
            print(f"    BSSID: {net.get('bssid', 'N/A')}")
            print(f"    Channel: {net.get('channel', 'N/A')}")
            print(f"    Frequency: {net.get('frequency', 'N/A')}")
            print(f"    Security Type: {net.get('security_type', 'Unknown')}")
            print(f"    Encryption: {', '.join(net.get('encryption', ['Unknown']))}")
            print(f"    Signal Strength: {net.get('signal_strength', 'N/A')}")
            print(f"    Signal Percentage: {net.get('signal_percent', 'N/A')}")
            print(f"    Mode: {net.get('mode', 'N/A')}")
            print("-" * 40)
        
        input("\n[+] Press Enter to continue...")
    
    def export_results(self, networks: List[Dict]):
        """Export scan results to file"""
        print("\n[+] Export Options:")
        print("    1. Export to TXT")
        print("    2. Export to JSON")
        print("    3. Export to CSV")
        print("    4. Back to menu")
        
        choice = input("\n[?] Enter your choice (1-4): ").strip()
        
        if choice == '1':
            self.export_txt(networks)
        elif choice == '2':
            self.export_json(networks)
        elif choice == '3':
            self.export_csv(networks)
    
    def export_txt(self, networks: List[Dict]):
        """Export to TXT format"""
        filename = f"wifi_recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        filepath = os.path.join(self.script_dir, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("WiFiReconX - Scan Results\n")
                f.write("=" * 60 + "\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 60 + "\n\n")
                
                for idx, net in enumerate(networks, 1):
                    f.write(f"[{idx}] Network Details:\n")
                    f.write(f"    SSID: {net.get('ssid', 'Unknown')}\n")
                    f.write(f"    BSSID: {net.get('bssid', 'N/A')}\n")
                    f.write(f"    Channel: {net.get('channel', 'N/A')}\n")
                    f.write(f"    Frequency: {net.get('frequency', 'N/A')}\n")
                    f.write(f"    Security Type: {net.get('security_type', 'Unknown')}\n")
                    f.write(f"    Encryption: {', '.join(net.get('encryption', ['Unknown']))}\n")
                    f.write(f"    Signal Strength: {net.get('signal_strength', 'N/A')}\n")
                    f.write(f"    Signal Percentage: {net.get('signal_percent', 'N/A')}\n")
                    f.write(f"    Mode: {net.get('mode', 'N/A')}\n")
                    f.write("-" * 40 + "\n\n")
            
            print(f"[+] Results exported to: {filepath}")
        except Exception as e:
            print(f"[-] Error exporting to TXT: {e}")
    
    def export_json(self, networks: List[Dict]):
        """Export to JSON format"""
        filename = f"wifi_recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(self.script_dir, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump({
                    'timestamp': datetime.now().isoformat(),
                    'total_networks': len(networks),
                    'networks': networks
                }, f, indent=4, ensure_ascii=False)
            print(f"[+] Results exported to: {filepath}")
        except Exception as e:
            print(f"[-] Error exporting to JSON: {e}")
    
    def export_csv(self, networks: List[Dict]):
        """Export to CSV format"""
        filename = f"wifi_recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        filepath = os.path.join(self.script_dir, filename)
        
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                if networks:
                    fieldnames = ['SSID', 'BSSID', 'Channel', 'Security Type', 
                                'Encryption', 'Signal Percentage', 'Mode']
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    
                    for net in networks:
                        writer.writerow({
                            'SSID': net.get('ssid', 'Unknown'),
                            'BSSID': net.get('bssid', 'N/A'),
                            'Channel': net.get('channel', 'N/A'),
                            'Security Type': net.get('security_type', 'Unknown'),
                            'Encryption': ', '.join(net.get('encryption', ['Unknown'])),
                            'Signal Percentage': net.get('signal_percent', 'N/A'),
                            'Mode': net.get('mode', 'N/A')
                        })
            print(f"[+] Results exported to: {filepath}")
        except Exception as e:
            print(f"[-] Error exporting to CSV: {e}")
    
    def exit_toolkit(self):
        """Exit the toolkit"""
        print("\n[+] Thank you for using WiFiReconX")
        print("[+] Coded by Mr Sabaz Ali Khan")
        sys.exit(0)
    
    def main_menu(self):
        """Main menu for the toolkit"""
        while True:
            print("\n" + "=" * 70)
            print(f"{'WiFiReconX - Main Menu':^70}")
            print("=" * 70)
            print("\n[+] Available Options:")
            print("    1. Scan Wi-Fi Networks")
            print("    2. Show Wireless Interfaces")
            print("    3. Show Local Network Info")
            print("    4. About Toolkit")
            print("    5. Exit")
            
            choice = input("\n[?] Enter your choice (1-5): ").strip()
            
            if choice == '1':
                self.scan_menu()
            elif choice == '2':
                self.show_interfaces()
            elif choice == '3':
                self.show_network_info()
            elif choice == '4':
                self.show_about()
            elif choice == '5':
                self.exit_toolkit()
            else:
                print("[-] Invalid choice. Please try again.")
    
    def scan_menu(self):
        """Scan menu"""
        interfaces = self.get_wireless_interfaces()
        
        if not interfaces:
            print("[-] No wireless interfaces found!")
            print("[!] Make sure you have wireless hardware and drivers installed")
            return
        
        print("\n[+] Available Wireless Interfaces:")
        for idx, iface in enumerate(interfaces, 1):
            info = self.get_interface_info(iface)
            print(f"    {idx}. {iface} ({info.get('mac', 'N/A')})")
        
        if len(interfaces) == 1:
            interface = interfaces[0]
        else:
            choice = input(f"\n[?] Select interface number (1-{len(interfaces)}): ").strip()
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(interfaces):
                    interface = interfaces[idx]
                else:
                    print("[-] Invalid selection")
                    return
            except ValueError:
                print("[-] Invalid selection")
                return
        
        # Scan for networks
        self.interface_info = self.get_interface_info(interface)
        networks = self.scan_networks(interface)
        
        if networks:
            self.scan_results = networks
            self.display_results(networks, self.interface_info)
        else:
            print("[-] No networks found or scan failed")
            print("[!] On Windows, try running as Administrator")
            print("[!] Make sure Wi-Fi is enabled")
    
    def show_interfaces(self):
        """Show wireless interface information"""
        interfaces = self.get_wireless_interfaces()
        
        if not interfaces:
            print("[-] No wireless interfaces found!")
            return
        
        print("\n" + "=" * 70)
        print("WIRELESS INTERFACES INFORMATION")
        print("=" * 70)
        
        for iface in interfaces:
            info = self.get_interface_info(iface)
            print(f"\n[+] Interface: {iface}")
            print(f"    MAC Address: {info.get('mac', 'N/A')}")
            print(f"    IP Address: {info.get('ip', 'N/A')}")
            print(f"    Mode: {info.get('mode', 'N/A')}")
            print(f"    TX Power: {info.get('tx_power', 'N/A')}")
            print(f"    Driver: {info.get('driver', 'N/A')}")
            print("-" * 50)
        
        input("\n[+] Press Enter to continue...")
    
    def show_network_info(self):
        """Show local network information"""
        info = self.get_local_network_info()
        
        print("\n" + "=" * 70)
        print("LOCAL NETWORK INFORMATION")
        print("=" * 70)
        
        print(f"\n[+] Hostname: {info['hostname']}")
        
        if info['ip_addresses']:
            print("\n[+] IP Addresses:")
            for addr in info['ip_addresses']:
                print(f"    {addr['interface']}: {addr['ip']} ({addr['netmask']})")
        
        if info['gateway']:
            print(f"\n[+] Gateway: {info['gateway']}")
        
        input("\n[+] Press Enter to continue...")
    
    def show_about(self):
        """Show about information"""
        print("\n" + "=" * 70)
        print("ABOUT WIFIRECONX")
        print("=" * 70)
        print("\n[+] WiFiReconX - Professional Wi-Fi Information Gathering & Reconnaissance Toolkit")
        print("[+] Version: 1.0")
        print("[+] Author: Mr Sabaz Ali Khan")
        print("[+] Description: Advanced Wi-Fi reconnaissance tool for network security professionals")
        print("\n[+] Features:")
        print("    • Wi-Fi network discovery")
        print("    • SSID / BSSID information")
        print("    • Security type detection (WPA/WPA2/WPA3/Open)")
        print("    • Channel & signal-strength information")
        print("    • Local network/interface information")
        print("    • Network adapter details")
        print("    • Scan results export (TXT/JSON/CSV)")
        print("    • Windows & Linux compatible")
        print("    • Professional Hacker/Terminal UI")
        print("\n[+] Disclaimer: This tool is for educational and authorized testing purposes only.")
        
        input("\n[+] Press Enter to continue...")
    
    def run(self):
        """Main entry point for the toolkit"""
        print("[!] Windows Compatibility Mode")
        if self.system == "Windows":
            print("[!] Run as Administrator for full functionality")
        
        self.print_banner()
        
        if not self.check_dependencies():
            print("[!] Please fix dependencies and try again.")
            if self.system == "Windows":
                print("[!] On Windows, netsh wlan commands should work")
                print("[!] Make sure your Wi-Fi adapter is working")
            return
        
        self.main_menu()

def main():
    """Main function"""
    try:
        toolkit = WiFiReconX()
        toolkit.run()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        print("[+] Exiting WiFiReconX...")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] An error occurred: {e}")
        print("[+] Exiting WiFiReconX...")
        sys.exit(1)

if __name__ == "__main__":
    main()