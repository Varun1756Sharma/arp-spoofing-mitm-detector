# arp_detector_final_working.py - COMPLETE WORKING CODE
from scapy.all import sniff, ARP
import time
import datetime
import os
import json
import subprocess
import re

class ARPDetectorCLI:
    def __init__(self):
        self.ip_mac_map = {}
        self.suspects = {}
        self.packet_count = 0
        self.arp_packets = 0
        self.suspicious_packets = 0
        self.start_time = time.time()
        self.alert_log = []
        self.gateway_ip = None
        self.my_ip = None
        self.interface = None
        
    def get_all_interfaces(self):
        """Get all interfaces with IPs"""
        interfaces = []
        try:
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            
            current_iface = None
            
            for line in lines:
                if 'adapter' in line.lower():
                    current_iface = line.split('adapter')[1].split(':')[0].strip()
                
                if 'IPv4' in line or 'IP Address' in line:
                    ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                    if ip_match:
                        ip = ip_match.group()
                        if not ip.startswith('127.') and not ip.startswith('169.'):
                            if current_iface:
                                interfaces.append({
                                    'name': current_iface,
                                    'ip': ip
                                })
        except:
            pass
        return interfaces
    
    def select_interface(self):
        """Let user select interface"""
        print("\n" + "="*70)
        print("📡 AVAILABLE NETWORK INTERFACES")
        print("="*70)
        
        interfaces = self.get_all_interfaces()
        
        if not interfaces:
            print("❌ No interfaces found!")
            return False
        
        print(f"\n{'No.':<5} {'INTERFACE NAME':<45} {'IP ADDRESS':<15}")
        print("-" * 70)
        
        for i, iface in enumerate(interfaces, 1):
            name = iface['name'][:43] if len(iface['name']) > 43 else iface['name']
            print(f"{i:<5} {name:<45} {iface['ip']:<15}")
        
        print("-" * 70)
        print("\n💡 Select your ACTIVE WiFi interface")
        
        try:
            choice = int(input("\n👉 Select interface number: "))
            if 1 <= choice <= len(interfaces):
                self.interface = interfaces[choice - 1]['name']
                self.my_ip = interfaces[choice - 1]['ip']
                print(f"\n✅ Selected: {self.interface}")
                print(f"✅ Your IP: {self.my_ip}")
                return True
        except:
            print("❌ Invalid choice!")
        return False
    
    def get_gateway(self):
        """Get gateway IP"""
        try:
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            
            for i, line in enumerate(lines):
                if 'adapter' in line.lower() and self.interface.lower() in line.lower():
                    # Found interface, look for gateway in next lines
                    for j in range(i, min(i+15, len(lines))):
                        if 'Default Gateway' in lines[j]:
                            gw_match = re.search(r'\d+\.\d+\.\d+\.\d+', lines[j])
                            if gw_match:
                                self.gateway_ip = gw_match.group()
                                if self.gateway_ip != '0.0.0.0' and not self.gateway_ip.startswith('169.'):
                                    print(f"✅ Gateway: {self.gateway_ip}")
                                    return True
        except:
            pass
        
        # Manual entry
        self.gateway_ip = input("Enter gateway IP manually: ").strip()
        return True
    
    def packet_callback(self, pkt):
        """Process each packet - THIS IS THE MAIN FUNCTION"""
        self.packet_count += 1
        
        # Show progress every 30 packets
        if self.packet_count % 30 == 0:
            print(f"\r📦 Total: {self.packet_count} | ARP: {self.arp_packets} | Alerts: {len(self.alert_log)}", end="")
        
        # Check for ARP packets
        if pkt.haslayer(ARP):
            self.arp_packets += 1
            src_ip = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc
            
            print(f"\n\n✅ ARP Packet #{self.arp_packets} Captured!")
            print(f"   📡 Source IP: {src_ip}")
            print(f"   🔒 Source MAC: {src_mac}")
            print(f"   📍 Target IP: {pkt[ARP].pdst}")
            print(f"   🔄 Operation: {'Request' if pkt[ARP].op == 1 else 'Reply'}")
            
            # Check if this is gateway spoofing
            if src_ip == self.gateway_ip:
                if src_ip in self.ip_mac_map:
                    if self.ip_mac_map[src_ip] != src_mac:
                        self.suspicious_packets += 1
                        
                        print(f"\n{'='*70}")
                        print(f"\033[91m🚨🚨🚨 MITM ATTACK DETECTED! 🚨🚨🚨\033[0m")
                        print(f"\033[91m📡 Gateway {src_ip} is being SPOOFED!\033[0m")
                        print(f"\033[92m✅ Expected MAC: {self.ip_mac_map[src_ip]}\033[0m")
                        print(f"\033[91m❌ FAKE MAC: {src_mac}\033[0m")
                        print(f"{'='*70}\n")
                        
                        self.alert_log.append({
                            'timestamp': time.time(),
                            'type': 'MITM_ATTACK',
                            'gateway': src_ip,
                            'expected_mac': self.ip_mac_map[src_ip],
                            'fake_mac': src_mac
                        })
                else:
                    # First time seeing gateway
                    self.ip_mac_map[src_ip] = src_mac
                    print(f"   ✅ Gateway recorded! MAC: {src_mac}")
            else:
                # Normal device
                if src_ip in self.ip_mac_map:
                    if self.ip_mac_map[src_ip] != src_mac:
                        self.suspicious_packets += 1
                        print(f"\n⚠️ ARP Spoofing detected for {src_ip}!")
                        print(f"   Expected MAC: {self.ip_mac_map[src_ip]}")
                        print(f"   Fake MAC: {src_mac}")
                else:
                    self.ip_mac_map[src_ip] = src_mac
                    print(f"   ✅ New device: {src_ip} → {src_mac}")
    
    def start_monitoring(self, duration):
        """Start monitoring - NO FILTER"""
        print("\n" + "="*70)
        print("🛡️ ARP SPOOFING DETECTOR - ACTIVE")
        print("="*70)
        
        # Select interface
        if not self.select_interface():
            return
        
        # Get gateway
        self.get_gateway()
        
        print(f"\n📡 Monitoring Configuration:")
        print(f"   🔌 Interface: {self.interface}")
        print(f"   🌐 Gateway: {self.gateway_ip}")
        print(f"   🖥️  Your IP: {self.my_ip}")
        print(f"   ⏱️  Duration: {duration} seconds")
        print(f"\n📡 Listening for ALL packets...")
        print("💡 Looking for ARP packets in network traffic")
        print("⏳ Press Ctrl+C to stop early\n")
        
        # Reset counters
        self.start_time = time.time()
        self.packet_count = 0
        self.arp_packets = 0
        
        try:
            # IMPORTANT: NO FILTER - capture all packets
            sniff(iface=self.interface, prn=self.packet_callback, store=0, timeout=duration)
            
            self.show_report()
            
        except KeyboardInterrupt:
            print("\n\n⚠️ Stopped by user")
            self.show_report()
        except Exception as e:
            print(f"\n❌ Error: {e}")
    
    def show_report(self):
        """Show final report"""
        elapsed = time.time() - self.start_time
        
        # Calculate score
        if self.arp_packets == 0:
            score = 100.0
            status = "NO ARP TRAFFIC DETECTED"
        else:
            score = ((self.arp_packets - self.suspicious_packets) / self.arp_packets) * 100
            if score >= 80:
                status = "SECURE ✅"
            elif score >= 50:
                status = "MODERATE RISK ⚠️"
            else:
                status = "ATTACK DETECTED 🔴"
        
        print("\n" + "="*70)
        print("📊 FINAL SECURITY REPORT")
        print("="*70)
        print(f"🔌 Interface: {self.interface}")
        print(f"🌐 Gateway: {self.gateway_ip}")
        print(f"🖥️  Your IP: {self.my_ip}")
        print(f"⏱️  Runtime: {elapsed:.0f} seconds")
        print("\n📊 STATISTICS:")
        print(f"   📦 Total Packets Captured: {self.packet_count}")
        print(f"   🎯 ARP Packets Found: {self.arp_packets}")
        print(f"   ⚠️ Suspicious ARP: {self.suspicious_packets}")
        print(f"   🚨 Total Alerts: {len(self.alert_log)}")
        print(f"   🔒 Security Score: {score:.1f}%")
        print(f"\n📡 Status: {status}")
        
        if self.arp_packets == 0:
            print("\n⚠️ NOTE: No ARP packets were captured in this scan.")
            print("   This is normal for stable networks.")
            print("   ARP packets appear when:")
            print("   • New devices connect to network")
            print("   • ARP cache expires (every 1-2 minutes)")
            print("   • Someone does ARP spoofing attack")
        
        if self.alert_log:
            print(f"\n🚨 ATTACK DETAILS:")
            for alert in self.alert_log:
                print(f"   → Gateway {alert['gateway']} spoofed!")
        
        save = input("\n💾 Save report? (y/n): ").lower()
        if save == 'y':
            self.save_report(score)
    
    def save_report(self, score):
        """Save report to file"""
        if not os.path.exists('logs'):
            os.makedirs('logs')
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        with open(f'logs/report_{timestamp}.json', 'w') as f:
            json.dump({
                'timestamp': timestamp,
                'interface': self.interface,
                'gateway': self.gateway_ip,
                'my_ip': self.my_ip,
                'statistics': {
                    'total_packets': self.packet_count,
                    'arp_packets': self.arp_packets,
                    'suspicious': self.suspicious_packets,
                    'alerts': len(self.alert_log),
                    'security_score': score
                },
                'alerts': self.alert_log,
                'arp_table': self.ip_mac_map
            }, f, indent=2)
        
        print(f"\n✅ Report saved: logs/report_{timestamp}.json")

def main():
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║           🛡️  ARP SPOOFING & MITM DETECTION  🛡️             ║
    ║                      Network Security Tool                   ║
    ║                                                              ║
    ║        [•] Real-time Packet Monitoring                      ║
    ║        [•] ARP Spoofing Detection                           ║
    ║        [•] MITM Attack Alert                                ║
    ║        [•] Security Score Calculation                       ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Check admin
    if os.name == 'nt':
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("\033[93m⚠️  WARNING: Run as Administrator for packet capture!\033[0m")
                print("   Close this window, right-click → Run as Administrator\n")
                input("Press Enter to exit...")
                return
        except:
            pass
    
    detector = ARPDetectorCLI()
    
    try:
        print("\n📡 Select Monitoring Mode:")
        print("   1. Quick Scan (30 seconds)")
        print("   2. Standard Scan (60 seconds)")
        print("   3. Custom Duration")
        
        mode = input("\n👉 Enter choice [1/2/3]: ").strip()
        
        if mode == "1":
            duration = 30
        elif mode == "2":
            duration = 60
        elif mode == "3":
            duration = int(input("Enter duration in seconds: "))
        else:
            duration = 60
        
        detector.start_monitoring(duration)
        
    except KeyboardInterrupt:
        print("\n\nExiting...")
    except Exception as e:
        print(f"\nError: {e}")

if __name__ == "__main__":
    main()