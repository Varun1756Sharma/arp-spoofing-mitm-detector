from scapy.all import sniff, ARP
from datetime import datetime

# Tables
arp_table = {}   # IP → MAC
mac_table = {}   # MAC → IP

print("Monitoring ARP packets... Press CTRL+C to stop\n")

def log(msg):
    """Helper for timestamped logs"""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

def detect_attack(packet):
    if packet.haslayer(ARP):
        ip = packet.psrc
        mac = packet.hwsrc

        # 🔹 Basic packet info
        log(f"[INFO] {ip} → {mac}")

        # ARP Spoofing Detection (Same IP, Different MAC)
        if ip in arp_table:
            if arp_table[ip] != mac:
                print("\n" + "="*50)
                log("[ ALERT] ARP Spoofing Detected!")
                log(f"IP Address     : {ip}")
                log(f"Original MAC   : {arp_table[ip]}")
                log(f"Detected MAC   : {mac}")
                log("Reason         : MAC mismatch for same IP")
                print("="*50 + "\n")

                # Optional: mark as suspicious
                arp_table[ip] = mac
        else:
            arp_table[ip] = mac

        # MITM Detection (Same MAC, Different IP)
        if mac in mac_table:
            if mac_table[mac] != ip:
                print("\n" + "-"*50)
                log("[ ALERT] Possible MITM Attack!")
                log(f"MAC Address    : {mac}")
                log(f"IP Addresses   : {mac_table[mac]} , {ip}")
                log("Reason         : Same MAC used by multiple IPs")
                print("-"*50 + "\n")
        else:
            mac_table[mac] = ip


sniff(filter="arp", prn=detect_attack, store=False, iface="Wi-Fi")
