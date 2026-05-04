# test_capture.py - Simple Packet Capture Test
from scapy.all import sniff

def packet_callback(pkt):
    print(f"📦 Packet captured: {pkt.summary()}")

print("="*60)
print("🔍 SIMPLE PACKET CAPTURE TEST")
print("="*60)
print("Testing packet capture for 15 seconds...")
print("Make sure you're connected to WiFi/hotspot")
print("Try browsing internet or ping something\n")

try:
    sniff(timeout=15, prn=packet_callback, store=0)
    print("\n✅ Test complete!")
except PermissionError:
    print("\n❌ Permission denied! Run as Administrator!")
except Exception as e:
    print(f"\n❌ Error: {e}")