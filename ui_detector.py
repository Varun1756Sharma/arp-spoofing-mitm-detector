# ui_final_scrollable.py - With Scrollable Interface
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import datetime
import os
import subprocess
import re
import json
from scapy.all import sniff, ARP

class FixedARPDetectorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ SpoofSec - ARP Spoofing & MITM Detector")
        self.root.geometry("1400x850")
        self.root.configure(bg='#0a0e27')
        
        # Variables
        self.is_monitoring = False
        self.monitor_thread = None
        self.interface = None
        self.gateway_ip = None
        self.my_ip = None
        self.total_packets = 0
        self.arp_packets = 0
        self.suspicious_packets = 0
        self.attack_detected = False
        self.ip_mac_map = {}
        self.start_time = None
        self.duration = 60
        
        # Setup UI
        self.setup_ui()
        self.load_interfaces()
        self.update_display_loop()
        
    def setup_ui(self):
        """Setup UI with proper layout"""
        
        # Main container with scrollbar
        main_container = tk.Frame(self.root, bg='#0a0e27')
        main_container.pack(fill='both', expand=True)
        
        # Canvas for scrolling
        self.canvas = tk.Canvas(main_container, bg='#0a0e27', highlightthickness=0)
        scrollbar = tk.Scrollbar(main_container, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, bg='#0a0e27')
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)
        
        # Bind mouse wheel
        self.canvas.bind("<MouseWheel>", self._on_mousewheel)
        
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # ===== HEADER (Fixed at top) =====
        header = tk.Frame(self.scrollable_frame, bg='#0d1117', height=90)
        header.pack(fill='x', padx=10, pady=5)
        header.pack_propagate(False)
        
        title = tk.Label(header, text="🛡️ SPOOFSEC - ARP SPOOFING & MITM DETECTION SYSTEM", 
                        font=('Segoe UI', 16, 'bold'), bg='#0d1117', fg='#00d4ff')
        title.pack(pady=12)
        
        subtitle = tk.Label(header, text="Real-time Network Security Monitoring | ARP Spoofing Detection | MITM Attack Alert", 
                           font=('Segoe UI', 9), bg='#0d1117', fg='#8892b0')
        subtitle.pack()
        
        # ===== MAIN CONTENT =====
        content_frame = tk.Frame(self.scrollable_frame, bg='#0a0e27')
        content_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Three columns
        left_panel = tk.Frame(content_frame, bg='#161b33', relief='flat', bd=1)
        left_panel.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        middle_panel = tk.Frame(content_frame, bg='#161b33', relief='flat', bd=1)
        middle_panel.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        right_panel = tk.Frame(content_frame, bg='#161b33', relief='flat', bd=1)
        right_panel.pack(side='right', fill='both', expand=True, padx=5, pady=5)
        
        # ===== LEFT PANEL =====
        
        # Interface Selection
        iface_frame = tk.LabelFrame(left_panel, text="🌐 NETWORK INTERFACE", 
                                     font=('Segoe UI', 11, 'bold'),
                                     bg='#161b33', fg='#00d4ff')
        iface_frame.pack(fill='x', padx=15, pady=10)
        
        tk.Label(iface_frame, text="Select Active Interface:", 
                font=('Segoe UI', 10), bg='#161b33', fg='#c0c0c0').pack(pady=(10,5))
        
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(iface_frame, textvariable=self.interface_var, 
                                             font=('Segoe UI', 10), width=30)
        self.interface_combo.pack(pady=5, padx=10)
        
        refresh_btn = tk.Button(iface_frame, text="🔄 Refresh Interfaces", 
                                command=self.load_interfaces,
                                font=('Segoe UI', 9), bg='#2a2a4a', fg='white')
        refresh_btn.pack(pady=5)
        
        # Gateway Configuration
        gw_frame = tk.LabelFrame(left_panel, text="🎯 GATEWAY SETUP", 
                                  font=('Segoe UI', 11, 'bold'),
                                  bg='#161b33', fg='#00d4ff')
        gw_frame.pack(fill='x', padx=15, pady=10)
        
        tk.Label(gw_frame, text="Gateway IP Address:", 
                font=('Segoe UI', 10), bg='#161b33', fg='#c0c0c0').pack(pady=(10,5))
        
        self.gateway_entry = tk.Entry(gw_frame, font=('Segoe UI', 11), 
                                       bg='#0a0e27', fg='#00ff88', width=25)
        self.gateway_entry.pack(pady=5)
        
        tk.Label(gw_frame, text="Your IP Address:", 
                font=('Segoe UI', 10), bg='#161b33', fg='#c0c0c0').pack(pady=(10,5))
        
        self.my_ip_label = tk.Label(gw_frame, text="Not detected", 
                                     font=('Segoe UI', 10, 'bold'),
                                     bg='#161b33', fg='#00d4ff')
        self.my_ip_label.pack(pady=5)
        
        auto_detect_btn = tk.Button(gw_frame, text="🔍 Auto-Detect", 
                                    command=self.auto_detect,
                                    font=('Segoe UI', 9), bg='#2a2a4a', fg='white')
        auto_detect_btn.pack(pady=10)
        
        # Duration Selection
        dur_frame = tk.LabelFrame(left_panel, text="⏱️ MONITORING DURATION", 
                                   font=('Segoe UI', 11, 'bold'),
                                   bg='#161b33', fg='#00d4ff')
        dur_frame.pack(fill='x', padx=15, pady=10)
        
        self.duration_var = tk.StringVar(value="60")
        
        durations = [("30 Seconds", "30"), ("60 Seconds", "60"), ("120 Seconds", "120")]
        for text, value in durations:
            tk.Radiobutton(dur_frame, text=text, variable=self.duration_var, 
                           value=value, bg='#161b33', fg='white', 
                           selectcolor='#161b33', font=('Segoe UI', 10)).pack(anchor='w', padx=20, pady=2)
        
        # ===== START/STOP BUTTONS (VISIBLE NOW) =====
        btn_frame = tk.Frame(left_panel, bg='#161b33')
        btn_frame.pack(pady=20)
        
        self.start_btn = tk.Button(btn_frame, text="▶ START MONITORING", 
                                   command=self.start_monitoring,
                                   font=('Segoe UI', 13, 'bold'), bg='#00aa44', 
                                   fg='white', width=25, height=2)
        self.start_btn.pack(pady=5)
        
        self.stop_btn = tk.Button(btn_frame, text="⏹ STOP MONITORING", 
                                  command=self.stop_monitoring,
                                  font=('Segoe UI', 13, 'bold'), bg='#cc3333', 
                                  fg='white', width=25, height=2, state='disabled')
        self.stop_btn.pack(pady=5)
        
        self.save_btn = tk.Button(left_panel, text="💾 SAVE REPORT", 
                                  command=self.save_report,
                                  font=('Segoe UI', 11, 'bold'), bg='#4a4a6a', 
                                  fg='white', height=2)
        self.save_btn.pack(pady=10, padx=15, fill='x')
        
        # ===== MIDDLE PANEL - Statistics =====
        
        # Packet Counters
        counter_frame = tk.LabelFrame(middle_panel, text="📊 PACKET STATISTICS", 
                                       font=('Segoe UI', 12, 'bold'),
                                       bg='#161b33', fg='#00d4ff')
        counter_frame.pack(fill='x', padx=15, pady=10)
        
        self.total_packets_var = tk.StringVar(value="0")
        self.arp_packets_var = tk.StringVar(value="0")
        self.suspicious_var = tk.StringVar(value="0")
        
        stats_data = [
            ("📦 Total Packets", self.total_packets_var, "#00d4ff"),
            ("🎯 ARP Packets", self.arp_packets_var, "#00ff88"),
            ("⚠️ Suspicious", self.suspicious_var, "#ffcc00")
        ]
        
        for label, var, color in stats_data:
            f = tk.Frame(counter_frame, bg='#161b33')
            f.pack(fill='x', pady=8, padx=10)
            tk.Label(f, text=label+":", font=('Segoe UI', 11), 
                    bg='#161b33', fg=color).pack(side='left')
            tk.Label(f, textvariable=var, font=('Segoe UI', 14, 'bold'),
                    bg='#161b33', fg=color).pack(side='right')
        
        # Security Score
        score_frame = tk.LabelFrame(middle_panel, text="🔒 SECURITY SCORE", 
                                     font=('Segoe UI', 12, 'bold'),
                                     bg='#161b33', fg='#00d4ff')
        score_frame.pack(fill='x', padx=15, pady=10)
        
        self.security_score_var = tk.StringVar(value="100%")
        self.score_label = tk.Label(score_frame, textvariable=self.security_score_var, 
                                     font=('Segoe UI', 36, 'bold'),
                                     bg='#161b33', fg='#00ff88')
        self.score_label.pack(pady=15)
        
        self.security_progress = ttk.Progressbar(score_frame, length=250, mode='determinate')
        self.security_progress.pack(pady=10)
        
        # MITM Status
        mitm_frame = tk.LabelFrame(middle_panel, text="🚨 MITM STATUS", 
                                    font=('Segoe UI', 12, 'bold'),
                                    bg='#161b33', fg='#00d4ff')
        mitm_frame.pack(fill='x', padx=15, pady=10)
        
        self.mitm_status_var = tk.StringVar(value="✅ NO ATTACK")
        self.mitm_status_label = tk.Label(mitm_frame, textvariable=self.mitm_status_var, 
                                           font=('Segoe UI', 13, 'bold'),
                                           bg='#161b33', fg='#00ff88')
        self.mitm_status_label.pack(pady=15)
        
        # Runtime Info
        runtime_frame = tk.LabelFrame(middle_panel, text="⏱️ INFO", 
                                       font=('Segoe UI', 11, 'bold'),
                                       bg='#161b33', fg='#00d4ff')
        runtime_frame.pack(fill='x', padx=15, pady=10)
        
        self.runtime_var = tk.StringVar(value="0s")
        self.interface_info_var = tk.StringVar(value="None")
        
        f = tk.Frame(runtime_frame, bg='#161b33')
        f.pack(fill='x', pady=5, padx=10)
        tk.Label(f, text="Runtime:", font=('Segoe UI', 10), 
                bg='#161b33', fg='#8892b0').pack(side='left')
        tk.Label(f, textvariable=self.runtime_var, font=('Segoe UI', 10, 'bold'),
                bg='#161b33', fg='#00d4ff').pack(side='right')
        
        f = tk.Frame(runtime_frame, bg='#161b33')
        f.pack(fill='x', pady=5, padx=10)
        tk.Label(f, text="Interface:", font=('Segoe UI', 10), 
                bg='#161b33', fg='#8892b0').pack(side='left')
        tk.Label(f, textvariable=self.interface_info_var, font=('Segoe UI', 10, 'bold'),
                bg='#161b33', fg='#00d4ff').pack(side='right')
        
        # ===== RIGHT PANEL - Alerts =====
        
        alert_header = tk.Frame(right_panel, bg='#161b33')
        alert_header.pack(fill='x', padx=15, pady=10)
        
        tk.Label(alert_header, text="🚨 LIVE ALERTS", 
                font=('Segoe UI', 12, 'bold'),
                bg='#161b33', fg='#ff6666').pack(side='left')
        
        self.alert_badge = tk.Label(alert_header, text="0", font=('Segoe UI', 10, 'bold'),
                                     bg='#ff3366', fg='white', padx=8, pady=2)
        self.alert_badge.pack(side='right')
        
        self.alerts_text = scrolledtext.ScrolledText(right_panel, height=25,
                                                      bg='#0a0e27', fg='#ff6666',
                                                      font=('Consolas', 9),
                                                      wrap=tk.WORD)
        self.alerts_text.pack(fill='both', expand=True, padx=15, pady=5)
        
        clear_btn = tk.Button(right_panel, text="🗑 CLEAR ALERTS", 
                              command=self.clear_alerts,
                              font=('Segoe UI', 10), bg='#2a2a4a', fg='white')
        clear_btn.pack(pady=10)
        
        # Status Bar
        status_bar = tk.Frame(self.scrollable_frame, bg='#0d1117', height=35)
        status_bar.pack(fill='x', side='bottom')
        self.status_text = tk.Label(status_bar, text="⚡ Ready | Select Interface → Auto-Detect → Start", 
                                     font=('Segoe UI', 9), bg='#0d1117', fg='#8892b0')
        self.status_text.pack(side='left', padx=20)
        
        # Initial alerts
        self.add_alert("🛡️ SpoofSec Activated")
        self.add_alert("📡 Select interface and click Auto-Detect")
        self.add_alert("▶ Click START MONITORING to begin")
        
        # Configure canvas
        self.scrollable_frame.update_idletasks()
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
    
    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
    
    def load_interfaces(self):
        """Load interfaces"""
        interfaces = []
        try:
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'adapter' in line.lower():
                    iface = line.split('adapter')[1].split(':')[0].strip()
                    if iface and 'Virtual' not in iface:
                        interfaces.append(iface)
        except:
            pass
        if interfaces:
            self.interface_combo['values'] = interfaces
            self.interface_combo.set(interfaces[0])
    
    def auto_detect(self):
        """Auto-detect gateway and IP"""
        try:
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'Default Gateway' in line:
                    gw_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                    if gw_match:
                        gateway = gw_match.group()
                        if gateway != '0.0.0.0':
                            self.gateway_entry.delete(0, tk.END)
                            self.gateway_entry.insert(0, gateway)
                            self.add_alert(f"✅ Gateway: {gateway}")
                            break
            
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            self.my_ip_label.config(text=ip)
            self.add_alert(f"🌐 Your IP: {ip}")
        except Exception as e:
            self.add_alert(f"⚠️ Error: {e}")
    
    def packet_callback(self, pkt):
        """Process packets"""
        self.total_packets += 1
        if pkt.haslayer(ARP):
            self.arp_packets += 1
            src_ip = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc
            if src_ip == self.gateway_ip:
                if src_ip in self.ip_mac_map:
                    if self.ip_mac_map[src_ip] != src_mac:
                        self.suspicious_packets += 1
                        self.attack_detected = True
                        self.root.after(0, self.add_alert, f"🚨 MITM ATTACK! Gateway {src_ip} spoofed!")
                        self.root.after(0, self.mitm_status_var.set, "🔴 ATTACK DETECTED!")
                        self.root.after(0, self.mitm_status_label.config, {'fg': '#ff3366'})
                else:
                    self.ip_mac_map[src_ip] = src_mac
    
    def update_display_loop(self):
        """Update display"""
        if self.is_monitoring and self.start_time:
            elapsed = time.time() - self.start_time
            self.runtime_var.set(f"{elapsed:.0f}s")
            self.total_packets_var.set(str(self.total_packets))
            self.arp_packets_var.set(str(self.arp_packets))
            self.suspicious_var.set(str(self.suspicious_packets))
            
            if self.arp_packets == 0:
                score = 100
            else:
                score = ((self.arp_packets - self.suspicious_packets) / self.arp_packets) * 100
            
            self.security_score_var.set(f"{score:.1f}%")
            self.security_progress['value'] = score
            
            if score >= 80:
                self.score_label.config(fg='#00ff88')
                if not self.attack_detected:
                    self.mitm_status_var.set("✅ SECURE")
            elif score >= 50:
                self.score_label.config(fg='#ffcc00')
                self.mitm_status_var.set("⚠️ WARNING")
            else:
                self.score_label.config(fg='#ff3366')
                self.mitm_status_var.set("🔴 ATTACK!")
        
        self.root.after(1000, self.update_display_loop)
    
    def add_alert(self, message):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.alerts_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.alerts_text.see(tk.END)
        count = len(self.alerts_text.get('1.0', tk.END).split('\n')) - 2
        self.alert_badge.config(text=str(count))
    
    def clear_alerts(self):
        self.alerts_text.delete(1.0, tk.END)
        self.add_alert("Alerts cleared")
    
    def start_monitoring(self):
        interface = self.interface_var.get()
        gateway = self.gateway_entry.get().strip()
        if not interface or not gateway:
            messagebox.showerror("Error", "Select interface and gateway!")
            return
        
        self.interface = interface
        self.gateway_ip = gateway
        self.total_packets = 0
        self.arp_packets = 0
        self.suspicious_packets = 0
        self.attack_detected = False
        self.ip_mac_map = {}
        self.start_time = time.time()
        self.is_monitoring = True
        
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.interface_info_var.set(interface)
        self.add_alert(f"▶ Monitoring started on {interface} for {self.duration_var.get()}s")
        
        self.duration = int(self.duration_var.get())
        self.monitor_thread = threading.Thread(target=self.run_monitoring, daemon=True)
        self.monitor_thread.start()
        self.root.after(self.duration * 1000, self.auto_stop)
    
    def run_monitoring(self):
        try:
            sniff(iface=self.interface, prn=self.packet_callback, store=0, timeout=self.duration)
            self.root.after(0, self.monitoring_complete)
        except Exception as e:
            self.root.after(0, self.add_alert, f"Error: {e}")
            self.root.after(0, self.stop_monitoring)
    
    def auto_stop(self):
        if self.is_monitoring:
            self.monitoring_complete()
    
    def monitoring_complete(self):
        if self.is_monitoring:
            self.stop_monitoring()
            self.add_alert(f"✅ Scan complete! Score: {self.security_score_var.get()}")
            if self.attack_detected:
                self.add_alert("🔴 MITM ATTACK DETECTED!")
            elif self.suspicious_packets > 0:
                self.add_alert("⚠️ Suspicious activity found")
            else:
                self.add_alert("✅ Network secure - No MITM attack")
    
    def stop_monitoring(self):
        self.is_monitoring = False
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.add_alert("⏹ Monitoring stopped")
    
    def save_report(self):
        if not os.path.exists('logs'):
            os.makedirs('logs')
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        if self.arp_packets == 0:
            score = 100
        else:
            score = ((self.arp_packets - self.suspicious_packets) / self.arp_packets) * 100
        report = {
            'timestamp': timestamp,
            'duration': self.duration,
            'interface': self.interface,
            'gateway': self.gateway_ip,
            'statistics': {
                'total_packets': self.total_packets,
                'arp_packets': self.arp_packets,
                'security_score': score,
                'mitm_detected': self.attack_detected
            }
        }
        with open(f'logs/report_{timestamp}.json', 'w') as f:
            json.dump(report, f, indent=2)
        self.add_alert(f"💾 Report saved: logs/report_{timestamp}.json")
        messagebox.showinfo("Saved", f"Report saved!\nScore: {score:.1f}%")

def main():
    root = tk.Tk()
    app = FixedARPDetectorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    print("Starting SpoofSec...")
    if os.name == 'nt':
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("⚠️ Run as Administrator for packet capture!")
        except:
            pass
    main()
