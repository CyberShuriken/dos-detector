import scapy.all as scapy
from collections import defaultdict
import time
import threading

class DoSDetector:
    def __init__(self):
        self.packet_counts = defaultdict(int)
        self.syn_counts = defaultdict(int)
        self.start_time = time.time()
        self.alerts = []
        self.lock = threading.Lock()
        self.running = True
        
        # Thresholds
        self.MAX_PPS = 50 # Packets Per Second (Low for demo purposes)
        self.MAX_SYN_PPS = 20 # SYN Packets Per Second

    def process_packet(self, packet):
        if not self.running:
            return

        with self.lock:
            # Basic IP Packet Counting
            if packet.haslayer(scapy.IP):
                src_ip = packet[scapy.IP].src
                self.packet_counts[src_ip] += 1
                
                # Debug print to confirm we are seeing traffic
                if sum(self.packet_counts.values()) % 10 == 0:
                    print(f"[DEBUG] Sniffed packet from {src_ip}")
                
                # SYN Flood Detection (TCP)
                if packet.haslayer(scapy.TCP):
                    # Flag 'S' is SYN (0x02)
                    if packet[scapy.TCP].flags & 0x02:
                        self.syn_counts[src_ip] += 1

    def monitor_traffic(self):
        """
        Background loop to check thresholds every second.
        """
        while self.running:
            time.sleep(1)
            with self.lock:
                current_time = time.time()
                elapsed = current_time - self.start_time
                
                if elapsed >= 1:
                    # Calculate totals for debug
                    total_packets = sum(self.packet_counts.values())
                    total_syn = sum(self.syn_counts.values())
                    
                    # Debug Print
                    if total_packets > 0:
                        print(f"[DEBUG] Rate: {total_packets/elapsed:.1f} PPS | SYN: {total_syn/elapsed:.1f} PPS")

                    # Check for anomalies
                    for ip, count in self.packet_counts.items():
                        pps = count / elapsed
                        if pps > self.MAX_PPS:
                            print(f"[ALERT] High Traffic from {ip}: {pps:.1f} PPS")
                            self.add_alert(ip, "High Traffic Volume", f"{int(pps)} packets/sec")
                            
                    for ip, count in self.syn_counts.items():
                        pps = count / elapsed
                        if pps > self.MAX_SYN_PPS:
                            print(f"[ALERT] SYN Flood from {ip}: {pps:.1f} PPS")
                            self.add_alert(ip, "SYN Flood Detected", f"{int(pps)} SYN/sec")

                    # Reset counters for next window
                    self.packet_counts.clear()
                    self.syn_counts.clear()
                    self.start_time = time.time()

    def get_status(self):
        with self.lock:
            # Check if the latest alert was recent (less than 10 seconds ago)
            is_under_attack = False
            if self.alerts:
                # We can't easily parse the time string back to a timestamp safely on all OSs
                # So we'll just check if the alert was added recently using a simpler heuristic
                # Or better yet, store the raw timestamp in the alert too
                last_alert_time = self.alerts[0].get('timestamp_raw', 0)
                if time.time() - last_alert_time < 10:
                    is_under_attack = True
            
            return {
                "alerts": self.alerts,
                "is_under_attack": is_under_attack
            }

    def add_alert(self, ip, type, details):
        timestamp = time.strftime("%H:%M:%S")
        alert = {
            "time": timestamp,
            "timestamp_raw": time.time(), # Store raw time for calculation
            "ip": ip,
            "type": type,
            "details": details
        }
        # Avoid duplicate alerts spamming the UI
        if not self.alerts or self.alerts[-1]['details'] != details:
            self.alerts.insert(0, alert)
            # Keep only last 50 alerts
            if len(self.alerts) > 50:
                self.alerts.pop()

    def start(self):
        # Start sniffer in a thread
        t_sniff = threading.Thread(target=lambda: scapy.sniff(prn=self.process_packet, store=False))
        t_sniff.daemon = True
        t_sniff.start()
        
        # Start monitor in a thread
        t_monitor = threading.Thread(target=self.monitor_traffic)
        t_monitor.daemon = True
        t_monitor.start()
