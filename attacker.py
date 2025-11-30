import scapy.all as scapy
import time
import random
import socket

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't need to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def simulate_attack(count=200):
    target_ip = get_local_ip()
    print(f"Simulating SYN Flood against {target_ip}...")
    print(f"Sending {count} packets...")
    
    for i in range(count):
        # Randomize source port
        sport = random.randint(1024, 65535)
        
        # Create SYN packet
        packet = scapy.IP(dst=target_ip)/scapy.TCP(sport=sport, dport=80, flags="S")
        
        scapy.send(packet, verbose=False)
        
        if i % 50 == 0:
            print(f"Sent {i} packets...")
            
    print("Attack simulation complete.")

if __name__ == "__main__":
    print("Starting attack in 3 seconds...")
    time.sleep(3)
    simulate_attack()
