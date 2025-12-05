## from scapy.all import sniff

## def packet_callback(packet):
##    print(packet.summary())

##print("Starting NIDS... (Press CTRL + C to stop)")
##sniff(prn=packet_callback)

from scapy.all import ARP, sniff, TCP, IP, ICMP
from collections import defaultdict
import time

# This line of code is to store known IP -> MAC mappings
ip_to_mac = {}

def detect_arp_spoof(packet):
    # Check if the packet is an ARP reply
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP is-at (reply)
        sender_ip = packet[ARP].psrc      # IP address claiming
        sender_mac = packet[ARP].hwsrc    # MAC address claiming the IP

        # This is to save a newly seen IP address
        if sender_ip not in ip_to_mac:
            ip_to_mac[sender_ip] = sender_mac
            print(f"[INFO] Learned: {sender_ip} -> {sender_mac}")

        # If IP already exists but MAC is different → SPOOFING
        elif ip_to_mac[sender_ip] != sender_mac:
            print("\n[ALERT] ARP SPOOFING DETECTED!")
            print(f"IP address {sender_ip} is being claimed by multiple MACs")
            print(f" - Original MAC: {ip_to_mac[sender_ip]}")
            print(f" - Fake MAC:     {sender_mac}\n")



# Track SYN attempts from each source IP
syn_tracker = defaultdict(list)

TIME_WINDOW = 5       
PORT_THRESHOLD = 10    # number of ports probed before alert

def detect_port_scan(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags

        # Check if SYN flag is set and ACK is not
        if flags == "S":
            current_time = time.time()
            
            syn_tracker[src_ip].append((dst_port, current_time))

            # Remove old entries outside time window
            syn_tracker[src_ip] = [
                (port, t) for (port, t) in syn_tracker[src_ip]
                if current_time - t <= TIME_WINDOW
            ]

            # Count unique ports scanned recently
            unique_ports = {port for (port, t) in syn_tracker[src_ip]}

            if len(unique_ports) >= PORT_THRESHOLD:
                print("\n🚨 [ALERT] PORT SCAN DETECTED! 🚨")
                print(f"Source IP: {src_ip}")
                print(f"Probing {len(unique_ports)} ports within {TIME_WINDOW} seconds.")
                print(f"Ports: {sorted(unique_ports)}\n")

                syn_tracker[src_ip] = []


icmp_tracker = defaultdict(list)

ICMP_TIME_WINDOW = 5      # seconds
ICMP_THRESHOLD = 50       # number of packets in window before alert

def detect_icmp_flood(packet):
    # Only care about ICMP packets with an IP layer
    if packet.haslayer(IP) and packet.haslayer(ICMP):
        src_ip = packet[IP].src
        now = time.time()

        # Record this ICMP packet time
        icmp_tracker[src_ip].append(now)

        # Keep only recent timestamps (within time window)
        icmp_tracker[src_ip] = [
            t for t in icmp_tracker[src_ip]
            if now - t <= ICMP_TIME_WINDOW
        ]

        count = len(icmp_tracker[src_ip])

        if count >= ICMP_THRESHOLD:
            print("\n🚨 [ALERT] ICMP FLOOD DETECTED! 🚨")
            print(f"Source IP: {src_ip}")
            print(f"ICMP packets in last {ICMP_TIME_WINDOW} seconds: {count}\n")

           
            icmp_tracker[src_ip] = []




def packet_callback(packet):
    detect_arp_spoof(packet)
    detect_port_scan(packet)
    detect_icmp_flood(packet)

print("Starting NIDS with ARP Spoofing Detection...")
print("Press CTRL + C to stop.\n")

sniff(prn=packet_callback, iface=["en0", "lo0"], store=False)