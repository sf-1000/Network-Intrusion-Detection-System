# Network-Intrusion-Detection-System

A lightweight real-time Intrusion Detection System built in Python using Scapy.
It monitors live network traffic and detects:\

	•	ARP Spoofing 
	
	•	SYN Port Scans 
	
	•	ICMP Flood Attacks 

This project demonstrates packet-level analysis, protocol understanding, and real-world threat detection techniques in a simple, readable Python tool.

⸻

# 🔐 Features

✔ Real-time Packet Capture

Monitors both Wi-Fi (en0) and loopback (lo0) interfaces.

✔ ARP Spoofing Detection

Detects if a device sends fake ARP replies pretending to be your router.

✔ SYN Port Scan Detection

Identifies SYN scans performed by attackers using tools like Nmap.

✔ ICMP Flood Detection

Catches high-rate ICMP echo floods (DoS-style attacks).

⸻

# 🧠How It Works

1. Packet Capture (Scapy Sniffer)

Uses: sniff(prn=packet_callback, iface=["en0", "lo0"], store=False)

This captures:
	•	Wi-Fi traffic
	•	Localhost/Nmap traffic
	•	ARP, TCP, ICMP packets

2. ARP Spoofing
   
used for:
	•	Man-in-the-Middle attacks
	•	Session hijacking
	•	DNS poisoning
	•	Credential interception

Detection logic
	1.	Track IP → MAC mappings
	2.	If the same IP suddenly appears with a new MAC → alert

Sample Alert:

🚨 ARP SPOOFING DETECTED!
IP 10.24.96.1 claimed by multiple MACs.

3. Port Scan Detection

Detects:
Attackers probing many ports quickly using Nmap: nmap -sS target_ip

Detection logic
	•	Track TCP SYN packets per source IP
	•	Count unique destination ports in a time window
	•	Trigger alert if threshold is exceeded

Sample Alert:

🚨 PORT SCAN DETECTED!
Source IP: 127.0.0.1
Probing 12 ports within 5 seconds.








4. 
5. 
