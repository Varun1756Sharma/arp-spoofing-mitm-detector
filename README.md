# arp-spoofing-mitm-detector
LAN Packet Analyzer with ARP Spoofing Detection:-

[Project Description]

This project implements a LAN Packet Analyzer to monitor ARP traffic and detect ARP spoofing (ARP poisoning) attacks in a local network. Since ARP does not provide authentication, attackers can exploit it to perform Man-in-the-Middle (MITM) attacks by sending fake ARP replies.

The system captures ARP packets, analyzes IP–MAC mappings, and detects suspicious changes using rule-based logic. Alerts and logs are generated when abnormal behavior is identified, helping in early detection of LAN-level attacks.

[Objectives]

Capture and analyze ARP packets in a LAN

Validate IP–MAC address mappings

Detect ARP spoofing using consistency checks

Generate alerts and logs for suspicious activity

[Methodology (High Level)]

Capture ARP packets from the network

Extract and track IP–MAC mappings

Detect conflicts or abnormal changes

Log and alert suspicious behavior

[Tools & Technologies]

Language: Python

Library: Scapy

OS: Kali Linux / Linux

Optional: Streamlit (visualization)

Tools: VS Code, GitHub

[Applications]

Detection of ARP spoofing and MITM attacks

LAN security monitoring

Cybersecurity learning and experimentation

[Disclaimer]

This project is for educational purposes only. Use only on authorized networks.
