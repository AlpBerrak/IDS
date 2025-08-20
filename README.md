# Terminal IDS
## About:
TerminalIDS is an advanced Python-based Intrusion Detection System (IDS) that monitors network traffic in real-time. It detects multiple types of network attacks including SYN floods, UDP floods, ICMP floods, and port scanning. The IDS logs alerts, shows color-coded messages in the terminal, automatically blocks malicious IPs using iptables, and can provide geolocation of attackers using the ipinfo.io API.

This tool is useful for cybersecurity professionals, network administrators, and students to understand network threats and experiment with real-time detection.

## Features:
- Detects SYN flood attacks: multiple TCP SYN packets from a single IP in a short time.
- Detects UDP flood attacks: large numbers of UDP packets from a single IP.
- Detects ICMP (ping) flood attacks.
- Detects Port scanning activity: multiple distinct ports accessed by the same IP in a short time.
- Logs alerts to a file (ids_alerts.log).
- Color-coded terminal alerts for better readability.
- Automatically blocks attacking IPs using iptables.
- Retrieves geolocation information of suspicious IPs (city and country).
- Easy to customize thresholds and time windows for different attack types.

## Defintions of Attacks:
1. SYN Flood

- A type of Denial-of-Service (DoS) attack.

- The attacker sends many TCP SYN packets to a target server without completing the handshake, exhausting server resources.

2. UDP Flood

- A DoS attack where the attacker sends a large number of UDP packets to random or specific ports.

- The target may crash or become unresponsive due to the high packet volume.

3. ICMP Flood (Ping Flood)

- A DoS attack using ICMP Echo Request (ping) packets.

- Overwhelms the target system’s network resources.

4. Port Scanning

- A reconnaissance technique used to identify open ports and services on a system.

- Can indicate preparation for an attack or system vulnerability mapping.

## Installation:

## Usage: