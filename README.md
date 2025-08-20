# Terminal IDS
## About:
Terminal IDS is an advanced Python-based Intrusion Detection System (IDS) that monitors network traffic in real-time. It detects multiple types of network attacks including SYN floods, UDP floods, ICMP floods, and port scanning. The IDS logs alerts, shows color-coded messages in the terminal, automatically blocks malicious IPs using iptables, and can provide geolocation of attackers using the ipinfo.io API.

This tool is useful for cybersecurity professionals, network administrators, and students to understand network threats and experiment with real-time detection.

Must be run in linux


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
### SYN Flood

- A type of Denial-of-Service (DoS) attack.

- The attacker sends many TCP SYN packets to a target server without completing the handshake, exhausting server resources.

### UDP Flood

- A DoS attack where the attacker sends a large number of UDP packets to random or specific ports.

- The target may crash or become unresponsive due to the high packet volume.

### ICMP Flood (Ping Flood)

- A DoS attack using ICMP Echo Request (ping) packets.

- Overwhelms the target system’s network resources.

### Port Scanning

- A reconnaissance technique used to identify open ports and services on a system.

- Can indicate preparation for an attack or system vulnerability mapping.

## Installation:

1. **Requirements:**
   - Python 3.x
   - `scapy` library for packet sniffing
   - `requests` library for geolocation API
   - `colorama` library for colored terminal output
   - Linux system with `iptables` (for automatic IP blocking)
   - Internet connection (for geolocation lookup)

2. **Install Python dependencies:**
```bash
pip install scapy requests colorama

```
3. **Clone or download the Terminal IDS script to your local machine.**
4. **Ensure the script has execute permissions:**
```bash
chmod +x terminal_ids.py
```

## Usage:
**Start the IDS**
```bash
sudo python3 IDS.py
```

The terminal will display:
- [INFO] messages in yellow/cyan
- [ALERT] messages in red for detected attacks
- Alerts are also logged to ids_alerts.log in the same directory.
- The IDS will automatically block malicious IPs using iptables.
- To stop monitoring, press Ctrl+C.