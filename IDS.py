import time
import requests
import subprocess
from scapy.all import sniff, IP, TCP, UDP, ICMP
from colorama import Fore, Style, init # get colored terminal messages

# initialize colorama
init(autoreset=True)

# configs
SYN_THRESHOLD = 20 # max syn pakcets allowed per IP in Time window seconds
UDP_THRESHOLD = 50       # Max UDP packets allowed per IP in Time window
ICMP_THRESHOLD = 30      # Max ICMP packets allowed per IP in time window
PORT_SCAN_THRESHOLD = 10 # Max distinct ports accessed per IP in time window
TIME_WINDOW = 10         # Time window in seconds for counting packets

ALERT_LOG_FILE = "ids_alerts.log"  # File to log alerts


# Data structures to track sus activity
synCounter = {} # store timestamps of SYN packets per IP
udpCounter ={} # sotres timeseaps of UDP packets per ip
icmpCounter = {} #stores timestamps of ICMP packets per ip
portScanCounter = {} # stores port access times per ip
blockedIPS = set() # set to track already blocked IPS

# Helper functions

# Log alert message to both terminal and file
# use red color for terminal alerts
def logAlert(message):
  timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
  # append alert to log file
  with open(ALERT_LOG_FILE, "a") as f:
    f.write(f"{timestamp} - {message}\n")
  #print red colored alert to reminal
  print(Fore.RED + f"[ALERT] {message}" + Style.RESET_ALL)

# Block a malicious IP using iptables
# Avoid blocking the same IP multiple times
def blockIP(ip):
  if ip in blockedIPS:
    return
  try:
    # Add DROP rule to iptables for this IP
    subprocess.run(["sudo","iptables","-A","INPUT","-s",ip,"-j","DROP"])
    blockedIPS.add(ip)
    print(Fore.YELLOW + f"[INFO] Blocked IP {ip}" + Style.RESET_ALL)  
  except Exception as e:
    print(Fore.MAGENTA + f"[WARN] Could not block IP {ip}: {e}" + Style.RESET_ALL)
    
# Get geolocation of an IP using ipinfo.io API
# Returns city and country if possible
def getGeolocation(ip):
  try: 
    response = requests.get(f"https://ipinfo.io/{ip}/json")
    data = response.json()
    country = data.get("country", "Unknown")
    city = data.get("city", "Unknown")
    return f"{city}, {country}"
  except:
    return "Unknown"
      
  
# Detection Functions

# Detect SYN flood attacks
# Counts SYN packets per IP withing time window seconds
# if threshold exceeded, log alert and block IP
def detectSynFlood(pkt):
  if pkt.haslayer(TCP) and pkt[TCP].flags == 'S':
    srcIP = pkt[IP].src
    now = time.time()
    synCounter.setdefault(srcIP, []).append(now)
    # remove timestamps older than timewindow
    portScanCounter[srcIP] = [t for t in synCounter[srcIP] if now - t <= TIME_WINDOW]
    if len(synCounter[srcIP]) > SYN_THRESHOLD:
      location = getGeolocation(srcIP)
      logAlert(f"SYN flood detected from {srcIP} ({location})")
      blockIP(srcIP)
      
# Detect UDP flood attacks
def detectUdpFlood(pkt):
  if pkt.haslayer(UDP):
    srcIP = pkt[IP].src
    now = time.time()
    udpCounter.setdefault(srcIP,[]).append(now)
    udpCounter[srcIP] = [t for t in udpCounter[srcIP] if now - t <= TIME_WINDOW]
    if len(udpCounter[srcIP]) > UDP_THRESHOLD:
      location = getGeolocation(srcIP)
      logAlert(f"UDP flood detected from {srcIP} ({location})")
      blockIP(srcIP)
  
# Detect ICMP (ping) flood attacks
# counts ICMP packets per IP within Time window seconds
def detectIcmpFlood(pkt):
  if pkt.haslayer(ICMP):
    srcIP = pkt[IP].src
    now = time.time()
    icmpCounter.setdefault(srcIP, []).append(now)
    icmpCounter[srcIP] = [t for t in icmpCounter[srcIP] if now - t <= TIME_WINDOW]
    if len(icmpCounter[srcIP]) > ICMP_THRESHOLD:
      location = getGeolocation(srcIP)
      logAlert(f"ICMP flood detected from {srcIP} ({location})")
      blockIP(srcIP) 