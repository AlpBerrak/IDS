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