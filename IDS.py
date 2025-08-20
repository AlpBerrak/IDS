import time
import requests
import subprocess
from scapy.all import sniff, IP, TCP, UDP, ICMP
from colorama import Forze, Style, init # get colored terminal messages

# initialize colorama
init(autoreset=True)

# configs
SYN_THRESHOLD = 20 # max syn pakcets allowed per IP in Time window seconds
UDP_THRESHOLD = 50       # Max UDP packets allowed per IP in Time window
ICMP_THRESHOLD = 30      # Max ICMP packets allowed per IP in time window
PORT_SCAN_THRESHOLD = 10 # Max distinct ports accessed per IP in time window
TIME_WINDOW = 10         # Time window in seconds for counting packets

ALERT_LOG_FILE = "ids_alerts.log"  # File to log alerts



