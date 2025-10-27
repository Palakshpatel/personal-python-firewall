from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import sys
import subprocess # <-- NEW: For running shell commands (iptables)

# ----------------------------------------------------
# 1. GLOBAL FIREWALL RULES
# ----------------------------------------------------
# Ports: Block Telnet (23) and HTTP (80)
BLOCKED_PORTS = [23, 80]
# Protocols: Block ICMP (1), which is used for the ping command
BLOCKED_PROTOCOLS = [1]
# IPs: Placeholder IP - CHANGE THIS to the IP of the machine you want to test blocking from.
BLOCKED_SOURCE_IPS = ["1.2.3.4"] 

# Logging Configuration
LOG_FILE = "firewall_audit.log"
INTERFACE_NAME = "eth0" # Verified interface

# ----------------------------------------------------
# 2. HELPER FUNCTION: LOGGING & ENFORCEMENT
# ----------------------------------------------------
def log_event(message, src_ip=None):
    """
    Writes a timestamped message to the audit log and enforces blocking
    using iptables if a source IP is provided and the packet is dropped.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}"
    
    # 1. Write to the file and print to console
    with open(LOG_FILE, "a") as f:
        f.write(log_entry + "\n")
    print(log_entry)

    # 2. iptables ENFORCEMENT
    if src_ip:
        # Command: sudo iptables -A INPUT -s [SRC_IP] -j DROP
        iptables_cmd = ["iptables", "-A", "INPUT", "-s", src_ip, "-j", "DROP"]
        
        try:
            # Execute iptables command
            subprocess.run(iptables_cmd, check=True, capture_output=True, text=True)
            enforcement_message = f"[ENFORCED] Added iptables rule to DROP traffic from {src_ip}"
            
            # Log the successful enforcement
            with open(LOG_FILE, "a") as f:
                f.write(f"[{timestamp}] {enforcement_message}\n")
            print(enforcement_message)

        except subprocess.CalledProcessError as e:
            # Logs failure if iptables returns an error
            print(f"[ERROR] Failed to run iptables command: {e.stderr.strip()}")
        except FileNotFoundError:
            print("[ERROR] iptables command not found. Ensure iptables is installed.")

# ----------------------------------------------------
# 3. CORE FIREWALL LOGIC
# ----------------------------------------------------
def process_packet(packet):
    """
    Checks the packet against defined rules. If a rule is matched, the packet is 
    logged as dropped and the rule is enforced via iptables.
    """
    drop_packet = False
    log_message = ""
    
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        # --- A. IP FILTERING ---
        if src_ip in BLOCKED_SOURCE_IPS:
            log_message = f"[BLOCKED - SOURCE IP] {src_ip} -> {dst_ip}"
            drop_packet = True
        
        # --- B. PROTOCOL FILTERING (ICMP/Ping) ---
        elif protocol in BLOCKED_PROTOCOLS:
            log_message = f"[BLOCKED - PROTOCOL] ICMP (Ping) from {src_ip} -> {dst_ip}"
            drop_packet = True
            
        # Initialize port variables
        src_port, dst_port, proto_name = "-", "-", f"IP_Proto({protocol})"
        
        # Check for TCP/UDP to get port data and apply port rules
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            proto_name = "TCP"
            
            # --- C. PORT FILTERING (TCP) ---
            if dst_port in BLOCKED_PORTS:
                log_message = f"[BLOCKED - PORT] {proto_name} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                drop_packet = True
                
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            proto_name = "UDP"
            
            # --- C. PORT FILTERING (UDP) ---
            if dst_port in BLOCKED_PORTS:
                log_message = f"[BLOCKED - PORT] {proto_name} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                drop_packet = True
                

        if drop_packet:
            # Pass the IP for iptables enforcement
            log_event(f"{log_message}. DROPPED.", src_ip=src_ip) 
            return # Exit function to complete drop simulation
        
        # If not dropped, print the ALLOWED packet
        print(f"[{proto_name}] {src_ip}:{src_port} --> {dst_ip}:{dst_port} [ALLOWED]")

# ----------------------------------------------------
# 4. START THE FIREWALL
# ----------------------------------------------------
print(f"[*] Starting Personal Firewall on {INTERFACE_NAME}... Press Ctrl+C to stop.")
print(f"[*] Blocking Ports: {BLOCKED_PORTS} | Protocols: {BLOCKED_PROTOCOLS} | IPs: {BLOCKED_SOURCE_IPS}")

try:
    sniff(iface=INTERFACE_NAME, prn=process_packet, store=0, count=0)
    
except PermissionError:
    print("\n[!!!] ERROR: Sniffing and iptables require root/sudo privileges.")
    print("[!!!] Run the script with: sudo python3 firewall.py")
except Exception as e:
    print(f"\n[!!!] A critical error occurred: {e}")
    sys.exit(1)
