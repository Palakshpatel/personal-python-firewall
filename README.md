🛡️ Advanced Personal Firewall with System Enforcement
Project Overview
This project is a high-impact implementation of a Host-Based Personal Firewall developed in Python. It moves beyond a simple packet monitoring script to function as a live, kernel-enforced intrusion prevention system (IPS) on a Linux operating system.

The firewall uses the Scapy library to sniff network traffic and enforce custom security policies. Crucially, it demonstrates mastery of system interaction by integrating with Linux iptables to apply permanent, persistent block rules against malicious sources immediately upon detection.

Key Features & Deliverables
Real-Time Packet Analysis: Uses Scapy to capture and parse network traffic on the eth0 interface.

Layer 3/4 Filtering: Enforces rules based on Source/Destination IPs, Ports (e.g., Telnet 23, HTTP 80), and Protocols (e.g., ICMP/Ping).

Proactive Enforcement (The Upgrade): Automatically executes the iptables command via Python's subprocess module to install a permanent DROP rule in the kernel's firewall table against any detected attacker's IP.

Comprehensive Audit Logging: Records all blocked and enforced events to a file (firewall_audit.log) with timestamps for incident response purposes.

Project Structure & Dependencies
Prerequisites
Operating System: Linux Distribution (Tested on Kali Linux).

Virtualization: Oracle VM VirtualBox or VMware.

Kernel Tool: iptables (or iptables-legacy) must be installed.

Installation & Setup
Clone the Repository:

Bash

git clone https://github.com/YOUR_USERNAME/personal-python-firewall.git
cd personal-python-firewall
Install Python Dependencies:

Bash

# Install Scapy and other requirements
sudo apt install python3-scapy
Usage and Testing (Demonstration)
To run the firewall, you must use sudo because network sniffing and managing iptables rules requires root privileges.

1. Clear Existing Rules (Crucial Cleanup)
Before running, always clear your firewall rules to avoid conflicts:

Bash

sudo iptables -F
2. Launch the Firewall
Bash

sudo python3 firewall.py
3. Test Enforcement (ICMP Block)
To demonstrate the kernel-level enforcement:

Identify Attacker IP: Get the IP address of the machine you are testing from (e.g., your Windows/Host machine).

Trigger the Block: From the external attacker machine, try to ping the Kali VM.

Verify the Block: The firewall.py terminal will output the following:

[BLOCKED - PROTOCOL] ICMP (Ping) from 192.168.x.x -> ... DROPPED.
[ENFORCED] Added iptables rule to DROP traffic from 192.168.x.x
4. Verify Persistent Rule
Confirm the rule was added permanently to the system by listing the active rules:

Bash

sudo iptables-legacy -L -n
The output will show a DROP rule for the attacker's IP in the INPUT chain, proving the enforcement was successful.

Created by PALAKSH PATEL for the Elevate Labs Cyber Security Internship.
