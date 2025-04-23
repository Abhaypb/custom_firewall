# Python Firewall with GUI

A simple Python-based firewall with a PyQt5 graphical user interface that allows managing iptables rules and monitoring network traffic.

## Features

- Graphical interface for managing firewall rules
- Real-time packet sniffing and logging
- Rule management (add/delete)
- Backup and restore of original iptables rules
- Support for TCP, UDP, and ICMP protocols
- Port-based filtering
- Action logging for matched packets

## Requirements

- Python 3.x
- PyQt5
- iptables (Linux)
- Root privileges

## Installation

1. Clone the repository or download the script
2. Install dependencies:
   ```bash
   pip install PyQt5
   
##Make the script executable:
chmod +x pyfirewall.py


##Run the script as root:
sudo ./pyfirewall.py
