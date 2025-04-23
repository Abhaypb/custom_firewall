
# Project Report

```markdown
# Python Firewall Project Report

## 1. Introduction

This project implements a simple firewall with a graphical user interface using Python and PyQt5. The firewall leverages Linux's iptables for actual packet filtering while providing an intuitive interface for rule management and traffic monitoring.

## 2. System Architecture

### Components:
1. **GUI Layer**: PyQt5-based interface with tabs for rules management and logs
2. **Control Layer**: Manages iptables rules and packet processing
3. **Monitoring Layer**: Packet sniffer thread for real-time traffic monitoring

### Key Classes:
- `FirewallGUI`: Main application window and interface
- `PacketSniffer`: QThread subclass for packet capture and analysis
- Rule management system for iptables integration

## 3. Features Implemented

### Rule Management
- Add/delete firewall rules
- Support for IP addresses, ports, and protocols
- Two actions: ACCEPT or DROP

### Network Monitoring
- Real-time packet sniffing
- Basic protocol analysis (TCP, UDP, ICMP)
- Logging of matched packets

### Safety Features
- Automatic backup of original iptables rules
- Restoration of original rules on exit
- Default deny policy with exceptions for established connections and loopback

## 4. Technical Implementation Details

### Packet Sniffing
- Uses raw sockets to capture packets
- Parses Ethernet, IP, and transport layer headers
- Emits signals for GUI updates

### iptables Integration
- Programmatically generates and executes iptables commands
- Maintains rule consistency between GUI and actual firewall
- Default policies set for security

### Threading
- Packet sniffer runs in a separate thread to prevent GUI freezing
- Qt signals used for thread-safe GUI updates

## 5. Testing

The firewall was tested with:
- Various rule combinations (IP, port, protocol filters)
- Different types of network traffic (HTTP, DNS, ping)
- Rule addition and deletion scenarios
- Application exit/restore functionality

## 6. Limitations

1. **Platform Dependency**: Only works on Linux with iptables
2. **Root Requirement**: Must run with elevated privileges
3. **Basic Filtering**: Lacks advanced matching capabilities of enterprise firewalls
4. **No Persistence**: Rules aren't saved between sessions
5. **Limited Protocol Support**: Only handles TCP, UDP, and ICMP

## 7. Future Enhancements

1. Add rule persistence (save/load from file)
2. Implement more protocol support
3. Add rule editing capability
4. Include outgoing traffic filtering
5. Add more detailed packet inspection
6. Implement rate limiting rules
7. Add rule prioritization

## 8. Conclusion

This project successfully demonstrates how to build a basic firewall with a graphical interface in Python. While not suitable for production environments, it serves as an excellent educational tool for understanding firewall concepts, packet filtering, and network security fundamentals. The modular design allows for easy expansion of functionality.
