#!/usr/bin/env python3
import sys
import socket
import subprocess
import threading
import time
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, 
                            QVBoxLayout, QHBoxLayout, QListWidget, QTextEdit,
                            QLineEdit, QComboBox, QSpinBox, QPushButton, QLabel,
                            QMessageBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal

class PacketSniffer(QThread):
    packet_received = pyqtSignal(str, str, int, int, int)  # src_ip, dst_ip, proto, src_port, dst_port

    def __init__(self):
        super().__init__()
        self.running = True
        self.interface = "eth0"  # Change to your interface

    def run(self):
        try:
            # Create raw socket
            sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            
            while self.running:
                raw_packet = sniffer.recvfrom(65535)[0]
                
                # Ethernet header (14 bytes)
                eth_header = raw_packet[:14]
                eth_protocol = int.from_bytes(eth_header[12:14], byteorder='big')
                
                # Only process IPv4 packets (0x0800)
                if eth_protocol != 8:
                    continue
                
                # IP header (20 bytes)
                ip_header = raw_packet[14:34]
                iph = self.parse_ip_header(ip_header)
                
                src_ip = socket.inet_ntoa(iph['source_ip'])
                dst_ip = socket.inet_ntoa(iph['dest_ip'])
                protocol = iph['protocol']
                src_port = 0
                dst_port = 0
                
                # TCP
                if protocol == 6 and len(raw_packet) > 34 + 20:
                    tcp_header = raw_packet[34:54]
                    tcph = self.parse_tcp_header(tcp_header)
                    src_port = tcph['source_port']
                    dst_port = tcph['dest_port']
                
                # UDP
                elif protocol == 17 and len(raw_packet) > 34 + 8:
                    udp_header = raw_packet[34:42]
                    udph = self.parse_udp_header(udp_header)
                    src_port = udph['source_port']
                    dst_port = udph['dest_port']
                
                self.packet_received.emit(src_ip, dst_ip, protocol, src_port, dst_port)
                
        except Exception as e:
            print(f"Packet sniffer error: {e}")

    def parse_ip_header(self, ip_header):
        return {
            'version': (ip_header[0] >> 4),
            'ihl': (ip_header[0] & 0xF) * 4,
            'protocol': ip_header[9],
            'source_ip': ip_header[12:16],
            'dest_ip': ip_header[16:20]
        }

    def parse_tcp_header(self, tcp_header):
        return {
            'source_port': int.from_bytes(tcp_header[:2], byteorder='big'),
            'dest_port': int.from_bytes(tcp_header[2:4], byteorder='big')
        }

    def parse_udp_header(self, udp_header):
        return {
            'source_port': int.from_bytes(udp_header[:2], byteorder='big'),
            'dest_port': int.from_bytes(udp_header[2:4], byteorder='big')
        }

    def stop(self):
        self.running = False

class FirewallGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Python Firewall")
        self.setGeometry(100, 100, 800, 600)
        self.rules = []
        self.sniffer = PacketSniffer()
        self.sniffer.packet_received.connect(self.handle_packet)
        self.init_ui()
        self.backup_iptables()
        self.flush_iptables()
        self.sniffer.start()

    def init_ui(self):
        # Main tabs
        tabs = QTabWidget()
        self.setCentralWidget(tabs)

        # Rules tab
        rules_tab = QWidget()
        rules_layout = QVBoxLayout()
        
        # Rules list
        self.rules_list = QListWidget()
        rules_layout.addWidget(self.rules_list)
        
        # Rule creation form
        form_layout = QHBoxLayout()
        
        left_form = QVBoxLayout()
        self.src_ip_input = QLineEdit()
        self.src_ip_input.setPlaceholderText("Source IP (empty for any)")
        left_form.addWidget(QLabel("Source IP:"))
        left_form.addWidget(self.src_ip_input)
        
        self.dst_ip_input = QLineEdit()
        self.dst_ip_input.setPlaceholderText("Destination IP (empty for any)")
        left_form.addWidget(QLabel("Destination IP:"))
        left_form.addWidget(self.dst_ip_input)
        
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["Any", "TCP", "UDP", "ICMP"])
        left_form.addWidget(QLabel("Protocol:"))
        left_form.addWidget(self.protocol_combo)
        
        right_form = QVBoxLayout()
        self.src_port_input = QSpinBox()
        self.src_port_input.setRange(0, 65535)
        self.src_port_input.setValue(0)
        right_form.addWidget(QLabel("Source Port (0 for any):"))
        right_form.addWidget(self.src_port_input)
        
        self.dst_port_input = QSpinBox()
        self.dst_port_input.setRange(0, 65535)
        self.dst_port_input.setValue(0)
        right_form.addWidget(QLabel("Destination Port (0 for any):"))
        right_form.addWidget(self.dst_port_input)
        
        self.action_combo = QComboBox()
        self.action_combo.addItems(["ACCEPT", "DROP"])  # Changed from ALLOW/DENY to ACCEPT/DROP
        right_form.addWidget(QLabel("Action:"))
        right_form.addWidget(self.action_combo)
        
        self.desc_input = QLineEdit()
        self.desc_input.setPlaceholderText("Rule description")
        right_form.addWidget(QLabel("Description:"))
        right_form.addWidget(self.desc_input)
        
        form_layout.addLayout(left_form)
        form_layout.addLayout(right_form)
        rules_layout.addLayout(form_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        add_btn = QPushButton("Add Rule")
        add_btn.clicked.connect(self.add_rule)
        button_layout.addWidget(add_btn)
        
        del_btn = QPushButton("Delete Selected")
        del_btn.clicked.connect(self.delete_rule)
        button_layout.addWidget(del_btn)
        
        rules_layout.addLayout(button_layout)
        rules_tab.setLayout(rules_layout)
        tabs.addTab(rules_tab, "Rules")
        
        # Logs tab
        logs_tab = QWidget()
        logs_layout = QVBoxLayout()
        self.logs_text = QTextEdit()
        self.logs_text.setReadOnly(True)
        self.logs_text.setFontFamily("Courier")
        logs_layout.addWidget(self.logs_text)
        logs_tab.setLayout(logs_layout)
        tabs.addTab(logs_tab, "Logs")

    def backup_iptables(self):
        try:
            subprocess.run(["iptables-save", ">", "/etc/iptables_backup.rules"], 
                          shell=True, check=True)
            self.log("Backed up current iptables rules")
        except subprocess.CalledProcessError:
            self.log("Failed to backup iptables rules")

    def flush_iptables(self):
        try:
            subprocess.run(["iptables", "-F"], check=True)
            subprocess.run(["iptables", "-X"], check=True)
            subprocess.run(["iptables", "-Z"], check=True)
            subprocess.run(["iptables", "-P", "INPUT", "DROP"], check=True)
            subprocess.run(["iptables", "-P", "FORWARD", "DROP"], check=True)
            subprocess.run(["iptables", "-P", "OUTPUT", "ACCEPT"], check=True)
            subprocess.run(["iptables", "-A", "INPUT", "-m", "state", 
                          "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"], check=True)
            subprocess.run(["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"], check=True)
            self.log("Flushed iptables rules and set default policies")
        except subprocess.CalledProcessError as e:
            self.log(f"Error flushing iptables: {e}")

    def apply_iptables_rule(self, rule):
        cmd = ["iptables", "-I", "INPUT"]
        
        if rule['src_ip']:
            cmd.extend(["-s", rule['src_ip']])
        if rule['dst_ip']:
            cmd.extend(["-d", rule['dst_ip']])
        
        proto_map = {"TCP": "tcp", "UDP": "udp", "ICMP": "icmp"}
        if rule['protocol'] != "Any":
            cmd.extend(["-p", proto_map[rule['protocol']]])
        
        if rule['dst_port'] > 0 and rule['protocol'] in ["TCP", "UDP"]:
            cmd.extend(["--dport", str(rule['dst_port'])])
        
        cmd.extend(["-j", "ACCEPT" if rule['action'] == "ACCEPT" else "DROP"])
        
        try:
            subprocess.run(cmd, check=True)
            self.log(f"Applied rule: {' '.join(cmd)}")
            return True
        except subprocess.CalledProcessError as e:
            self.log(f"Failed to apply rule: {' '.join(cmd)} - {e}")
            return False

    def add_rule(self):
        rule = {
            'src_ip': self.src_ip_input.text().strip(),
            'dst_ip': self.dst_ip_input.text().strip(),
            'protocol': self.protocol_combo.currentText(),
            'src_port': self.src_port_input.value(),
            'dst_port': self.dst_port_input.value(),
            'action': self.action_combo.currentText(),
            'desc': self.desc_input.text().strip()
        }
        
        if self.apply_iptables_rule(rule):
            self.rules.append(rule)
            self.update_rules_list()
            
            # Clear form
            self.src_ip_input.clear()
            self.dst_ip_input.clear()
            self.src_port_input.setValue(0)
            self.dst_port_input.setValue(0)
            self.desc_input.clear()

    def delete_rule(self):
        selected = self.rules_list.currentRow()
        if selected >= 0:
            # Flush and reapply all rules except the selected one
            self.flush_iptables()
            del self.rules[selected]
            
            for rule in self.rules:
                self.apply_iptables_rule(rule)
            
            self.update_rules_list()

    def update_rules_list(self):
        self.rules_list.clear()
        for i, rule in enumerate(self.rules):
            proto = rule['protocol'][0] if rule['protocol'] != "Any" else "*"
            action = "🟢" if rule['action'] == "ALLOW" else "🔴"
            self.rules_list.addItem(
                f"{i}: {action} {rule['src_ip'] or 'any'}:{rule['src_port'] or 'any'} -> "
                f"{rule['dst_ip'] or 'any'}:{rule['dst_port'] or 'any'} ({proto}) - {rule['desc']}"
            )

    def handle_packet(self, src_ip, dst_ip, protocol, src_port, dst_port):
        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        proto_str = proto_map.get(protocol, str(protocol))
        
        for rule in self.rules:
            # Check if packet matches rule
            if ((not rule['src_ip'] or rule['src_ip'] == src_ip) and
                (not rule['dst_ip'] or rule['dst_ip'] == dst_ip) and
                (rule['protocol'] == "Any" or rule['protocol'] == proto_str) and
                (rule['dst_port'] == 0 or rule['dst_port'] == dst_port)):
                
                action = rule['action']
                self.log(
                    f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {action} "
                    f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} ({proto_str}) "
                    f"| Rule: {rule['desc']}"
                )
                break

    def log(self, message):
        self.logs_text.append(message)
        
    def closeEvent(self, event):
        # Restore original iptables rules on exit
        try:
            subprocess.run(["iptables-restore", "<", "/etc/iptables_backup.rules"], 
                          shell=True, check=True)
            self.log("Restored original iptables rules")
        except subprocess.CalledProcessError:
            self.log("Failed to restore iptables rules")
        
        self.sniffer.stop()
        self.sniffer.wait()
        event.accept()

if __name__ == "__main__":
    # Check if running as root
    if not subprocess.run(["id", "-u"], capture_output=True).stdout.decode().strip() == "0":
        print("Error: Must run as root.")
        sys.exit(1)
    
    app = QApplication(sys.argv)
    window = FirewallGUI()
    window.show()
    sys.exit(app.exec_())
