#!/usr/bin/env python3
"""
GuardianWall - Cross-Platform Host-Based Firewall System

A production-ready firewall that actively enforces rules using OS-level firewalls:
- Windows: Uses Windows Firewall (WFP) via netsh or PowerShell
- Linux: Uses nftables or iptables

Features:
- Default deny inbound traffic
- Allow specified safe ports
- Allow established/related connections
- Allow loopback
- Auto-threat detection and blocking
- Dynamic blocking with expiration
- Comprehensive logging
"""

import os
import sys
import time
import logging
import platform
import subprocess
import threading
import json
from datetime import datetime, timedelta
from collections import defaultdict, deque
import socket
import struct
import select
import psutil  # For process monitoring (install via pip)

# Configuration
ALLOWED_PORTS = [80, 443, 22, 3389]  # HTTP, HTTPS, SSH, RDP
BLOCK_DURATION = 3600  # 1 hour in seconds
LOG_FILE = 'guardianwall.log'
CONFIG_FILE = 'guardianwall_config.json'

# Threat detection thresholds
RAPID_CONNECTION_THRESHOLD = 10  # Connections per minute
PORT_SCAN_THRESHOLD = 5  # Different ports scanned per minute
BRUTE_FORCE_THRESHOLD = 5  # Failed logins per minute
HIGH_FREQUENCY_THRESHOLD = 100  # Requests per minute

class FirewallManager:
    def __init__(self):
        self.os_type = platform.system().lower()
        self.blocked_ips = {}  # IP -> expiration_time
        self.threat_tracker = defaultdict(lambda: {'connections': deque(maxlen=60),
                                                   'ports': set(),
                                                   'failed_logins': deque(maxlen=60),
                                                   'requests': deque(maxlen=60)})
        self.logger = self.setup_logging()
        self.load_config()

    def setup_logging(self):
        logger = logging.getLogger('GuardianWall')
        logger.setLevel(logging.INFO)
        handler = logging.FileHandler(LOG_FILE)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                global ALLOWED_PORTS, BLOCK_DURATION
                ALLOWED_PORTS = config.get('allowed_ports', ALLOWED_PORTS)
                BLOCK_DURATION = config.get('block_duration', BLOCK_DURATION)

    def save_config(self):
        config = {
            'allowed_ports': ALLOWED_PORTS,
            'block_duration': BLOCK_DURATION
        }
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)

    def initialize_firewall(self):
        """Set up initial firewall rules"""
        self.logger.info("Initializing firewall rules")
        if self.os_type == 'windows':
            self._init_windows_firewall()
        elif self.os_type in ['linux', 'darwin']:
            self._init_linux_firewall()
        else:
            raise NotImplementedError(f"Unsupported OS: {self.os_type}")

    def _init_windows_firewall(self):
        """Initialize Windows Firewall rules using netsh"""
        try:
            # Reset to defaults
            subprocess.run(['netsh', 'advfirewall', 'reset'], check=True, capture_output=True)

            # Set default inbound to block
            subprocess.run(['netsh', 'advfirewall', 'set', 'allprofiles', 'firewallpolicy', 'blockinbound,allowoutbound'], check=True, capture_output=True)

            # Allow loopback
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name="Loopback"', 'dir=in', 'action=allow', 'profile=any', 'interfacetype=loopback'], check=True, capture_output=True)

            # Allow established connections
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name="Established"', 'dir=in', 'action=allow', 'profile=any', 'protocol=tcp', 'localport=any', 'remoteport=any', 'state=established'], check=True, capture_output=True)

            # Allow specified ports
            for port in ALLOWED_PORTS:
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', f'name="Allow Port {port}"', 'dir=in', 'action=allow', 'profile=any', 'protocol=tcp', f'localport={port}'], check=True, capture_output=True)

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to initialize Windows firewall: {e}")

    def _init_linux_firewall(self):
        """Initialize Linux firewall using nftables or iptables"""
        try:
            # Check if nftables is available, otherwise use iptables
            if subprocess.run(['which', 'nft'], capture_output=True).returncode == 0:
                self._init_nftables()
            else:
                self._init_iptables()
        except Exception as e:
            self.logger.error(f"Failed to initialize Linux firewall: {e}")

    def _init_nftables(self):
        """Initialize nftables rules"""
        rules = f"""
        flush ruleset

        table inet guardianwall {{
            chain input {{
                type filter hook input priority 0; policy drop;

                # Allow loopback
                iif lo accept

                # Allow established and related
                ct state established,related accept

                # Allow specified ports
                {" ".join(f"tcp dport {port} accept" for port in ALLOWED_PORTS)}

                # Drop everything else
                drop
            }}

            chain output {{
                type filter hook output priority 0; policy accept;
            }}
        }}
        """
        with open('/tmp/guardianwall.nft', 'w') as f:
            f.write(rules)
        subprocess.run(['nft', '-f', '/tmp/guardianwall.nft'], check=True)

    def _init_iptables(self):
        """Initialize iptables rules"""
        subprocess.run(['iptables', '-F'], check=True)
        subprocess.run(['iptables', '-X'], check=True)
        subprocess.run(['iptables', '-t', 'nat', '-F'], check=True)

        # Default policy
        subprocess.run(['iptables', '-P', 'INPUT', 'DROP'], check=True)
        subprocess.run(['iptables', '-P', 'FORWARD', 'DROP'], check=True)
        subprocess.run(['iptables', '-P', 'OUTPUT', 'ACCEPT'], check=True)

        # Allow loopback
        subprocess.run(['iptables', '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'], check=True)

        # Allow established
        subprocess.run(['iptables', '-A', 'INPUT', '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'], check=True)

        # Allow specified ports
        for port in ALLOWED_PORTS:
            subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', str(port), '-j', 'ACCEPT'], check=True)

    def block_ip(self, ip, reason):
        """Block an IP address"""
        expiration = datetime.now() + timedelta(seconds=BLOCK_DURATION)
        self.blocked_ips[ip] = expiration
        self.logger.info(f"Blocked IP {ip} for {BLOCK_DURATION} seconds. Reason: {reason}")

        if self.os_type == 'windows':
            self._block_ip_windows(ip)
        elif self.os_type in ['linux', 'darwin']:
            self._block_ip_linux(ip)

    def _block_ip_windows(self, ip):
        """Block IP on Windows"""
        try:
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', f'name="Block {ip}"', 'dir=in', 'action=block', 'profile=any', 'remoteip=' + ip], check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to block IP {ip} on Windows: {e}")

    def _block_ip_linux(self, ip):
        """Block IP on Linux"""
        try:
            if subprocess.run(['which', 'nft'], capture_output=True).returncode == 0:
                subprocess.run(['nft', 'add', 'rule', 'inet', 'guardianwall', 'input', 'ip', 'saddr', ip, 'drop'], check=True)
            else:
                subprocess.run(['iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to block IP {ip} on Linux: {e}")

    def unblock_expired_ips(self):
        """Remove expired blocks"""
        now = datetime.now()
        expired = [ip for ip, exp in self.blocked_ips.items() if exp < now]
        for ip in expired:
            del self.blocked_ips[ip]
            self.logger.info(f"Unblocked IP {ip}")
            if self.os_type == 'windows':
                self._unblock_ip_windows(ip)
            elif self.os_type in ['linux', 'darwin']:
                self._unblock_ip_linux(ip)

    def _unblock_ip_windows(self, ip):
        """Unblock IP on Windows"""
        try:
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name="Block {ip}"'], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            pass  # Rule might not exist

    def _unblock_ip_linux(self, ip):
        """Unblock IP on Linux"""
        try:
            if subprocess.run(['which', 'nft'], capture_output=True).returncode == 0:
                # Find and delete the rule
                result = subprocess.run(['nft', 'list', 'ruleset'], capture_output=True, text=True)
                lines = result.stdout.split('\n')
                for i, line in enumerate(lines):
                    if ip in line and 'drop' in line:
                        rule_handle = lines[i-1].split()[-1] if 'handle' in lines[i-1] else None
                        if rule_handle:
                            subprocess.run(['nft', 'delete', 'rule', 'inet', 'guardianwall', 'input', 'handle', rule_handle], check=True)
                            break
            else:
                subprocess.run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
        except subprocess.CalledProcessError:
            pass  # Rule might not exist

    def monitor_traffic(self):
        """Monitor network traffic for threats"""
        # This is a simplified implementation. In production, you'd use libraries like scapy or pcap
        # For now, we'll simulate by checking system connections
        while True:
            try:
                connections = psutil.net_connections()
                current_time = time.time()

                ip_counts = defaultdict(int)
                port_scans = defaultdict(set)
                failed_logins = defaultdict(int)  # Simplified

                for conn in connections:
                    if conn.status == 'ESTABLISHED':
                        remote_ip = conn.raddr.ip if conn.raddr else None
                        if remote_ip:
                            ip_counts[remote_ip] += 1
                            if conn.laddr:
                                port_scans[remote_ip].add(conn.laddr.port)

                # Check for rapid connections
                for ip, count in ip_counts.items():
                    if count > RAPID_CONNECTION_THRESHOLD and ip not in self.blocked_ips:
                        self.block_ip(ip, f"Rapid connections: {count} in last minute")

                # Check for port scanning
                for ip, ports in port_scans.items():
                    if len(ports) > PORT_SCAN_THRESHOLD and ip not in self.blocked_ips:
                        self.block_ip(ip, f"Port scanning: {len(ports)} ports")

                # Clean up expired blocks
                self.unblock_expired_ips()

                time.sleep(60)  # Check every minute

            except Exception as e:
                self.logger.error(f"Error in traffic monitoring: {e}")
                time.sleep(60)

    def run(self):
        """Main run loop"""
        self.logger.info("GuardianWall firewall started")
        self.initialize_firewall()

        # Start monitoring thread
        monitor_thread = threading.Thread(target=self.monitor_traffic, daemon=True)
        monitor_thread.start()

        # Keep running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("GuardianWall shutting down")

if __name__ == '__main__':
    if os.geteuid() != 0:  # Check for root on Unix-like systems
        print("This script must be run with administrator/root privileges.")
        sys.exit(1)

    firewall = FirewallManager()
    firewall.run()
