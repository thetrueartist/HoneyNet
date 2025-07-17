#!/usr/bin/env python3

import socket
import threading
import time
import random
import argparse
import json
import platform
import requests
import smtplib
from ftplib import FTP
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import subprocess
import os
import sys
from datetime import datetime

class WindowsCompatibility:
    """Windows compatibility layer for traffic generator"""
    
    @staticmethod
    def is_windows():
        return platform.system().lower() == 'windows'
    
    @staticmethod
    def get_safe_ports():
        """Get Windows-safe port configuration"""
        if WindowsCompatibility.is_windows():
            return {
                'http': 8080,
                'https': 8443,
                'ftp': 2121,
                'smtp': 2525,
                'dns': 5353
            }
        else:
            return {
                'http': 80,
                'https': 443,
                'ftp': 2121,
                'smtp': 25,
                'dns': 53
            }

class TrafficGeneratorWindows:
    def __init__(self, target_host="127.0.0.1", duration=300, threads=10):
        self.target_host = target_host
        self.duration = duration
        self.threads = threads
        self.running = False
        self.stats = {
            'http_requests': 0,
            'https_requests': 0,
            'ftp_connections': 0,
            'smtp_connections': 0,
            'dns_queries': 0,
            'tcp_connections': 0,
            'udp_packets': 0,
            'errors': 0
        }
        self.stats_lock = threading.Lock()
        self.ports = WindowsCompatibility.get_safe_ports()
        
        # Common malware domains and URLs
        self.malware_domains = [
            'malware-command.com',
            'evil-c2.net',
            'botnet-control.org',
            'fake-update.com',
            'suspicious-download.net',
            'phishing-site.com',
            'trojan-host.org',
            'ransomware-payment.com',
            'data-exfil.net',
            'backdoor-access.com'
        ]
        
        # Malware-like URLs
        self.malware_urls = [
            '/api/checkin',
            '/api/register',
            '/api/upload',
            '/api/download',
            '/api/command',
            '/panel/index.php',
            '/admin/login',
            '/gate.php',
            '/update.bin',
            '/config.json',
            '/screenshot.jpg',
            '/keylog.txt',
            '/stolen_data.zip',
            '/bitcoin_wallet.json',
            '/ransom_note.txt',
            '/download/payload.exe'
        ]
        
        # Check available libraries
        self.libraries = {
            'requests': self._check_requests(),
            'email': self._check_email(),
            'ftp': self._check_ftp()
        }
        
    def _check_requests(self):
        try:
            import requests
            return True
        except ImportError:
            return False
    
    def _check_email(self):
        try:
            import smtplib
            from email.mime.text import MIMEText
            return True
        except ImportError:
            return False
    
    def _check_ftp(self):
        try:
            from ftplib import FTP
            return True
        except ImportError:
            return False
    
    def update_stats(self, key):
        with self.stats_lock:
            self.stats[key] += 1
    
    def generate_http_traffic(self):
        """Generate HTTP traffic"""
        if not self.libraries['requests']:
            return
            
        while self.running:
            try:
                url = random.choice(self.malware_urls)
                method = random.choice(['GET', 'POST'])
                
                if method == 'GET':
                    response = requests.get(
                        f"http://{self.target_host}:{self.ports['http']}{url}",
                        timeout=5,
                        verify=False
                    )
                else:
                    response = requests.post(
                        f"http://{self.target_host}:{self.ports['http']}{url}",
                        data={'data': 'malware_payload'},
                        timeout=5,
                        verify=False
                    )
                
                print(f"[HTTP] {response.status_code} http://{self.target_host}:{self.ports['http']}{url}")
                self.update_stats('http_requests')
                
                time.sleep(random.uniform(1, 5))
                
            except Exception as e:
                self.update_stats('errors')
                time.sleep(2)
    
    def generate_https_traffic(self):
        """Generate HTTPS traffic"""
        if not self.libraries['requests']:
            return
            
        while self.running:
            try:
                url = random.choice(self.malware_urls)
                method = random.choice(['GET', 'POST'])
                
                if method == 'GET':
                    response = requests.get(
                        f"https://{self.target_host}:{self.ports['https']}{url}",
                        timeout=5,
                        verify=False
                    )
                else:
                    response = requests.post(
                        f"https://{self.target_host}:{self.ports['https']}{url}",
                        data={'data': 'malware_payload'},
                        timeout=5,
                        verify=False
                    )
                
                print(f"[HTTPS] {response.status_code} https://{self.target_host}:{self.ports['https']}{url}")
                self.update_stats('https_requests')
                
                time.sleep(random.uniform(1, 5))
                
            except Exception as e:
                self.update_stats('errors')
                time.sleep(2)
    
    def generate_ftp_traffic(self):
        """Generate FTP traffic"""
        if not self.libraries['ftp']:
            return
            
        while self.running:
            try:
                ftp = FTP()
                ftp.connect(self.target_host, self.ports['ftp'])
                ftp.login('anonymous', 'malware@evil.com')
                
                # Random FTP commands
                commands = ['pwd', 'cwd /uploads', 'type A']
                command = random.choice(commands)
                
                if command == 'pwd':
                    ftp.pwd()
                elif command.startswith('cwd'):
                    try:
                        ftp.cwd('/uploads')
                    except:
                        pass
                elif command == 'type A':
                    ftp.sendcmd('TYPE A')
                
                ftp.quit()
                
                print(f"[FTP] Connected to port {self.ports['ftp']} and performed {command}")
                self.update_stats('ftp_connections')
                
                time.sleep(random.uniform(2, 8))
                
            except Exception as e:
                self.update_stats('errors')
                time.sleep(3)
    
    def generate_smtp_traffic(self):
        """Generate SMTP traffic"""
        if not self.libraries['email']:
            return
            
        while self.running:
            try:
                msg = MIMEMultipart()
                msg['From'] = 'noreply@malware-bot.com'
                msg['To'] = 'victim@target.com'
                msg['Subject'] = random.choice([
                    'Important security update required',
                    'Your package is ready for delivery',
                    'Urgent: Your account has been compromised',
                    'Action required: Verify your identity',
                    'Congratulations! You have won $1,000,000'
                ])
                
                body = "This is a fake phishing email generated for testing purposes."
                msg.attach(MIMEText(body, 'plain'))
                
                server = smtplib.SMTP(self.target_host, self.ports['smtp'])
                server.helo('malware-bot.local')
                server.sendmail('noreply@malware-bot.com', 'victim@target.com', msg.as_string())
                server.quit()
                
                print(f"[SMTP] Email sent successfully to port {self.ports['smtp']}")
                self.update_stats('smtp_connections')
                
                time.sleep(random.uniform(5, 15))
                
            except Exception as e:
                self.update_stats('errors')
                time.sleep(3)
    
    def generate_dns_traffic(self):
        """Generate DNS traffic"""
        while self.running:
            try:
                domain = random.choice(self.malware_domains)
                
                # Create DNS query
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                
                # Build simple DNS query
                query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                for part in domain.split('.'):
                    query += bytes([len(part)]) + part.encode()
                query += b'\x00\x00\x01\x00\x01'
                
                sock.sendto(query, (self.target_host, self.ports['dns']))
                
                try:
                    response = sock.recv(1024)
                    print(f"[DNS] Queried {domain} on port {self.ports['dns']}")
                    self.update_stats('dns_queries')
                except socket.timeout:
                    pass
                
                sock.close()
                time.sleep(random.uniform(0.5, 3))
                
            except Exception as e:
                self.update_stats('errors')
                time.sleep(2)
    
    def generate_tcp_traffic(self):
        """Generate TCP traffic"""
        while self.running:
            try:
                port = random.choice([self.ports['ftp'], self.ports['http'], self.ports['https']])
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((self.target_host, port))
                
                print(f"[TCP] Connected to port {port}")
                self.update_stats('tcp_connections')
                
                sock.close()
                time.sleep(random.uniform(1, 4))
                
            except Exception as e:
                self.update_stats('errors')
                time.sleep(2)
    
    def generate_udp_traffic(self):
        """Generate UDP traffic"""
        while self.running:
            try:
                port = random.choice([self.ports['dns'], 123, 161, 514, 1194, 4500, 5060, 5353])
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(1)
                
                # Send random UDP data
                data = os.urandom(random.randint(10, 100))
                sock.sendto(data, (self.target_host, port))
                
                print(f"[UDP] Sent packet to port {port}")
                self.update_stats('udp_packets')
                
                sock.close()
                time.sleep(random.uniform(2, 6))
                
            except Exception as e:
                self.update_stats('errors')
                time.sleep(2)
    
    def print_stats(self):
        """Print traffic statistics"""
        platform_name = "Windows" if WindowsCompatibility.is_windows() else "Unix/Linux"
        
        print(f"\n--- Traffic Statistics ({platform_name}) ---")
        with self.stats_lock:
            for key, value in self.stats.items():
                print(f"{key.replace('_', ' ').title()}: {value}")
        print("--- End Statistics ---\n")
    
    def run(self):
        """Start traffic generation"""
        print(f"Platform: {platform.system()} {platform.release()}")
        print(f"Starting traffic generation on {platform.system()} {platform.release()}")
        print(f"Target: {self.target_host}, Duration: {self.duration}s, Threads: {self.threads}")
        print(f"Using ports: HTTP={self.ports['http']}, HTTPS={self.ports['https']}, FTP={self.ports['ftp']}, SMTP={self.ports['smtp']}, DNS={self.ports['dns']}")
        print(f"Available libraries: requests={self.libraries['requests']}, email={self.libraries['email']}, ftp={self.libraries['ftp']}")
        
        self.running = True
        threads = []
        
        # Start traffic generation threads
        generators = [
            self.generate_http_traffic,
            self.generate_https_traffic,
            self.generate_ftp_traffic,
            self.generate_smtp_traffic,
            self.generate_dns_traffic,
            self.generate_tcp_traffic,
            self.generate_udp_traffic
        ]
        
        for i in range(self.threads):
            generator = generators[i % len(generators)]
            thread = threading.Thread(target=generator)
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Stats thread
        stats_thread = threading.Thread(target=self.stats_printer)
        stats_thread.daemon = True
        stats_thread.start()
        
        try:
            time.sleep(self.duration)
        except KeyboardInterrupt:
            print("\nStopping traffic generation...")
        
        self.running = False
        print("\n--- Final Statistics ---")
        with self.stats_lock:
            for key, value in self.stats.items():
                print(f"{key.replace('_', ' ').title()}: {value}")
    
    def stats_printer(self):
        """Print periodic statistics"""
        while self.running:
            time.sleep(30)  # Print stats every 30 seconds
            if self.running:
                self.print_stats()

def main():
    parser = argparse.ArgumentParser(description='HoneyNet Traffic Generator - Windows Edition')
    parser.add_argument('--host', '-H', default='127.0.0.1', help='Target host')
    parser.add_argument('--duration', '-d', type=int, default=300, help='Duration in seconds')
    parser.add_argument('--threads', '-t', type=int, default=10, help='Number of threads')
    
    args = parser.parse_args()
    
    # Disable SSL warnings for self-signed certificates
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    generator = TrafficGeneratorWindows(
        target_host=args.host,
        duration=args.duration,
        threads=args.threads
    )
    
    try:
        generator.run()
    except KeyboardInterrupt:
        print("\nStopped by user")

if __name__ == "__main__":
    main()
