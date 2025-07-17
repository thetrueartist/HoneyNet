#!/usr/bin/env python3

import socket
import threading
import time
import json
import logging
import argparse
import ssl
import os
import sys
import platform
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import urllib.parse
import base64
import hashlib
import re
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import tempfile
import ipaddress

class WindowsCompatibility:
    """Windows compatibility layer for HoneyNet"""
    
    @staticmethod
    def is_windows():
        return platform.system().lower() == 'windows'
    
    @staticmethod
    def is_admin():
        """Check if running with administrator privileges"""
        if WindowsCompatibility.is_windows():
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin()
            except:
                return False
        else:
            return os.geteuid() == 0
    
    @staticmethod
    def get_safe_ports():
        """Get Windows-safe port configuration"""
        if WindowsCompatibility.is_windows():
            return {
                'http': 8080,    # Avoid IIS conflicts
                'https': 8443,   # Avoid IIS conflicts
                'ftp': 2121,     # Same as Linux version
                'smtp': 2525,    # Avoid Windows mail service conflicts
                'dns': 5353      # Avoid Windows DNS service conflicts
            }
        else:
            return {
                'http': 80,
                'https': 443,
                'ftp': 2121,
                'smtp': 25,
                'dns': 53
            }
    
    @staticmethod
    def get_cert_dir():
        """Get appropriate certificate directory for OS"""
        if WindowsCompatibility.is_windows():
            return os.path.join(os.environ.get('APPDATA', '.'), 'HoneyNet', 'certs')
        else:
            return './certs'

class SSLCertificateManager:
    def __init__(self, cert_dir=None):
        self.cert_dir = cert_dir or WindowsCompatibility.get_cert_dir()
        self.lock = threading.Lock()
        if not os.path.exists(self.cert_dir):
            os.makedirs(self.cert_dir, exist_ok=True)
    
    def generate_certificate(self, hostname="localhost"):
        """Generate a self-signed certificate for the given hostname"""
        with self.lock:
            cert_path = os.path.join(self.cert_dir, f"{hostname}.crt")
            key_path = os.path.join(self.cert_dir, f"{hostname}.key")
            
            if os.path.exists(cert_path) and os.path.exists(key_path):
                return cert_path, key_path
            
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # Generate certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "HoneyNet"),
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.now(timezone.utc)
            ).not_valid_after(
                datetime.now(timezone.utc) + timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(hostname),
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256())
            
            # Write certificate
            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            # Write private key
            with open(key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            return cert_path, key_path

class RequestCache:
    def __init__(self):
        self.cache = {}
        self.lock = threading.Lock()
    
    def get(self, key):
        with self.lock:
            return self.cache.get(key)
    
    def set(self, key, value):
        with self.lock:
            self.cache[key] = value
    
    def clear(self):
        with self.lock:
            self.cache.clear()

class Logger:
    def __init__(self, log_file="honeynet_windows.log"):
        self.log_file = log_file
        self.lock = threading.Lock()
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def log_request(self, protocol, client_addr, request_data, response_data=None):
        timestamp = datetime.now().isoformat()
        log_entry = {
            'timestamp': timestamp,
            'protocol': protocol,
            'client_addr': client_addr,
            'request': request_data,
            'response': response_data
        }
        
        with self.lock:
            self.logger.info(f"[{protocol}] {client_addr} - {request_data}")
            
            # Save detailed log to JSON
            try:
                log_filename = f"honeynet_detailed_{timestamp[:10]}.json"
                with open(log_filename, "a", encoding='utf-8') as f:
                    f.write(json.dumps(log_entry) + "\n")
            except Exception as e:
                self.logger.error(f"Failed to write detailed log: {e}")

class DNSServer:
    def __init__(self, host="0.0.0.0", port=None, logger=None):
        self.host = host
        self.port = port or WindowsCompatibility.get_safe_ports()['dns']
        self.logger = logger or Logger()
        self.socket = None
        self.running = False
        
    def start(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.running = True
            
            self.logger.logger.info(f"DNS Server started on {self.host}:{self.port}")
            
            while self.running:
                try:
                    data, addr = self.socket.recvfrom(1024)
                    threading.Thread(target=self.handle_dns_request, args=(data, addr)).start()
                except socket.error:
                    if self.running:
                        self.logger.logger.error("DNS socket error")
                        break
        except Exception as e:
            self.logger.logger.error(f"DNS Server failed to start: {e}")
    
    def handle_dns_request(self, data, addr):
        try:
            if len(data) < 12:
                return
            
            # Extract domain from DNS query
            domain = self.extract_domain(data)
            self.logger.log_request("DNS", addr, f"Query: {domain}")
            
            # Build response
            response = self.build_dns_response(data, domain)
            self.socket.sendto(response, addr)
            
        except Exception as e:
            self.logger.logger.error(f"DNS request handling error: {e}")
    
    def extract_domain(self, data):
        try:
            # Skip header (12 bytes)
            pos = 12
            domain_parts = []
            
            while pos < len(data):
                length = data[pos]
                if length == 0:
                    break
                pos += 1
                if pos + length > len(data):
                    break
                domain_parts.append(data[pos:pos+length].decode('utf-8'))
                pos += length
            
            return '.'.join(domain_parts) if domain_parts else "unknown"
        except:
            return "unknown"
    
    def build_dns_response(self, request, domain):
        # Basic DNS response header
        response = bytearray(request[:2])  # Transaction ID
        response.extend(b'\x81\x80')  # Flags
        response.extend(b'\x00\x01')  # Questions
        response.extend(b'\x00\x01')  # Answer RRs
        response.extend(b'\x00\x00')  # Authority RRs
        response.extend(b'\x00\x00')  # Additional RRs
        
        # Copy question section
        response.extend(request[12:])
        
        # Add answer section
        response.extend(b'\xc0\x0c')  # Name pointer
        response.extend(b'\x00\x01')  # Type A
        response.extend(b'\x00\x01')  # Class IN
        response.extend(b'\x00\x00\x00\x3c')  # TTL
        response.extend(b'\x00\x04')  # Data length
        response.extend(b'\x7f\x00\x00\x01')  # IP: 127.0.0.1
        
        return bytes(response)
    
    def stop(self):
        self.running = False
        if self.socket:
            self.socket.close()

class HTTPRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        self.logger = server.logger
        self.cache = server.cache
        super().__init__(request, client_address, server)
    
    def log_message(self, format, *args):
        # Override to use our custom logger
        pass
    
    def do_GET(self):
        self.handle_request("GET")
    
    def do_POST(self):
        self.handle_request("POST")
    
    def do_HEAD(self):
        self.handle_request("HEAD")
    
    def handle_request(self, method):
        try:
            # Log request
            headers = dict(self.headers)
            request_info = f"{method} {self.path}"
            self.logger.log_request("HTTP", self.client_address, request_info, headers)
            
            # Check cache
            cache_key = f"{method}:{self.path}"
            cached_response = self.cache.get(cache_key)
            
            if cached_response:
                self.send_cached_response(cached_response)
                return
            
            # Generate dynamic response
            response_data = self.generate_response()
            
            # Cache response
            self.cache.set(cache_key, response_data)
            
            # Send response
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(response_data)))
            platform_name = "Windows" if WindowsCompatibility.is_windows() else "Unix"
            self.send_header('Server', f'HoneyNet/2.0 ({platform_name})')
            self.end_headers()
            
            if method != "HEAD":
                self.wfile.write(response_data.encode('utf-8'))
                
        except Exception as e:
            self.logger.logger.error(f"HTTP request handling error: {e}")
            self.send_error(500, "Internal Server Error")
    
    def generate_response(self):
        # Generate realistic responses based on path
        if self.path.endswith('.js'):
            return "console.log('HoneyNet JavaScript loaded');"
        elif self.path.endswith('.css'):
            return "body { font-family: Arial, sans-serif; background: #f0f0f0; }"
        elif self.path.endswith('.png') or self.path.endswith('.jpg'):
            return "Fake image data"
        elif 'api' in self.path:
            return '{"status": "success", "data": "honeypot_response", "platform": "windows"}'
        else:
            return f"""
            <html>
            <head><title>HoneyNet Windows Response</title></head>
            <body>
                <h1>🍯 Connection Successful</h1>
                <p>Path: {self.path}</p>
                <p>Timestamp: {datetime.now().isoformat()}</p>
                <p>Platform: {platform.system()}</p>
                <p>Your request was processed by HoneyNet ({platform.system()})</p>
            </body>
            </html>
            """
    
    def send_cached_response(self, response_data):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(response_data)))
        platform_name = "Windows" if WindowsCompatibility.is_windows() else "Unix"
        self.send_header('Server', f'HoneyNet/2.0 ({platform_name}) (cached)')
        self.end_headers()
        self.wfile.write(response_data.encode('utf-8'))

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    def __init__(self, server_address, RequestHandlerClass, logger, cache):
        self.logger = logger
        self.cache = cache
        super().__init__(server_address, RequestHandlerClass)

class SSLHTTPServer(ThreadedHTTPServer):
    def __init__(self, server_address, RequestHandlerClass, logger, cache, cert_manager):
        self.cert_manager = cert_manager
        super().__init__(server_address, RequestHandlerClass, logger, cache)
        
        # Generate certificate for this server
        cert_path, key_path = self.cert_manager.generate_certificate()
        
        # Create SSL context
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ssl_context.load_cert_chain(cert_path, key_path)
        
        # Wrap socket with SSL
        self.socket = self.ssl_context.wrap_socket(self.socket, server_side=True)
        
        logger.logger.info(f"SSL/TLS enabled with certificate: {cert_path}")

class HTTPSRequestHandler(HTTPRequestHandler):
    def handle_request(self, method):
        try:
            # Log HTTPS request with SSL info
            headers = dict(self.headers)
            ssl_info = getattr(self.connection, 'cipher', lambda: ('Unknown', 'Unknown', 'Unknown'))()
            request_info = f"{method} {self.path} (SSL: {ssl_info[0]})"
            self.logger.log_request("HTTPS", self.client_address, request_info, headers)
            
            # Check cache
            cache_key = f"HTTPS:{method}:{self.path}"
            cached_response = self.cache.get(cache_key)
            
            if cached_response:
                self.send_cached_response(cached_response)
                return
            
            # Generate dynamic response
            response_data = self.generate_response()
            
            # Cache response
            self.cache.set(cache_key, response_data)
            
            # Send response
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(response_data)))
            platform_name = "Windows" if WindowsCompatibility.is_windows() else "Unix"
            self.send_header('Server', f'HoneyNet/2.0 ({platform_name} SSL)')
            self.send_header('Strict-Transport-Security', 'max-age=31536000')
            self.end_headers()
            
            if method != "HEAD":
                self.wfile.write(response_data.encode('utf-8'))
                
        except Exception as e:
            self.logger.logger.error(f"HTTPS request handling error: {e}")
            self.send_error(500, "Internal Server Error")
    
    def generate_response(self):
        # Generate realistic HTTPS responses
        if self.path.endswith('.js'):
            return "console.log('Secure JavaScript loaded via HTTPS on Windows');"
        elif self.path.endswith('.css'):
            return "body { font-family: Arial, sans-serif; background: #f0f0f0; }"
        elif self.path.endswith('.png') or self.path.endswith('.jpg'):
            return "Secure fake image data"
        elif 'api' in self.path:
            return '{"status": "success", "data": "secure_api_response", "ssl": true, "platform": "windows"}'
        else:
            return f"""
            <html>
            <head><title>Secure HoneyNet Response (Windows)</title></head>
            <body>
                <h1>🔒 Secure Connection Established</h1>
                <p>Path: {self.path}</p>
                <p>Timestamp: {datetime.now().isoformat()}</p>
                <p>Platform: {platform.system()}</p>
                <p>Your HTTPS request was processed by HoneyNet ({platform.system()})</p>
                <p>SSL/TLS encryption is active</p>
            </body>
            </html>
            """

class FTPServer:
    def __init__(self, host="0.0.0.0", port=None, logger=None):
        self.host = host
        self.port = port or WindowsCompatibility.get_safe_ports()['ftp']
        self.logger = logger or Logger()
        self.socket = None
        self.running = False
        
    def start(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            self.running = True
            
            self.logger.logger.info(f"FTP Server started on {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, addr = self.socket.accept()
                    threading.Thread(target=self.handle_ftp_client, args=(client_socket, addr)).start()
                except socket.error:
                    if self.running:
                        self.logger.logger.error("FTP socket error")
                        break
        except Exception as e:
            self.logger.logger.error(f"FTP Server failed to start: {e}")
    
    def handle_ftp_client(self, client_socket, addr):
        try:
            # Send welcome message
            platform_name = "Windows" if WindowsCompatibility.is_windows() else "Unix"
            client_socket.send(f"220 HoneyNet FTP Server Ready ({platform_name})\r\n".encode())
            
            while True:
                try:
                    data = client_socket.recv(1024)
                    if not data:
                        break
                    
                    command = data.decode('utf-8', errors='ignore').strip()
                    self.logger.log_request("FTP", addr, command)
                    
                    # Handle basic FTP commands
                    if command.upper().startswith("USER"):
                        client_socket.send(b"331 User name okay, need password\r\n")
                    elif command.upper().startswith("PASS"):
                        client_socket.send(b"230 User logged in, proceed\r\n")
                    elif command.upper().startswith("QUIT"):
                        client_socket.send(b"221 Goodbye\r\n")
                        break
                    elif command.upper().startswith("PWD"):
                        client_socket.send(b"257 \"/\" is current directory\r\n")
                    elif command.upper().startswith("CWD"):
                        client_socket.send(b"250 Directory successfully changed\r\n")
                    elif command.upper().startswith("LIST"):
                        client_socket.send(b"150 Here comes the directory listing\r\n")
                        client_socket.send(b"226 Directory send OK\r\n")
                    else:
                        client_socket.send(b"502 Command not implemented\r\n")
                        
                except socket.error:
                    break
        except Exception as e:
            self.logger.logger.error(f"FTP client handling error: {e}")
        finally:
            client_socket.close()
    
    def stop(self):
        self.running = False
        if self.socket:
            self.socket.close()

class SMTPServer:
    def __init__(self, host="0.0.0.0", port=None, logger=None):
        self.host = host
        self.port = port or WindowsCompatibility.get_safe_ports()['smtp']
        self.logger = logger or Logger()
        self.socket = None
        self.running = False
        
    def start(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            self.running = True
            
            self.logger.logger.info(f"SMTP Server started on {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, addr = self.socket.accept()
                    threading.Thread(target=self.handle_smtp_client, args=(client_socket, addr)).start()
                except socket.error:
                    if self.running:
                        self.logger.logger.error("SMTP socket error")
                        break
        except Exception as e:
            self.logger.logger.error(f"SMTP Server failed to start: {e}")
    
    def handle_smtp_client(self, client_socket, addr):
        try:
            platform_name = "Windows" if WindowsCompatibility.is_windows() else "Unix"
            client_socket.send(f"220 HoneyNet SMTP Server Ready ({platform_name})\r\n".encode())
            
            while True:
                try:
                    data = client_socket.recv(1024)
                    if not data:
                        break
                    
                    command = data.decode('utf-8', errors='ignore').strip()
                    self.logger.log_request("SMTP", addr, command)
                    
                    if command.upper().startswith("HELO") or command.upper().startswith("EHLO"):
                        client_socket.send(b"250 Hello\r\n")
                    elif command.upper().startswith("MAIL FROM"):
                        client_socket.send(b"250 OK\r\n")
                    elif command.upper().startswith("RCPT TO"):
                        client_socket.send(b"250 OK\r\n")
                    elif command.upper().startswith("DATA"):
                        client_socket.send(b"354 Start mail input\r\n")
                    elif command.upper().startswith("QUIT"):
                        client_socket.send(b"221 Goodbye\r\n")
                        break
                    elif command == ".":
                        client_socket.send(b"250 OK\r\n")
                    else:
                        client_socket.send(b"250 OK\r\n")
                        
                except socket.error:
                    break
        except Exception as e:
            self.logger.logger.error(f"SMTP client handling error: {e}")
        finally:
            client_socket.close()
    
    def stop(self):
        self.running = False
        if self.socket:
            self.socket.close()

class HoneyNetWindows:
    def __init__(self, config=None):
        self.config = config or {}
        self.logger = Logger("honeynet_windows.log")
        self.cache = RequestCache()
        self.cert_manager = SSLCertificateManager()
        self.servers = []
        self.running = False
        self.ports = WindowsCompatibility.get_safe_ports()
        
    def start(self):
        platform_name = "Windows" if WindowsCompatibility.is_windows() else "Unix/Linux"
        self.logger.logger.info(f"Starting HoneyNet ({platform_name} Edition)...")
        
        # Display port information
        port_type = "Windows-safe" if WindowsCompatibility.is_windows() else "standard"
        self.logger.logger.info(f"Using {port_type} ports: {self.ports}")
        
        if not WindowsCompatibility.is_admin():
            privilege_type = "administrator" if WindowsCompatibility.is_windows() else "root"
            self.logger.logger.warning(f"Not running as {privilege_type}. Some features may be limited.")
        
        self.running = True
        
        # Start DNS server
        dns_server = DNSServer(logger=self.logger)
        dns_thread = threading.Thread(target=dns_server.start)
        dns_thread.daemon = True
        dns_thread.start()
        self.servers.append(dns_server)
        
        # Start HTTP server
        http_server = ThreadedHTTPServer(('0.0.0.0', self.ports['http']), HTTPRequestHandler, self.logger, self.cache)
        http_thread = threading.Thread(target=http_server.serve_forever)
        http_thread.daemon = True
        http_thread.start()
        self.servers.append(http_server)
        
        # Start HTTPS server with SSL/TLS
        try:
            https_server = SSLHTTPServer(('0.0.0.0', self.ports['https']), HTTPSRequestHandler, self.logger, self.cache, self.cert_manager)
            https_thread = threading.Thread(target=https_server.serve_forever)
            https_thread.daemon = True
            https_thread.start()
            self.servers.append(https_server)
            self.logger.logger.info("HTTPS server started with SSL/TLS interception")
        except Exception as e:
            self.logger.logger.error(f"Failed to start HTTPS server: {e}")
        
        # Start FTP server
        ftp_server = FTPServer(logger=self.logger)
        ftp_thread = threading.Thread(target=ftp_server.start)
        ftp_thread.daemon = True
        ftp_thread.start()
        self.servers.append(ftp_server)
        
        # Start SMTP server
        smtp_server = SMTPServer(logger=self.logger)
        smtp_thread = threading.Thread(target=smtp_server.start)
        smtp_thread.daemon = True
        smtp_thread.start()
        self.servers.append(smtp_server)
        
        platform_name = "Windows" if WindowsCompatibility.is_windows() else "Unix/Linux"
        self.logger.logger.info(f"All HoneyNet servers started successfully ({platform_name} Edition)")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        platform_name = "Windows" if WindowsCompatibility.is_windows() else "Unix/Linux"
        self.logger.logger.info(f"Stopping HoneyNet ({platform_name} Edition)...")
        self.running = False
        
        for server in self.servers:
            if hasattr(server, 'stop'):
                server.stop()

def main():
    parser = argparse.ArgumentParser(description='HoneyNet - Cross-Platform Edition')
    parser.add_argument('--config', help='Configuration file path')
    args = parser.parse_args()
    
    platform_name = "Windows" if WindowsCompatibility.is_windows() else "Unix/Linux"
    print(f"HoneyNet Cross-Platform Edition")
    print("=" * 50)
    
    if WindowsCompatibility.is_windows():
        print("Platform: Windows")
        if not WindowsCompatibility.is_admin():
            print("WARNING: Not running as administrator. Some features may be limited.")
            print("Consider running as administrator for full functionality.")
    else:
        print("Platform: Unix/Linux")
        if os.geteuid() != 0:
            print("WARNING: Not running with root privileges. Some features may not work correctly.")
            print("Consider running with sudo for full functionality.")
    
    ports = WindowsCompatibility.get_safe_ports()
    port_type = "Windows-safe" if WindowsCompatibility.is_windows() else "standard"
    print(f"Using {port_type} ports: HTTP={ports['http']}, HTTPS={ports['https']}, FTP={ports['ftp']}, SMTP={ports['smtp']}, DNS={ports['dns']}")
    print()
    
    honeynet = HoneyNetWindows()
    
    try:
        honeynet.start()
    except KeyboardInterrupt:
        print("\nShutting down...")
        honeynet.stop()

if __name__ == "__main__":
    main()
