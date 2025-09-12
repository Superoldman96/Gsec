from colorama import Fore
import requests
import ssl
import socket
import time
import os
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings()

class SSLScanner:
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        self.parsed_url = urlparse(self.target)
        self.hostname = self.parsed_url.netloc.split(':')[0]  # Remove port if present
        self.port = 443 if self.parsed_url.scheme == 'https' else 443
        self.findings = []

    def scan_ssl(self):
        """Main SSL scanning function"""
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}Scanning SSL/TLS configuration...{Fore.RESET}", end='', flush=True)

        try:
            # Basic SSL connection test
            self.check_ssl_connection()

            # Certificate validation
            self.check_certificate()

            # Protocol support
            self.check_protocol_support()

            # Cipher suites
            self.check_cipher_suites()

            print(f" {Fore.GREEN}Done{Fore.RESET}")

        except Exception as e:
            print(f" {Fore.RED}Error: {str(e)}{Fore.RESET}")

    def check_ssl_connection(self):
        """Test basic SSL connection"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((self.hostname, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        return True
        except Exception as e:
            self.findings.append({
                'type': 'SSL Connection Failed',
                'description': f'Cannot establish SSL connection: {str(e)}',
                'severity': 'High'
            })
            return False

    def check_certificate(self):
        """Check SSL certificate validity"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()

                    if cert:
                        # Check expiration
                        import datetime
                        not_after = ssl.cert_time_to_seconds(cert['notAfter'])
                        current_time = time.time()

                        if not_after < current_time:
                            self.findings.append({
                                'type': 'Expired SSL Certificate',
                                'description': 'SSL certificate has expired',
                                'severity': 'High'
                            })

                        # Check issuer
                        issuer = dict(x[0] for x in cert['issuer'])
                        if 'organizationName' not in issuer:
                            self.findings.append({
                                'type': 'Self-Signed Certificate',
                                'description': 'Certificate appears to be self-signed',
                                'severity': 'Medium'
                            })

        except Exception as e:
            pass

    def check_protocol_support(self):
        """Check supported SSL/TLS protocols"""
        try:
            # Test different protocols
            protocols = [
                (ssl.PROTOCOL_TLSv1_2, 'TLSv1.2'),
                (ssl.PROTOCOL_TLSv1_1, 'TLSv1.1'),
                (ssl.PROTOCOL_TLSv1, 'TLSv1.0')
            ]

            deprecated_protocols = []
            for protocol, name in protocols:
                try:
                    context = ssl.SSLContext(protocol)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE

                    with socket.create_connection((self.hostname, self.port)) as sock:
                        with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                            deprecated_protocols.append(name)
                except:
                    pass

            if deprecated_protocols:
                self.findings.append({
                    'type': 'Deprecated SSL/TLS Protocols',
                    'description': f'Supports deprecated protocols: {", ".join(deprecated_protocols)}',
                    'severity': 'Medium'
                })

        except Exception as e:
            pass

    def check_cipher_suites(self):
        """Check supported cipher suites"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((self.hostname, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        # Check for weak ciphers
                        weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL']
                        if any(weak in cipher_name.upper() for weak in weak_ciphers):
                            self.findings.append({
                                'type': 'Weak Cipher Suite',
                                'description': f'Using weak cipher: {cipher_name}',
                                'severity': 'Medium'
                            })

        except Exception as e:
            pass

    def generate_ssl_report(self):
        """Generate SSL report and save to file"""
        output_dir = os.path.join(os.path.dirname(__file__), '..', 'output')
        os.makedirs(output_dir, exist_ok=True)

        target_name = self.hostname.replace('.', '_')
        report_file = os.path.join(output_dir, f'ssl_scan_{target_name}.txt')

        with open(report_file, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("SSL/TLS SECURITY SCAN REPORT\n")
            f.write("=" * 60 + "\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Hostname: {self.hostname}\n")
            f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 60 + "\n\n")

            if not self.findings:
                f.write("✅ No critical SSL/TLS issues found!\n")
                print(f"{Fore.GREEN}[+] SSL report saved to: {report_file}{Fore.RESET}")
                return

            # Group findings by severity
            severity_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
            for finding in self.findings:
                severity_count[finding['severity']] += 1

            f.write("ISSUES FOUND:\n")
            f.write("-" * 30 + "\n")
            for severity, count in severity_count.items():
                if count > 0:
                    f.write(f"{severity}: {count} issues\n")

            f.write("\nDETAILED FINDINGS:\n")
            f.write("-" * 30 + "\n")
            for i, finding in enumerate(self.findings, 1):
                f.write(f"{i}. [{finding['severity']}] {finding['type']}\n")
                if 'description' in finding:
                    f.write(f"   Description: {finding['description']}\n")
                f.write("\n")

            # Add SSL recommendations
            f.write("\nRECOMMENDATIONS:\n")
            f.write("-" * 30 + "\n")
            if severity_count['High'] > 0 or severity_count['Critical'] > 0:
                f.write("🚨 HIGH PRIORITY:\n")
                f.write("- Renew expired SSL certificates immediately\n")
                f.write("- Fix SSL connection issues\n\n")

            if severity_count['Medium'] > 0:
                f.write("⚠️  MEDIUM PRIORITY:\n")
                f.write("- Disable deprecated SSL/TLS protocols (TLSv1.0, TLSv1.1)\n")
                f.write("- Replace weak cipher suites\n")
                f.write("- Use certificates from trusted CAs\n\n")

        print(f"{Fore.GREEN}[+] SSL report saved to: {report_file}{Fore.RESET}")
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}Found {len(self.findings)} SSL issues ({severity_count['High']} High, {severity_count['Medium']} Medium){Fore.RESET}")

def ssl_scan(target):
    """Main function to run SSL vulnerability scan"""
    scanner = SSLScanner(target)
    scanner.scan_ssl()
    scanner.generate_ssl_report()
    return scanner.findings
