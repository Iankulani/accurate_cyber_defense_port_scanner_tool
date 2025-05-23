#!/usr/bin/env python3
"""
Accurate Cyber Defense Advanced Cybersecurity Port Scanner Tool
========================================
A comprehensive port scanning utility for network security assessment.
This tool provides various scanning techniques and detailed reporting capabilities.

Author: Ian Carter Kulani
Version: 2.1.0
License: Non

"""

import socket
import threading
import time
import sys
import argparse
import json
import csv
import xml.etree.ElementTree as ET
from datetime import datetime
import ipaddress
import subprocess
import platform
import os
import random
import signal
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from dataclasses import dataclass, asdict
from typing import List, Dict, Tuple, Optional
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('port_scanner.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class ScanResult:
    """Data class to store scan results"""
    ip: str
    port: int
    status: str
    service: str
    banner: str
    response_time: float
    timestamp: str

@dataclass
class ScanConfiguration:
    """Data class to store scan configuration"""
    target_ips: List[str]
    port_range: Tuple[int, int]
    scan_type: str
    timeout: float
    threads: int
    delay: float
    verbose: bool
    output_format: str
    output_file: str

class PortScannerException(Exception):
    """Custom exception for port scanner errors"""
    pass

class NetworkUtils:
    """Utility class for network operations"""
    
    @staticmethod
    def validate_ip(ip_address: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_ip_range(ip_range: str) -> List[str]:
        """Validate and expand IP range"""
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            # Try to handle dash-separated ranges like 192.168.1.1-192.168.1.10
            if '-' in ip_range:
                start_ip, end_ip = ip_range.split('-')
                start = ipaddress.ip_address(start_ip.strip())
                end = ipaddress.ip_address(end_ip.strip())
                
                if start.version != end.version:
                    raise PortScannerException("IP version mismatch in range")
                
                ips = []
                current = start
                while current <= end:
                    ips.append(str(current))
                    current += 1
                return ips
            else:
                raise PortScannerException(f"Invalid IP range format: {ip_range}")
    
    @staticmethod
    def resolve_hostname(hostname: str) -> str:
        """Resolve hostname to IP address"""
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            raise PortScannerException(f"Cannot resolve hostname: {hostname}")
    
    @staticmethod
    def reverse_dns_lookup(ip: str) -> str:
        """Perform reverse DNS lookup"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return "Unknown"
    
    @staticmethod
    def ping_host(ip: str, timeout: int = 3) -> bool:
        """Ping host to check if it's alive"""
        try:
            if platform.system().lower() == "windows":
                cmd = f"ping -n 1 -w {timeout * 1000} {ip}"
            else:
                cmd = f"ping -c 1 -W {timeout} {ip}"
            
            result = subprocess.run(
                cmd.split(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout + 1
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            return False

class ServiceDetection:
    """Class for service detection and banner grabbing"""
    
    # Common service ports and their default services
    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 111: "RPC", 135: "RPC", 139: "NetBIOS",
        143: "IMAP", 443: "HTTPS", 993: "IMAPS", 995: "POP3S", 1723: "PPTP",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
        6379: "Redis", 27017: "MongoDB", 1433: "MSSQL", 1521: "Oracle"
    }
    
    @staticmethod
    def get_service_name(port: int) -> str:
        """Get service name for a given port"""
        return ServiceDetection.COMMON_PORTS.get(port, "Unknown")
    
    @staticmethod
    def grab_banner(ip: str, port: int, timeout: float = 3.0) -> str:
        """Attempt to grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            # Send HTTP request for web servers
            if port in [80, 443, 8080, 8443]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            elif port == 25:  # SMTP
                pass  # SMTP servers usually send banner immediately
            elif port == 21:  # FTP
                pass  # FTP servers usually send banner immediately
            elif port == 22:  # SSH
                pass  # SSH servers send banner immediately
            else:
                # Generic probe
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:200] if banner else "No banner"
            
        except Exception:
            return "No banner"

class PortScanner:
    """Main port scanner class"""
    
    def __init__(self, config: ScanConfiguration):
        self.config = config
        self.results: List[ScanResult] = []
        self.scan_start_time = None
        self.scan_end_time = None
        self.total_ports_scanned = 0
        self.open_ports_found = 0
        self.stop_scanning = False
        
        # Set up signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle interrupt signals"""
        logger.info("Scan interrupted by user. Generating report...")
        self.stop_scanning = True
    
    def tcp_connect_scan(self, ip: str, port: int) -> ScanResult:
        """Perform TCP connect scan"""
        start_time = time.time()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            result = sock.connect_ex((ip, port))
            response_time = time.time() - start_time
            
            if result == 0:
                status = "Open"
                service = ServiceDetection.get_service_name(port)
                banner = ServiceDetection.grab_banner(ip, port, self.config.timeout)
                self.open_ports_found += 1
            else:
                status = "Closed"
                service = "N/A"
                banner = "N/A"
            
            sock.close()
            
        except socket.timeout:
            status = "Filtered"
            service = "N/A"
            banner = "N/A"
            response_time = self.config.timeout
        except Exception as e:
            status = "Error"
            service = "N/A"
            banner = f"Error: {str(e)}"
            response_time = time.time() - start_time
        
        return ScanResult(
            ip=ip,
            port=port,
            status=status,
            service=service,
            banner=banner,
            response_time=response_time,
            timestamp=datetime.now().isoformat()
        )
    
    def syn_scan(self, ip: str, port: int) -> ScanResult:
        """Perform SYN scan (requires root privileges)"""
        # Note: This is a simplified implementation
        # Real SYN scanning requires raw sockets and root privileges
        logger.warning("SYN scan requires root privileges and raw socket support")
        return self.tcp_connect_scan(ip, port)  # Fallback to connect scan
    
    def udp_scan(self, ip: str, port: int) -> ScanResult:
        """Perform UDP scan"""
        start_time = time.time()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.config.timeout)
            
            # Send UDP packet
            sock.sendto(b"UDP_PROBE", (ip, port))
            
            try:
                data, addr = sock.recvfrom(1024)
                status = "Open"
                banner = data.decode('utf-8', errors='ignore')[:200]
            except socket.timeout:
                # UDP is connectionless, timeout might mean open or filtered
                status = "Open|Filtered"
                banner = "No response"
            
            response_time = time.time() - start_time
            service = ServiceDetection.get_service_name(port)
            sock.close()
            
        except Exception as e:
            status = "Error"
            service = "N/A"
            banner = f"Error: {str(e)}"
            response_time = time.time() - start_time
        
        return ScanResult(
            ip=ip,
            port=port,
            status=status,
            service=service,
            banner=banner,
            response_time=response_time,
            timestamp=datetime.now().isoformat()
        )
    
    def stealth_scan(self, ip: str, port: int) -> ScanResult:
        """Perform stealth scan with random delays"""
        # Add random delay for stealth
        time.sleep(random.uniform(0.1, 0.5))
        return self.tcp_connect_scan(ip, port)
    
    def scan_port(self, ip: str, port: int) -> ScanResult:
        """Scan a single port based on scan type"""
        self.total_ports_scanned += 1
        
        if self.config.delay > 0:
            time.sleep(self.config.delay)
        
        if self.config.scan_type.lower() == "tcp":
            return self.tcp_connect_scan(ip, port)
        elif self.config.scan_type.lower() == "udp":
            return self.udp_scan(ip, port)
        elif self.config.scan_type.lower() == "syn":
            return self.syn_scan(ip, port)
        elif self.config.scan_type.lower() == "stealth":
            return self.stealth_scan(ip, port)
        else:
            return self.tcp_connect_scan(ip, port)  # Default to TCP
    
    def scan_host(self, ip: str) -> List[ScanResult]:
        """Scan all ports on a single host"""
        logger.info(f"Scanning host: {ip}")
        host_results = []
        
        # Check if host is alive
        if not NetworkUtils.ping_host(ip):
            logger.warning(f"Host {ip} appears to be down or not responding to ping")
        
        start_port, end_port = self.config.port_range
        ports_to_scan = list(range(start_port, end_port + 1))
        
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            # Submit all port scan tasks
            future_to_port = {
                executor.submit(self.scan_port, ip, port): port 
                for port in ports_to_scan
            }
            
            # Process completed scans
            for future in as_completed(future_to_port):
                if self.stop_scanning:
                    break
                
                try:
                    result = future.result()
                    host_results.append(result)
                    
                    if self.config.verbose and result.status == "Open":
                        logger.info(f"Open port found: {ip}:{result.port} ({result.service})")
                
                except Exception as e:
                    port = future_to_port[future]
                    logger.error(f"Error scanning {ip}:{port} - {str(e)}")
        
        return host_results
    
    def run_scan(self) -> List[ScanResult]:
        """Run the complete scan"""
        logger.info("Starting port scan...")
        self.scan_start_time = datetime.now()
        
        all_results = []
        
        for ip in self.config.target_ips:
            if self.stop_scanning:
                break
            
            try:
                host_results = self.scan_host(ip)
                all_results.extend(host_results)
                self.results.extend(host_results)
                
            except Exception as e:
                logger.error(f"Error scanning host {ip}: {str(e)}")
        
        self.scan_end_time = datetime.now()
        logger.info("Scan completed!")
        
        return all_results

class ReportGenerator:
    """Class for generating various report formats"""
    
    def __init__(self, results: List[ScanResult], config: ScanConfiguration):
        self.results = results
        self.config = config
    
    def generate_console_report(self) -> str:
        """Generate console report"""
        report = []
        report.append("=" * 80)
        report.append("CYBERSECURITY PORT SCAN REPORT")
        report.append("=" * 80)
        report.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Targets: {', '.join(self.config.target_ips)}")
        report.append(f"Port Range: {self.config.port_range[0]}-{self.config.port_range[1]}")
        report.append(f"Scan Type: {self.config.scan_type.upper()}")
        report.append("-" * 80)
        
        # Group results by IP
        ip_results = {}
        for result in self.results:
            if result.ip not in ip_results:
                ip_results[result.ip] = []
            ip_results[result.ip].append(result)
        
        for ip, results in ip_results.items():
            report.append(f"\nTarget: {ip}")
            report.append(f"Hostname: {NetworkUtils.reverse_dns_lookup(ip)}")
            report.append("-" * 40)
            
            open_ports = [r for r in results if r.status == "Open"]
            
            if open_ports:
                report.append("OPEN PORTS:")
                for result in open_ports:
                    report.append(f"  {result.port:5d}/tcp  {result.service:15s} {result.banner[:50]}")
            else:
                report.append("No open ports found.")
            
            report.append("")
        
        # Summary
        total_ports = len(self.results)
        open_ports = len([r for r in self.results if r.status == "Open"])
        report.append(f"Summary: {open_ports} open ports out of {total_ports} scanned")
        
        return "\n".join(report)
    
    def generate_json_report(self) -> str:
        """Generate JSON report"""
        report_data = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "targets": self.config.target_ips,
                "port_range": self.config.port_range,
                "scan_type": self.config.scan_type,
                "total_ports_scanned": len(self.results),
                "open_ports_found": len([r for r in self.results if r.status == "Open"])
            },
            "results": [asdict(result) for result in self.results]
        }
        return json.dumps(report_data, indent=2)
    
    def generate_csv_report(self) -> str:
        """Generate CSV report"""
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['IP', 'Port', 'Status', 'Service', 'Banner', 'Response Time', 'Timestamp'])
        
        # Write data
        for result in self.results:
            writer.writerow([
                result.ip, result.port, result.status, result.service,
                result.banner, result.response_time, result.timestamp
            ])
        
        return output.getvalue()
    
    def generate_xml_report(self) -> str:
        """Generate XML report"""
        root = ET.Element("portscan_report")
        
        # Scan info
        scan_info = ET.SubElement(root, "scan_info")
        ET.SubElement(scan_info, "timestamp").text = datetime.now().isoformat()
        ET.SubElement(scan_info, "scan_type").text = self.config.scan_type
        
        targets_elem = ET.SubElement(scan_info, "targets")
        for target in self.config.target_ips:
            ET.SubElement(targets_elem, "target").text = target
        
        # Results
        results_elem = ET.SubElement(root, "results")
        for result in self.results:
            result_elem = ET.SubElement(results_elem, "result")
            ET.SubElement(result_elem, "ip").text = result.ip
            ET.SubElement(result_elem, "port").text = str(result.port)
            ET.SubElement(result_elem, "status").text = result.status
            ET.SubElement(result_elem, "service").text = result.service
            ET.SubElement(result_elem, "banner").text = result.banner
            ET.SubElement(result_elem, "response_time").text = str(result.response_time)
            ET.SubElement(result_elem, "timestamp").text = result.timestamp
        
        return ET.tostring(root, encoding='unicode')
    
    def save_report(self, filename: str, format_type: str):
        """Save report to file"""
        try:
            if format_type.lower() == "json":
                content = self.generate_json_report()
            elif format_type.lower() == "csv":
                content = self.generate_csv_report()
            elif format_type.lower() == "xml":
                content = self.generate_xml_report()
            else:
                content = self.generate_console_report()
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(content)
            
            logger.info(f"Report saved to: {filename}")
            
        except Exception as e:
            logger.error(f"Error saving report: {str(e)}")

class PortScannerCLI:
    """Command-line interface for the port scanner"""
    
    def __init__(self):
        self.parser = self.create_parser()
    
    def create_parser(self):
        """Create argument parser"""
        parser = argparse.ArgumentParser(
            description="Accurate Cyber Defense Advanced Cybersecurity Port Scanner Tool",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  python port_scanner.py -t 192.168.1.1 -p 1-1000
  python port_scanner.py -t 192.168.1.0/24 -p 80,443,22 --scan-type udp
  python port_scanner.py -t example.com -p 1-65535 --threads 100 --output report.json
            """
        )
        
        parser.add_argument('-t', '--target', required=True,
                          help='Target IP address, hostname, or IP range (e.g., 192.168.1.1, 192.168.1.0/24)')
        parser.add_argument('-p', '--ports', default='1-1000',
                          help='Port range (e.g., 1-1000, 80,443,22) [default: 1-1000]')
        parser.add_argument('--scan-type', choices=['tcp', 'udp', 'syn', 'stealth'], default='tcp',
                          help='Scan type [default: tcp]')
        parser.add_argument('--timeout', type=float, default=3.0,
                          help='Connection timeout in seconds [default: 3.0]')
        parser.add_argument('--threads', type=int, default=50,
                          help='Number of threads [default: 50]')
        parser.add_argument('--delay', type=float, default=0.0,
                          help='Delay between scans in seconds [default: 0.0]')
        parser.add_argument('-v', '--verbose', action='store_true',
                          help='Verbose output')
        parser.add_argument('-o', '--output',
                          help='Output file name')
        parser.add_argument('--format', choices=['txt', 'json', 'csv', 'xml'], default='txt',
                          help='Output format [default: txt]')
        
        return parser
    
    def parse_port_range(self, port_string: str) -> Tuple[int, int]:
        """Parse port range string"""
        if ',' in port_string:
            # Handle comma-separated ports
            ports = [int(p.strip()) for p in port_string.split(',')]
            return (min(ports), max(ports))
        elif '-' in port_string:
            # Handle range
            start, end = port_string.split('-')
            return (int(start.strip()), int(end.strip()))
        else:
            # Single port
            port = int(port_string)
            return (port, port)
    
    def parse_targets(self, target_string: str) -> List[str]:
        """Parse target string into list of IP addresses"""
        targets = []
        
        for target in target_string.split(','):
            target = target.strip()
            
            # Check if it's a hostname
            if not NetworkUtils.validate_ip(target) and '/' not in target and '-' not in target:
                try:
                    target = NetworkUtils.resolve_hostname(target)
                except PortScannerException as e:
                    logger.warning(str(e))
                    continue
            
            # Check if it's an IP range
            if '/' in target or '-' in target:
                try:
                    range_ips = NetworkUtils.validate_ip_range(target)
                    targets.extend(range_ips)
                except PortScannerException as e:
                    logger.error(str(e))
                    continue
            else:
                if NetworkUtils.validate_ip(target):
                    targets.append(target)
                else:
                    logger.warning(f"Invalid IP address: {target}")
        
        return targets
    
    def run(self):
        """Run the CLI application"""
        args = self.parser.parse_args()
        
        try:
            # Parse targets
            targets = self.parse_targets(args.target)
            if not targets:
                logger.error("No valid targets specified")
                return
            
            # Parse port range
            port_range = self.parse_port_range(args.ports)
            
            # Create configuration
            config = ScanConfiguration(
                target_ips=targets,
                port_range=port_range,
                scan_type=args.scan_type,
                timeout=args.timeout,
                threads=args.threads,
                delay=args.delay,
                verbose=args.verbose,
                output_format=args.format,
                output_file=args.output or f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{args.format}"
            )
            
            # Display scan configuration
            logger.info(f"Scan Configuration:")
            logger.info(f"  Targets: {targets}")
            logger.info(f"  Ports: {port_range[0]}-{port_range[1]}")
            logger.info(f"  Scan Type: {args.scan_type.upper()}")
            logger.info(f"  Threads: {args.threads}")
            logger.info(f"  Timeout: {args.timeout}s")
            
            # Run scan
            scanner = PortScanner(config)
            results = scanner.run_scan()
            
            # Generate and display report
            report_gen = ReportGenerator(results, config)
            
            if args.output:
                report_gen.save_report(args.output, args.format)
            
            # Always show console report
            console_report = report_gen.generate_console_report()
            print(console_report)
            
        except KeyboardInterrupt:
            logger.info("Scan interrupted by user")
        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")

def interactive_mode():
    """Interactive mode for the port scanner"""
    print("=" * 60)
    print("ADVANCED CYBERSECURITY PORT SCANNER TOOL")
    print("=" * 60)
    print("Interactive Mode")
    
    # Get target IP
    while True:
        target = input("\nEnter target IP address, hostname, or IP range: ").strip()
        if not target:
            print("Please enter a valid target.")
            continue
        break
    
    # Get port range
    while True:
        ports = input("Enter port range (e.g., 1-1000, 80,443,22) [default: 1-1000]: ").strip()
        if not ports:
            ports = "1-1000"
        try:
            cli = PortScannerCLI()
            port_range = cli.parse_port_range(ports)
            break
        except ValueError:
            print("Invalid port range format. Please try again.")
    
    # Get scan type
    print("\nScan Types:")
    print("1. TCP Connect Scan (default)")
    print("2. UDP Scan")
    print("3. SYN Scan (requires root)")
    print("4. Stealth Scan")
    
    scan_types = {'1': 'tcp', '2': 'udp', '3': 'syn', '4': 'stealth'}
    while True:
        choice = input("Select scan type [1-4, default: 1]: ").strip()
        if not choice:
            choice = '1'
        if choice in scan_types:
            scan_type = scan_types[choice]
            break
        else:
            print("Invalid choice. Please select 1-4.")
    
    # Get number of threads
    while True:
        threads_input = input("Number of threads [default: 50]: ").strip()
        if not threads_input:
            threads = 50
            break
        try:
            threads = int(threads_input)
            if 1 <= threads <= 1000:
                break
            else:
                print("Please enter a number between 1 and 1000.")
        except ValueError:
            print("Please enter a valid number.")
    
    # Get timeout
    while True:
        timeout_input = input("Connection timeout in seconds [default: 3.0]: ").strip()
        if not timeout_input:
            timeout = 3.0
            break
        try:
            timeout = float(timeout_input)
            if 0.1 <= timeout <= 30.0:
                break
            else:
                print("Please enter a timeout between 0.1 and 30.0 seconds.")
        except ValueError:
            print("Please enter a valid number.")
    
    # Ask for output file
    output_file = input("Output file name (optional): ").strip()
    if output_file:
        format_choice = input("Output format (txt/json/csv/xml) [default: txt]: ").strip().lower()
        if format_choice not in ['txt', 'json', 'csv', 'xml']:
            format_choice = 'txt'
    else:
        format_choice = 'txt'
    
    verbose = input("Verbose output? (y/n) [default: n]: ").strip().lower() == 'y'
    
    try:
        # Parse targets
        cli = PortScannerCLI()
        targets = cli.parse_targets(target)
        
        if not targets:
            print("No valid targets found.")
            return
        
        # Create configuration
        config = ScanConfiguration(
            target_ips=targets,
            port_range=port_range,
            scan_type=scan_type,
            timeout=timeout,
            threads=threads,
            delay=0.0,
            verbose=verbose,
            output_format=format_choice,
            output_file=output_file or f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format_choice}"
        )
        
        print(f"\nStarting {scan_type.upper()} scan...")
        print(f"Targets: {targets}")
        print(f"Ports: {port_range[0]}-{port_range[1]}")
        print(f"Threads: {threads}")
        
        # Run scan
        scanner = PortScanner(config)
        results = scanner.run_scan()
        
        # Generate report
        report_gen = ReportGenerator(results, config)
        
        if output_file:
            report_gen.save_report(output_file, format_choice)
        
        # Show console report
        console_report = report_gen.generate_console_report()
        print(console_report)
        
    except Exception as e:
        print(f"Error during scan: {str(e)}")

def main():
    """Main function"""
    if len(sys.argv) == 1:
        # No command line arguments, run interactive mode
        interactive_mode()
    else:
        # Command line arguments provided, run CLI mode
        cli = PortScannerCLI()
        cli.run()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        sys.exit(1)