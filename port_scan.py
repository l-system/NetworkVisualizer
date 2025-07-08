import ipaddress
import socket
import time
from typing import Optional, Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed

from PyQt6.QtCore import QThread, pyqtSignal, QDateTime
from scapy.config import conf
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.sendrecv import sr1

from data_structures import (
    PortScanResult,
    DNSCacheManager
)
from network_logger import logger


class PortScannerThread(QThread):
    """
    Advanced port scanner thread that uses PortScanResult data structures.

    Signals:
        scan_progress: Emitted with (current_port, total_ports, open_ports_count)
        scan_result: Emitted with PortScanResult object when scan completes
        port_found: Emitted when individual port is found open
        scan_error: Emitted when scan encounters an error
    """

    scan_progress = pyqtSignal(int, int, int)  # current_port, total_ports, open_count
    scan_result = pyqtSignal(object)  # PortScanResult object
    port_found = pyqtSignal(int)  # Individual open port
    scan_error = pyqtSignal(str)  # Error message

    def __init__(self, target_ip: str, start_port: int = 1, end_port: int = 1024,
                 timeout: float = 0.5, scan_mode: str = "connect",
                 max_threads: int = 50, detect_services: bool = False,
                 dns_cache: Optional[DNSCacheManager] = None, parent=None):
        """
        Initialize the port scanner.

        Args:
            target_ip: Target IP address to scan
            start_port: Starting port number
            end_port: Ending port number
            timeout: Timeout for each port scan
            scan_mode: Scan mode ("connect", "syn", "udp")
            max_threads: Maximum threads for connect scan
            detect_services: Whether to detect services on open ports
            dns_cache: DNS cache manager instance
            parent: Parent QObject
        """
        super().__init__(parent)
        self.target_ip = target_ip
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.scan_mode = scan_mode.lower()
        self.max_threads = max_threads
        self.detect_services = detect_services
        self._running = True
        self._paused = False
        self._dns_cache = dns_cache or DNSCacheManager()

        # Initialize scan result with proper timestamp
        self.scan_result_data = PortScanResult(
            ip=target_ip,
            scan_time=QDateTime.currentDateTime()
        )

        # Validate IP address on initialization
        try:
            self.ip_obj = ipaddress.ip_address(self.target_ip)
            self.is_ipv6 = self.ip_obj.version == 6
        except ValueError as e:
            logger.error(f"Invalid IP address {self.target_ip}: {e}")
            self.ip_obj = None
            self.is_ipv6 = False

        # Validate scan mode
        if self.scan_mode not in ["connect", "syn", "udp"]:
            logger.warning(f"Invalid scan mode {self.scan_mode}, defaulting to 'connect'")
            self.scan_mode = "connect"

    def run(self):
        """Execute the port scan with proper error handling and progress reporting."""
        if not self.ip_obj:
            error_msg = f"Invalid IP address: {self.target_ip}"
            logger.error(error_msg)
            self.scan_error.emit(error_msg)
            return

        logger.info(f"Starting {self.scan_mode} scan on {self.target_ip} ports {self.start_port}-{self.end_port}")

        # Configure Scapy to be quiet
        conf.verb = 0

        # Initialize scan timing
        start_time = time.time()
        total_ports = self.end_port - self.start_port + 1

        try:
            # Resolve hostname if possible
            self._resolve_hostname()

            # Choose scan method based on mode
            if self.scan_mode == "connect":
                self._connect_scan()
            elif self.scan_mode == "syn":
                self._syn_scan()
            elif self.scan_mode == "udp":
                self._udp_scan()

            # Finalize scan results
            self.scan_result_data.scan_duration = time.time() - start_time
            self.scan_result_data.is_complete = True

            logger.info(f"Port scan completed. Found {len(self.scan_result_data.open_ports)} open ports")

        except Exception as e:
            error_msg = f"Port scan error: {str(e)}"
            logger.error(error_msg)
            self.scan_error.emit(error_msg)

        finally:
            # Always emit the final result
            self.scan_result.emit(self.scan_result_data)

    def _connect_scan(self):
        """Perform TCP connect scan using multiple threads."""
        ports_to_scan = list(range(self.start_port, self.end_port + 1))

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port = {
                executor.submit(self._connect_scan_port, port): port
                for port in ports_to_scan
            }

            for future in as_completed(future_to_port):
                if not self._running:
                    break

                # Handle pause functionality
                while self._paused and self._running:
                    time.sleep(0.1)

                if not self._running:
                    break

                port = future_to_port[future]
                try:
                    is_open = future.result()

                    if is_open:
                        self.scan_result_data.add_open_port(port)
                        self.port_found.emit(port)
                        logger.debug(f"Port {port} is open on {self.target_ip}")
                    else:
                        self.scan_result_data.add_closed_port(port)

                    # Emit progress
                    self.scan_progress.emit(port, len(ports_to_scan), len(self.scan_result_data.open_ports))

                except Exception as e:
                    logger.debug(f"Error scanning port {port}: {e}")
                    self.scan_result_data.add_closed_port(port)

    def _connect_scan_port(self, port: int) -> bool:
        """Perform TCP connect scan on a single port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target_ip, port))
            sock.close()
            return result == 0
        except Exception as e:
            logger.debug(f"Connect scan error on port {port}: {e}")
            return False

    def _syn_scan(self):
        """Perform SYN scan using Scapy."""
        for port in range(self.start_port, self.end_port + 1):
            if not self._running:
                break

            # Handle pause functionality
            while self._paused and self._running:
                time.sleep(0.1)

            if not self._running:
                break

            is_open = self._syn_scan_port(port)

            if is_open:
                self.scan_result_data.add_open_port(port)
                self.port_found.emit(port)
                logger.debug(f"Port {port} is open on {self.target_ip}")
            else:
                self.scan_result_data.add_closed_port(port)

            # Emit progress
            total_ports = self.end_port - self.start_port + 1
            self.scan_progress.emit(port, total_ports, len(self.scan_result_data.open_ports))

    def _syn_scan_port(self, port: int) -> bool:
        """Perform SYN scan on a single port using Scapy."""
        try:
            # Create the SYN packet
            if self.is_ipv6:
                pkt = IPv6(dst=self.target_ip) / TCP(dport=port, flags='S')
            else:
                pkt = IP(dst=self.target_ip) / TCP(dport=port, flags='S')

            # Send packet and wait for response
            resp = sr1(pkt, timeout=self.timeout, verbose=0)

            if resp and resp.haslayer(TCP):
                tcp_layer = resp.getlayer(TCP)
                if tcp_layer.flags == 0x12:  # SYN-ACK means port open
                    # Send RST to close the connection properly
                    self._send_rst(port)
                    return True

            return False

        except Exception as e:
            logger.debug(f"SYN scan error on port {port}: {e}")
            return False

    def _udp_scan(self):
        """Perform UDP scan using Scapy."""
        # TODO: Implement UDP scanning
        logger.warning("UDP scanning not yet implemented")
        self.scan_error.emit("UDP scanning not yet implemented")

    def _send_rst(self, port: int) -> None:
        """Send RST packet to properly close connection."""
        try:
            if self.is_ipv6:
                rst_pkt = IPv6(dst=self.target_ip) / TCP(dport=port, flags='R')
            else:
                rst_pkt = IP(dst=self.target_ip) / TCP(dport=port, flags='R')

            sr1(rst_pkt, timeout=0.1, verbose=0)
        except Exception as e:
            logger.debug(f"Error sending RST to port {port}: {e}")

    def _resolve_hostname(self) -> Optional[str]:
        """Resolve hostname for the target IP."""
        try:
            # Check cache first
            if self._dns_cache.has(self.target_ip):
                return self._dns_cache.get(self.target_ip)

            # Try to resolve
            hostname = socket.gethostbyaddr(self.target_ip)[0]

            # Cache the result
            self._dns_cache.set(self.target_ip, hostname)
            return hostname

        except (socket.herror, OSError) as e:
            logger.debug(f"Could not resolve hostname for {self.target_ip}: {e}")
            return None

    def _detect_service(self, port: int) -> Optional[str]:
        """Detect service running on an open port."""
        if not self.detect_services:
            return None

        try:
            # Common service mappings
            service_map = {
                21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
                53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
                443: "HTTPS", 993: "IMAPS", 995: "POP3S"
            }

            # Check if it's a well-known service
            if port in service_map:
                return service_map[port]

            # TODO: Implement banner grabbing for service detection
            return "Unknown"

        except Exception as e:
            logger.debug(f"Service detection error on port {port}: {e}")
            return None

    def stop(self):
        """Stop the port scan."""
        self._running = False
        logger.info("Port scan stop requested")

    def pause(self):
        """Pause the port scan."""
        self._paused = True
        logger.info("Port scan paused")

    def resume(self):
        """Resume the port scan."""
        self._paused = False
        logger.info("Port scan resumed")

    def is_running(self) -> bool:
        """Check if scan is currently running."""
        return self._running and self.isRunning()

    def is_paused(self) -> bool:
        """Check if scan is currently paused."""
        return self._paused

    def get_current_results(self) -> PortScanResult:
        """Get current scan results (even if scan is not complete)."""
        return self.scan_result_data

    def set_timeout(self, timeout: float):
        """Set timeout for individual port scans."""
        self.timeout = max(0.1, timeout)  # Minimum 0.1 seconds

    def get_scan_info(self) -> Dict:
        """Get information about the current scan configuration."""
        return {
            'target_ip': self.target_ip,
            'start_port': self.start_port,
            'end_port': self.end_port,
            'total_ports': self.end_port - self.start_port + 1,
            'timeout': self.timeout,
            'scan_mode': self.scan_mode,
            'max_threads': self.max_threads,
            'detect_services': self.detect_services,
            'is_ipv6': self.is_ipv6,
            'is_running': self.is_running(),
            'is_paused': self.is_paused()
        }


class PortScanManager:
    """
    Manager class for handling multiple port scans and results.
    """

    def __init__(self):
        self._scan_results: Dict[str, PortScanResult] = {}
        self._active_scans: Dict[str, PortScannerThread] = {}
        self._dns_cache = DNSCacheManager()

    def start_scan(self, target_ip: str, start_port: int = 1, end_port: int = 1024,
                   timeout: float = 0.5, scan_mode: str = "connect",
                   max_threads: int = 50, detect_services: bool = False) -> PortScannerThread:
        """
        Start a new port scan.

        Args:
            target_ip: IP address to scan
            start_port: Starting port number
            end_port: Ending port number
            timeout: Timeout for each port scan
            scan_mode: Scan mode ("connect", "syn", "udp")
            max_threads: Maximum threads for connect scan
            detect_services: Whether to detect services on open ports

        Returns:
            PortScannerThread instance
        """
        # Stop existing scan for this IP if running
        if target_ip in self._active_scans:
            self.stop_scan(target_ip)

        # Create new scanner
        scanner = PortScannerThread(
            target_ip=target_ip,
            start_port=start_port,
            end_port=end_port,
            timeout=timeout,
            scan_mode=scan_mode,
            max_threads=max_threads,
            detect_services=detect_services,
            dns_cache=self._dns_cache
        )

        # Connect signals
        scanner.scan_result.connect(lambda result: self._on_scan_complete(target_ip, result))
        scanner.finished.connect(lambda: self._cleanup_scan(target_ip))

        # Store and start
        self._active_scans[target_ip] = scanner
        scanner.start()

        return scanner

    def stop_scan(self, target_ip: str) -> bool:
        """
        Stop scan for specific IP.

        Args:
            target_ip: IP address to stop scanning

        Returns:
            True if scan was stopped, False if no scan was running
        """
        if target_ip in self._active_scans:
            scanner = self._active_scans[target_ip]
            scanner.stop()
            scanner.wait(3000)  # Wait up to 3 seconds for thread to finish
            return True
        return False

    def pause_scan(self, target_ip: str) -> bool:
        """Pause scan for specific IP."""
        if target_ip in self._active_scans:
            self._active_scans[target_ip].pause()
            return True
        return False

    def resume_scan(self, target_ip: str) -> bool:
        """Resume scan for specific IP."""
        if target_ip in self._active_scans:
            self._active_scans[target_ip].resume()
            return True
        return False

    def stop_all_scans(self):
        """Stop all active scans."""
        for target_ip in list(self._active_scans.keys()):
            self.stop_scan(target_ip)

    def get_scan_result(self, target_ip: str) -> Optional[PortScanResult]:
        """Get scan results for a specific IP."""
        return self._scan_results.get(target_ip)

    def get_all_results(self) -> Dict[str, PortScanResult]:
        """Get all scan results."""
        return self._scan_results.copy()

    def get_active_scans(self) -> Dict[str, PortScannerThread]:
        """Get all active scans."""
        return self._active_scans.copy()

    def is_scanning(self, target_ip: str) -> bool:
        """Check if currently scanning a specific IP."""
        return target_ip in self._active_scans

    def clear_results(self, target_ip: Optional[str] = None):
        """Clear scan results for specific IP or all results."""
        if target_ip:
            self._scan_results.pop(target_ip, None)
        else:
            self._scan_results.clear()

    def _on_scan_complete(self, target_ip: str, result: PortScanResult):
        """Handle scan completion."""
        self._scan_results[target_ip] = result
        logger.info(f"Scan completed for {target_ip}: {len(result.open_ports)} open ports found")

    def _cleanup_scan(self, target_ip: str):
        """Clean up after scan finishes."""
        self._active_scans.pop(target_ip, None)

    def get_summary(self) -> Dict:
        """Get summary of all scan results."""
        total_scanned = len(self._scan_results)
        total_open_ports = sum(len(result.open_ports) for result in self._scan_results.values())
        active_scans = len(self._active_scans)

        return {
            'total_scanned_ips': total_scanned,
            'total_open_ports_found': total_open_ports,
            'active_scans': active_scans,
            'dns_cache_size': self._dns_cache.size()
        }

    def export_results(self, target_ip: Optional[str] = None) -> Dict:
        """Export scan results in a serializable format."""
        if target_ip:
            results = {target_ip: self._scan_results.get(target_ip)}
        else:
            results = self._scan_results

        export_data = {}
        for ip, result in results.items():
            if result:
                export_data[ip] = {
                    'ip': result.ip,
                    'open_ports': result.open_ports,
                    'closed_ports': result.closed_ports,
                    'scan_time': result.scan_time.toString() if result.scan_time else None,
                    'scan_duration': result.scan_duration,
                    'is_complete': result.is_complete,
                    'total_ports_scanned': result.total_ports_scanned
                }

        return export_data


# Export classes
__all__ = [
    'PortScannerThread',
    'PortScanManager'
]