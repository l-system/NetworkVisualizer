# threads.py - Network monitoring threads

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

from PyQt6.QtCore import QThread, pyqtSignal, QDateTime
from data_structures import (
    NetworkConnection, ConnectionStatus,
    TrafficData, LANDevice
)

# Import the port scanning classes from port_scan.py
from port_scan import PortScannerThread, PortScanManager


class NetworkConnectionMonitorThread(QThread):
    """Thread for monitoring network connections."""
    connection_updated = pyqtSignal(list)  # List of NetworkConnection objects
    connection_status = pyqtSignal(str)

    def __init__(self, interval: float = 2.0, parent=None):
        super().__init__(parent)
        self.interval = interval
        self._stop_event = threading.Event()
        self._is_running = False

    def run(self):
        """Monitor network connections continuously."""
        self._is_running = True

        while not self._stop_event.is_set():
            try:
                connections = self._get_network_connections()
                self.connection_updated.emit(connections)
                self._stop_event.wait(self.interval)
            except Exception as e:
                self.connection_status.emit(f"Connection monitoring error: {str(e)}")
                break

        self._is_running = False

    def _get_network_connections(self) -> List[NetworkConnection]:
        """Get current network connections (simplified implementation)."""
        connections = []

        # TODO: Implement actual connection monitoring using psutil or similar
        # For now, return sample connections
        sample_connections = [
            ("192.168.1.100", "172.217.14.142", 49152, 443, "TCP", ConnectionStatus.ESTABLISHED),
            ("192.168.1.100", "140.82.112.4", 49153, 443, "TCP", ConnectionStatus.ESTABLISHED),
            ("192.168.1.100", "0.0.0.0", 22, 0, "TCP", ConnectionStatus.LISTENING),
        ]

        for src_ip, dest_ip, src_port, dest_port, protocol, status in sample_connections:
            conn = NetworkConnection(
                src_ip=src_ip,
                dest_ip=dest_ip,
                src_port=src_port,
                dest_port=dest_port,
                protocol=protocol,
                status=status,
                timestamp=QDateTime.currentDateTime()
            )
            connections.append(conn)

        return connections

    def stop(self):
        """Stop connection monitoring."""
        self._stop_event.set()
        self._is_running = False

    def is_running(self):
        """Check if monitoring is running."""
        return self._is_running


class TrafficMonitorThread(QThread):
    """Thread for monitoring network traffic."""
    traffic_updated = pyqtSignal(TrafficData)
    traffic_status = pyqtSignal(str)

    def __init__(self, interval: float = 1.0, parent=None):
        super().__init__(parent)
        self.interval = interval
        self._stop_event = threading.Event()
        self._is_running = False
        self._last_bytes_sent = 0
        self._last_bytes_received = 0
        self._last_time = time.time()

    def run(self):
        """Monitor network traffic continuously."""
        self._is_running = True

        while not self._stop_event.is_set():
            try:
                traffic_data = self._get_traffic_data()
                self.traffic_updated.emit(traffic_data)
                self._stop_event.wait(self.interval)
            except Exception as e:
                self.traffic_status.emit(f"Traffic monitoring error: {str(e)}")
                break

        self._is_running = False

    def _get_traffic_data(self) -> TrafficData:
        """Get current network traffic data (simplified simulation)."""
        current_time = time.time()
        time_diff = current_time - self._last_time

        # TODO: Implement actual traffic monitoring using psutil or similar
        # For now, simulate network traffic
        import random
        bytes_sent = self._last_bytes_sent + random.randint(1000, 10000)
        bytes_received = self._last_bytes_received + random.randint(1000, 10000)

        # Calculate rates
        upload_rate = (bytes_sent - self._last_bytes_sent) / time_diff if time_diff > 0 else 0
        download_rate = (bytes_received - self._last_bytes_received) / time_diff if time_diff > 0 else 0

        # Update last values
        self._last_bytes_sent = bytes_sent
        self._last_bytes_received = bytes_received
        self._last_time = current_time

        return TrafficData(
            upload_rate=upload_rate,
            download_rate=download_rate,
            upload_total=bytes_sent,
            download_total=bytes_received
        )

    def stop(self):
        """Stop traffic monitoring."""
        self._stop_event.set()
        self._is_running = False

    def is_running(self):
        """Check if monitoring is running."""
        return self._is_running


class LANDeviceDiscoveryThread(QThread):
    """Thread for discovering LAN devices."""
    device_discovered = pyqtSignal(LANDevice)
    discovery_finished = pyqtSignal(list)  # List of LANDevice objects
    discovery_status = pyqtSignal(str)

    def __init__(self, subnet: str = "192.168.1.0/24", timeout: float = 1.0, parent=None):
        super().__init__(parent)
        self.subnet = subnet
        self.timeout = timeout
        self._stop_event = threading.Event()
        self._is_running = False

    def run(self):
        """Discover devices on the LAN."""
        self._is_running = True
        self._stop_event.clear()
        discovered_devices = []

        try:
            self.discovery_status.emit(f"Starting LAN device discovery on {self.subnet}")
            ip_addresses = self._generate_ip_addresses()

            with ThreadPoolExecutor(max_workers=50) as executor:
                future_to_ip = {
                    executor.submit(self._check_device, ip): ip
                    for ip in ip_addresses
                }

                for future in as_completed(future_to_ip):
                    if self._stop_event.is_set():
                        break

                    ip = future_to_ip[future]
                    try:
                        device = future.result()
                        if device:
                            discovered_devices.append(device)
                            self.device_discovered.emit(device)
                    except Exception:
                        pass

            if not self._stop_event.is_set():
                self.discovery_finished.emit(discovered_devices)
                self.discovery_status.emit(f"Discovery completed. Found {len(discovered_devices)} devices.")
            else:
                self.discovery_status.emit("Discovery was cancelled.")

        except Exception as e:
            self.discovery_status.emit(f"Discovery failed: {str(e)}")
            self.discovery_finished.emit(discovered_devices)
        finally:
            self._is_running = False

    def _generate_ip_addresses(self) -> List[str]:
        """Generate IP addresses from subnet (/24 only)."""
        base_ip = self.subnet.split('/')[0]
        network_parts = base_ip.split('.')

        return [f"{network_parts[0]}.{network_parts[1]}.{network_parts[2]}.{i}"
                for i in range(1, 255)]

    def _check_device(self, ip_address: str) -> Optional[LANDevice]:
        """Check if a device exists at the given IP address."""
        if self._stop_event.is_set():
            return None

        try:
            # Try multiple common ports to detect device
            common_ports = [80, 443, 22, 21, 23, 25, 53, 135, 139, 445]

            for port in common_ports:
                if self._stop_event.is_set():
                    break

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip_address, port))
                sock.close()

                if result == 0:
                    return LANDevice(
                        ip_address=ip_address,
                        hostname=self._get_hostname(ip_address),
                        mac_address=self._get_mac_address(ip_address),
                        vendor="Unknown"
                    )

            return None

        except Exception:
            return None

    def _get_hostname(self, ip_address: str) -> str:
        """Get hostname for IP address."""
        try:
            import socket
            hostname = socket.gethostbyaddr(ip_address)[0]
            return hostname
        except:
            return f"device-{ip_address.split('.')[-1]}"

    def _get_mac_address(self, ip_address: str) -> str:
        """Get MAC address for IP address."""
        try:
            # TODO: Implement actual MAC address lookup using ARP
            # For now, simulate MAC address
            import random
            mac_parts = [f"{random.randint(0, 255):02x}" for _ in range(6)]
            return ":".join(mac_parts)
        except:
            return "00:00:00:00:00:00"

    def stop(self):
        """Stop device discovery."""
        self._stop_event.set()
        self._is_running = False

    def is_running(self):
        """Check if discovery is running."""
        return self._is_running


# Export classes
__all__ = [
    'NetworkConnectionMonitorThread',
    'TrafficMonitorThread',
    'LANDeviceDiscoveryThread',
    'PortScannerThread',  # From port_scan.py
    'PortScanManager'  # From port_scan.py
]