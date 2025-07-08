# data_structures.py

from PyQt6.QtCore import QDateTime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum


class ConnectionStatus(Enum):
    """Enumeration for connection status types."""
    ESTABLISHED = "ESTABLISHED"
    LISTENING = "LISTENING"
    TIME_WAIT = "TIME_WAIT"
    CLOSE_WAIT = "CLOSE_WAIT"
    UNKNOWN = "UNKNOWN"


class TracerouteStatus(Enum):
    """Enumeration for traceroute status."""
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    STOPPED = "STOPPED"


@dataclass
class NetworkConnection:
    """Represents a network connection with all relevant information."""
    src_ip: str
    dest_ip: str
    protocol: str
    src_port: int
    dest_port: int
    status: ConnectionStatus = ConnectionStatus.UNKNOWN
    timestamp: Optional[QDateTime] = None
    pid: Optional[int] = None
    process_name: Optional[str] = None
    hostname: Optional[str] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = QDateTime.currentDateTime()

    @property
    def remote_address(self) -> str:
        """Get formatted remote address."""
        return f"{self.dest_ip}:{self.dest_port}"

    @property
    def local_address(self) -> str:
        """Get formatted local address."""
        return f"{self.src_ip}:{self.src_port}"

    @property
    def display_name(self) -> str:
        """Get display name with hostname if available."""
        if self.hostname:
            return f"{self.dest_ip} ({self.hostname})"
        return self.dest_ip


@dataclass
class TracerouteHop:
    """Represents a single hop in a traceroute."""
    hop_number: int
    ip_address: str
    hostname: Optional[str] = None
    response_times: List[float] = field(default_factory=list)
    is_timeout: bool = False

    @property
    def display_address(self) -> str:
        """Get display address with hostname if available."""
        if self.is_timeout:
            return "*"
        if self.hostname and self.hostname != self.ip_address:
            return f"{self.hostname} ({self.ip_address})"
        return self.ip_address

    @property
    def avg_response_time(self) -> float:
        """Calculate average response time."""
        if not self.response_times:
            return 0.0
        return sum(self.response_times) / len(self.response_times)


@dataclass
class TracerouteData:
    """Complete traceroute information for a destination."""
    destination_ip: str
    destination_hostname: Optional[str] = None
    hops: List[TracerouteHop] = field(default_factory=list)
    status: TracerouteStatus = TracerouteStatus.RUNNING
    start_time: Optional[QDateTime] = None
    end_time: Optional[QDateTime] = None
    error_message: Optional[str] = None

    def __post_init__(self):
        if self.start_time is None:
            self.start_time = QDateTime.currentDateTime()

    @property
    def hop_count(self) -> int:
        """Get total number of hops."""
        return len(self.hops)

    @property
    def is_complete(self) -> bool:
        """Check if traceroute is complete."""
        return self.status in [TracerouteStatus.COMPLETED, TracerouteStatus.FAILED, TracerouteStatus.TIMEOUT]

    @property
    def display_destination(self) -> str:
        """Get display destination with hostname if available."""
        if self.destination_hostname:
            return f"{self.destination_hostname} ({self.destination_ip})"
        return self.destination_ip

    def add_hop(self, hop: TracerouteHop) -> None:
        """Add a hop to the traceroute."""
        self.hops.append(hop)

    def mark_completed(self) -> None:
        """Mark traceroute as completed."""
        self.status = TracerouteStatus.COMPLETED
        self.end_time = QDateTime.currentDateTime()

    def mark_failed(self, error: str) -> None:
        """Mark traceroute as failed."""
        self.status = TracerouteStatus.FAILED
        self.error_message = error
        self.end_time = QDateTime.currentDateTime()


@dataclass
class TrafficData:
    """Network traffic information."""
    upload_rate: float = 0.0
    download_rate: float = 0.0
    upload_total: int = 0
    download_total: int = 0
    timestamp: Optional[QDateTime] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = QDateTime.currentDateTime()

    def update(self, upload: float, download: float,
               upload_total: int = 0, download_total: int = 0) -> None:
        """Update traffic data with new values."""
        self.upload_rate = upload
        self.download_rate = download
        self.upload_total = upload_total
        self.download_total = download_total
        self.timestamp = QDateTime.currentDateTime()

    @property
    def total_rate(self) -> float:
        """Get combined upload and download rate."""
        return self.upload_rate + self.download_rate


@dataclass
class PortScanResult:
    """Result of a port scan operation."""
    ip: str
    open_ports: List[int] = field(default_factory=list)
    closed_ports: List[int] = field(default_factory=list)
    scan_time: Optional[QDateTime] = None
    scan_duration: float = 0.0
    is_complete: bool = False

    def __post_init__(self):
        if self.scan_time is None:
            self.scan_time = QDateTime.currentDateTime()

    @property
    def total_ports_scanned(self) -> int:
        """Get total number of ports scanned."""
        return len(self.open_ports) + len(self.closed_ports)

    def add_open_port(self, port: int) -> None:
        """Add an open port to the results."""
        if port not in self.open_ports:
            self.open_ports.append(port)

    def add_closed_port(self, port: int) -> None:
        """Add a closed port to the results."""
        if port not in self.closed_ports:
            self.closed_ports.append(port)


@dataclass
class LANDevice:
    """Represents a device on the local network."""
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    last_seen: Optional[QDateTime] = None
    bytes_sent: int = 0
    bytes_received: int = 0

    def __post_init__(self):
        if self.last_seen is None:
            self.last_seen = QDateTime.currentDateTime()

    @property
    def display_name(self) -> str:
        """Get display name for the device."""
        if self.hostname:
            return f"{self.hostname} ({self.ip_address})"
        return self.ip_address

    def update_traffic(self, bytes_sent: int = 0, bytes_received: int = 0) -> None:
        """Update traffic statistics for this device."""
        self.bytes_sent += bytes_sent
        self.bytes_received += bytes_received
        self.last_seen = QDateTime.currentDateTime()


class DNSCacheManager:
    """Manages DNS resolution cache with thread-safe operations."""

    def __init__(self, max_entries: int = 1000):
        self._cache: Dict[str, str] = {}
        self._max_entries = max_entries
        self._access_order: List[str] = []  # For LRU eviction

    def get(self, ip: str) -> Optional[str]:
        """Get hostname for IP address."""
        if ip in self._cache:
            # Move to end for LRU
            self._access_order.remove(ip)
            self._access_order.append(ip)
            return self._cache[ip]
        return None

    def set(self, ip: str, hostname: str) -> None:
        """Set hostname for IP address."""
        if ip in self._cache:
            # Update existing entry
            self._cache[ip] = hostname
            self._access_order.remove(ip)
            self._access_order.append(ip)
        else:
            # Add new entry
            if len(self._cache) >= self._max_entries:
                # Remove least recently used
                oldest_ip = self._access_order.pop(0)
                del self._cache[oldest_ip]

            self._cache[ip] = hostname
            self._access_order.append(ip)

    def has(self, ip: str) -> bool:
        """Check if IP address is in cache."""
        return ip in self._cache

    def remove(self, ip: str) -> bool:
        """Remove IP address from cache."""
        if ip in self._cache:
            del self._cache[ip]
            self._access_order.remove(ip)
            return True
        return False

    def clear(self) -> None:
        """Clear all cache entries."""
        self._cache.clear()
        self._access_order.clear()

    def items(self) -> List[Tuple[str, str]]:
        """Get all cache items as list of tuples."""
        return list(self._cache.items())

    def size(self) -> int:
        """Get current cache size."""
        return len(self._cache)


class ConnectionManager:
    """Manages network connections with filtering and querying capabilities."""

    def __init__(self, max_connections: int = 100):
        self._connections: Dict[str, NetworkConnection] = {}
        self._max_connections = max_connections

    def add_connection(self, conn: NetworkConnection) -> None:
        """Add or update a network connection."""
        key = self._get_connection_key(conn)

        if len(self._connections) >= self._max_connections and key not in self._connections:
            # Remove oldest connection
            oldest_key = min(self._connections.keys(),
                             key=lambda k: self._connections[k].timestamp)
            del self._connections[oldest_key]

        self._connections[key] = conn

    def get_connection(self, src_ip: str, dest_ip: str, src_port: int, dest_port: int) -> Optional[NetworkConnection]:
        """Get specific connection by address and port."""
        key = f"{src_ip}:{src_port}->{dest_ip}:{dest_port}"
        return self._connections.get(key)

    def get_all(self) -> List[NetworkConnection]:
        """Get all connections as a list."""
        return list(self._connections.values())

    def get_by_destination(self, dest_ip: str) -> List[NetworkConnection]:
        """Get all connections to a specific destination IP."""
        return [conn for conn in self._connections.values() if conn.dest_ip == dest_ip]

    def get_established(self) -> List[NetworkConnection]:
        """Get only established connections."""
        return [conn for conn in self._connections.values()
                if conn.status == ConnectionStatus.ESTABLISHED]

    def get_unique_destinations(self) -> List[str]:
        """Get list of unique destination IPs."""
        return list(set(conn.dest_ip for conn in self._connections.values()))

    def remove_connection(self, src_ip: str, dest_ip: str, src_port: int, dest_port: int) -> bool:
        """Remove a specific connection."""
        key = f"{src_ip}:{src_port}->{dest_ip}:{dest_port}"
        if key in self._connections:
            del self._connections[key]
            return True
        return False

    def clear(self) -> None:
        """Clear all connections."""
        self._connections.clear()

    def size(self) -> int:
        """Get number of connections."""
        return len(self._connections)

    def _get_connection_key(self, conn: NetworkConnection) -> str:
        """Generate unique key for connection."""
        return f"{conn.src_ip}:{conn.src_port}->{conn.dest_ip}:{conn.dest_port}"


class TracerouteManager:
    """Manages traceroute data for multiple destinations."""

    def __init__(self):
        self._traceroutes: Dict[str, TracerouteData] = {}

    def add_traceroute(self, destination: str, traceroute: TracerouteData) -> None:
        """Add or update traceroute data for a destination."""
        self._traceroutes[destination] = traceroute

    def get_traceroute(self, destination: str) -> Optional[TracerouteData]:
        """Get traceroute data for a destination."""
        return self._traceroutes.get(destination)

    def get_all(self) -> Dict[str, TracerouteData]:
        """Get all traceroute data."""
        return self._traceroutes.copy()

    def get_hop_counts(self) -> Dict[str, int]:
        """Get hop counts for all destinations."""
        return {dest: tr.hop_count for dest, tr in self._traceroutes.items()}

    def get_completed(self) -> Dict[str, TracerouteData]:
        """Get only completed traceroutes."""
        return {dest: tr for dest, tr in self._traceroutes.items() if tr.is_complete}

    def remove_traceroute(self, destination: str) -> bool:
        """Remove traceroute data for a destination."""
        if destination in self._traceroutes:
            del self._traceroutes[destination]
            return True
        return False

    def clear(self) -> None:
        """Clear all traceroute data."""
        self._traceroutes.clear()

    def cleanup_old_traceroutes(self, max_age_seconds: int = 300) -> int:
        """Remove traceroutes older than specified age."""
        current_time = QDateTime.currentDateTime()
        removed_count = 0

        for dest in list(self._traceroutes.keys()):
            tr = self._traceroutes[dest]
            if tr.start_time and tr.start_time.secsTo(current_time) > max_age_seconds:
                del self._traceroutes[dest]
                removed_count += 1

        return removed_count


class LANDeviceManager:
    """Manages LAN device discovery and tracking."""

    def __init__(self):
        self._devices: Dict[str, LANDevice] = {}

    def add_device(self, device: LANDevice) -> None:
        """Add or update a LAN device."""
        self._devices[device.ip_address] = device

    def get_device(self, ip_address: str) -> Optional[LANDevice]:
        """Get device by IP address."""
        return self._devices.get(ip_address)

    def get_all_devices(self) -> List[LANDevice]:
        """Get all devices."""
        return list(self._devices.values())

    def update_device_traffic(self, ip_address: str, bytes_sent: int = 0, bytes_received: int = 0) -> None:
        """Update traffic for a device."""
        if ip_address in self._devices:
            self._devices[ip_address].update_traffic(bytes_sent, bytes_received)
        else:
            # Create new device if it doesn't exist
            device = LANDevice(ip_address=ip_address)
            device.update_traffic(bytes_sent, bytes_received)
            self._devices[ip_address] = device

    def get_active_devices(self, max_age_seconds: int = 300) -> List[LANDevice]:
        """Get devices that have been active within the specified time."""
        current_time = QDateTime.currentDateTime()
        return [device for device in self._devices.values()
                if device.last_seen and device.last_seen.secsTo(current_time) <= max_age_seconds]

    def cleanup_old_devices(self, max_age_seconds: int = 3600) -> int:
        """Remove devices that haven't been seen for a while."""
        current_time = QDateTime.currentDateTime()
        removed_count = 0

        for ip in list(self._devices.keys()):
            device = self._devices[ip]
            if device.last_seen and device.last_seen.secsTo(current_time) > max_age_seconds:
                del self._devices[ip]
                removed_count += 1

        return removed_count

    def clear(self) -> None:
        """Clear all devices."""
        self._devices.clear()


# Factory functions for creating common data structures
def create_network_connection(src_ip: str, dest_ip: str, src_port: int, dest_port: int,
                              protocol: str = "TCP", **kwargs) -> NetworkConnection:
    """Factory function to create a NetworkConnection."""
    return NetworkConnection(
        src_ip=src_ip,
        dest_ip=dest_ip,
        src_port=src_port,
        dest_port=dest_port,
        protocol=protocol,
        **kwargs
    )


def create_traceroute_data(destination_ip: str, **kwargs) -> TracerouteData:
    """Factory function to create TracerouteData."""
    return TracerouteData(destination_ip=destination_ip, **kwargs)


def create_traceroute_hop(hop_number: int, ip_address: str, **kwargs) -> TracerouteHop:
    """Factory function to create a TracerouteHop."""
    return TracerouteHop(hop_number=hop_number, ip_address=ip_address, **kwargs)


def create_lan_device(ip_address: str, **kwargs) -> LANDevice:
    """Factory function to create a LANDevice."""
    return LANDevice(ip_address=ip_address, **kwargs)