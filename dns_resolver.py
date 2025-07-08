# dns_resolver.py

import ipaddress
import socket
import threading
import time
from typing import Dict, List, Optional

import psutil
from PyQt6.QtCore import QThread, pyqtSignal

from data_structures import (
    NetworkConnection,
    ConnectionStatus,
    ConnectionManager,
    DNSCacheManager,
    create_network_connection
)
from network_logger import logger


class DNSResolver:
    """Static methods for DNS resolution and connection enumeration with caching."""

    # Class-level cache for DNS resolution
    _dns_cache = DNSCacheManager()

    @staticmethod
    def resolve_hostname(ip: str, use_cache: bool = True) -> Optional[str]:
        """
        Perform reverse DNS lookup for an IP address with caching.

        Args:
            ip: IP address string (IPv4 or IPv6)
            use_cache: Whether to use/update the DNS cache

        Returns:
            Hostname if resolved, None if resolution fails
        """
        # Check cache first if enabled
        if use_cache and DNSResolver._dns_cache.has(ip):
            return DNSResolver._dns_cache.get(ip)

        try:
            ip_obj = ipaddress.ip_address(ip)
            hostname = DNSResolver._resolve_by_version(ip, ip_obj.version)

            # Cache the result if caching is enabled
            if use_cache and hostname:
                DNSResolver._dns_cache.set(ip, hostname)

            return hostname

        except (ValueError, ipaddress.AddressValueError) as e:
            logger.debug(f"Invalid IP address {ip}: {e}")
            return None

    @staticmethod
    def _resolve_by_version(ip: str, version: int) -> Optional[str]:
        """Handle IP resolution based on IP version."""
        try:
            if version == 4:
                return DNSResolver._resolve_ipv4(ip)
            else:
                return DNSResolver._resolve_ipv6(ip)
        except (socket.herror, OSError) as e:
            logger.debug(f"DNS resolution failed for {ip}: {e}")
            return None

    @staticmethod
    def _resolve_ipv4(ip: str) -> Optional[str]:
        """Resolve IPv4 address using gethostbyaddr."""
        hostname, *_ = socket.gethostbyaddr(ip)
        return hostname

    @staticmethod
    def _resolve_ipv6(ip: str) -> Optional[str]:
        """Resolve IPv6 address with fallback methods."""
        # Try gethostbyaddr first
        try:
            hostname, *_ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, OSError):
            pass

        # Fallback to getnameinfo with name required
        try:
            hostname, _ = socket.getnameinfo((ip, 0), socket.NI_NAMEREQD)
            return hostname
        except (socket.herror, OSError):
            pass

        # Last resort: getnameinfo without strict name requirement
        try:
            hostname, _ = socket.getnameinfo((ip, 0), 0)
            return hostname if hostname != ip else None
        except (socket.herror, OSError):
            return None

    @staticmethod
    def get_process_name(pid: Optional[int]) -> Optional[str]:
        """Get process name from PID, handling errors gracefully."""
        if not pid:
            return None

        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    @staticmethod
    def _map_connection_status(status: str) -> ConnectionStatus:
        """Map psutil connection status to ConnectionStatus enum."""
        status_mapping = {
            'ESTABLISHED': ConnectionStatus.ESTABLISHED,
            'LISTEN': ConnectionStatus.LISTENING,
            'TIME_WAIT': ConnectionStatus.TIME_WAIT,
            'CLOSE_WAIT': ConnectionStatus.CLOSE_WAIT,
        }
        return status_mapping.get(status, ConnectionStatus.UNKNOWN)

    @staticmethod
    def enumerate_connections() -> List[NetworkConnection]:
        """
        Get all established network connections with DNS resolution.

        Returns:
            List of NetworkConnection objects for each active connection
        """
        connections = []

        for conn in psutil.net_connections(kind="inet"):
            if not conn.raddr:  # Skip listening sockets
                continue

            # Resolve hostname for remote address
            hostname = DNSResolver.resolve_hostname(conn.raddr.ip)
            process_name = DNSResolver.get_process_name(conn.pid)

            # Map connection status
            status = DNSResolver._map_connection_status(conn.status)

            # Create NetworkConnection object
            network_conn = create_network_connection(
                src_ip=conn.laddr.ip if conn.laddr else "0.0.0.0",
                dest_ip=conn.raddr.ip,
                src_port=conn.laddr.port if conn.laddr else 0,
                dest_port=conn.raddr.port,
                protocol="TCP",  # psutil.net_connections defaults to TCP
                status=status,
                pid=conn.pid,
                process_name=process_name,
                hostname=hostname
            )

            connections.append(network_conn)

        return connections

    @staticmethod
    def clear_dns_cache() -> None:
        """Clear the DNS resolution cache."""
        DNSResolver._dns_cache.clear()

    @staticmethod
    def get_cache_stats() -> Dict[str, int]:
        """Get DNS cache statistics."""
        return {
            'size': DNSResolver._dns_cache.size(),
            'entries': len(DNSResolver._dns_cache.items())
        }


class DNSResolverThread(QThread):
    """
    Background worker that refreshes DNS information at a fixed interval.

    Emits
    -----
    resolved(list[NetworkConnection])
        A list of NetworkConnection objects representing active connections
    """

    resolved = pyqtSignal(list)

    def __init__(self, interval: float = 5.0, parent=None) -> None:
        super().__init__(parent)
        self.interval = interval
        self._running = True
        self._stop_event = threading.Event()
        self._connection_manager = ConnectionManager()

    def run(self) -> None:
        """Main thread loop that emits connection data periodically."""
        logger.info("DNSResolverThread started.")

        while self._running:
            try:
                connections = DNSResolver.enumerate_connections()

                # Update connection manager
                for conn in connections:
                    self._connection_manager.add_connection(conn)

                # Emit the connections
                self.resolved.emit(connections)

            except Exception as e:
                logger.error(f"Error in DNS resolver thread: {e}")
                # Continue running even if there's an error

            # Use wait() instead of sleep() for immediate interruption
            if self._stop_event.wait(self.interval):
                break

        logger.info("DNSResolverThread stopped.")

    def stop(self) -> None:
        """Signal the thread to shut down gracefully."""
        self._running = False
        self._stop_event.set()

    def get_connection_manager(self) -> ConnectionManager:
        """Get the connection manager instance."""
        return self._connection_manager


class ConnectionDisplayFormatter:
    """Handles formatting of connection data for CLI display."""

    @staticmethod
    def format_header() -> str:
        """Return formatted table header."""
        return f"{'PID':>6}  {'Program':<16}  {'Local Address':<22}  {'Remote Address':<22}  {'Status':<12}  {'Hostname'}"

    @staticmethod
    def format_connection(conn: NetworkConnection) -> str:
        """Format a single NetworkConnection for display."""
        return (
            f"{conn.pid or '-':>6}  "
            f"{conn.process_name or '-':<16}  "
            f"{conn.local_address:<22}  "
            f"{conn.remote_address:<22}  "
            f"{conn.status.value:<12}  "
            f"{conn.hostname or ''}"
        )

    @staticmethod
    def get_separator_line(terminal_width: int, header: str) -> str:
        """Get separator line for table."""
        return "-" * min(terminal_width, len(header))


def run_cli(interval: float = 5.0) -> None:
    """
    Run the CLI interface that displays active connections in a table.

    Args:
        interval: Refresh interval in seconds
    """
    import os
    import shutil

    formatter = ConnectionDisplayFormatter()
    terminal_width, _ = shutil.get_terminal_size(fallback=(120, 40))

    try:
        while True:
            # Clear screen
            os.system("cls" if os.name == "nt" else "clear")

            # Get and display connections
            connections = DNSResolver.enumerate_connections()

            print(f"Active Connections – refreshed every {interval} second(s)")
            print(f"DNS Cache: {DNSResolver.get_cache_stats()['size']} entries\n")

            header = formatter.format_header()
            print(header)
            print(formatter.get_separator_line(terminal_width, header))

            for conn in connections:
                print(formatter.format_connection(conn))

            print(f"\nTotal connections: {len(connections)}")
            time.sleep(interval)

    except KeyboardInterrupt:
        print("\nExiting...")


if __name__ == "__main__":
    run_cli()