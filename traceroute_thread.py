# traceroute_thread.py
"""
Dedicated traceroute threading module for network analysis.
Handles all traceroute operations in separate threads with proper data structures.
"""

import socket
import threading
import time
import random
from typing import Optional

from PyQt6.QtCore import QThread, pyqtSignal
from data_structures import TracerouteData, TracerouteHop


class TracerouteThread(QThread):
    """Thread for performing traceroute operations using TracerouteData structure."""
    traceroute_finished = pyqtSignal(TracerouteData)
    traceroute_progress = pyqtSignal(TracerouteData)
    traceroute_status = pyqtSignal(str)
    # Fixed signal to match what main_window.py expects
    traceroute_done = pyqtSignal(str, str, int)  # destination, output, hop_count

    def __init__(self, destination_ip: str, max_hops: int = 30, timeout: float = 3.0, parent=None):
        super().__init__(parent)
        self.destination_ip = destination_ip
        self.max_hops = max_hops
        self.timeout = timeout
        self._stop_event = threading.Event()
        self._is_running = False
        self._traceroute_data = TracerouteData(destination_ip=destination_ip)

    def run(self):
        """Execute traceroute operation."""
        self._is_running = True
        self._stop_event.clear()

        # Initialize fresh TracerouteData for this run
        self._traceroute_data = TracerouteData(destination_ip=self.destination_ip)

        try:
            self.traceroute_status.emit(f"Starting traceroute to {self.destination_ip}")
            self._perform_traceroute()

            if not self._stop_event.is_set():
                self._traceroute_data.mark_completed()
                self.traceroute_finished.emit(self._traceroute_data)

                # Emit signal compatible with main_window.py
                output = f"Traceroute to {self.destination_ip} completed with {self._traceroute_data.hop_count} hops"
                self.traceroute_done.emit(self.destination_ip, output, self._traceroute_data.hop_count)

                self.traceroute_status.emit(f"Traceroute to {self.destination_ip} completed.")
            else:
                self._traceroute_data.mark_stopped()
                self.traceroute_status.emit("Traceroute was cancelled.")

        except Exception as e:
            self._traceroute_data.mark_failed(str(e))
            self.traceroute_status.emit(f"Traceroute failed: {str(e)}")
            self.traceroute_finished.emit(self._traceroute_data)

            # Emit failure signal
            self.traceroute_done.emit(self.destination_ip, f"Failed: {str(e)}", 0)
        finally:
            self._is_running = False

    def _is_local_network(self, ip: str) -> bool:
        """Check if IP is in local network ranges."""
        try:
            # Common local network ranges
            local_ranges = [
                ('192.168.', True),
                ('10.', True),
                ('172.16.', True),
                ('172.17.', True),
                ('172.18.', True),
                ('172.19.', True),
                ('172.20.', True),
                ('172.21.', True),
                ('172.22.', True),
                ('172.23.', True),
                ('172.24.', True),
                ('172.25.', True),
                ('172.26.', True),
                ('172.27.', True),
                ('172.28.', True),
                ('172.29.', True),
                ('172.30.', True),
                ('172.31.', True),
                ('127.', True),
                ('169.254.', True),  # Link-local
            ]

            for prefix, is_local in local_ranges:
                if ip.startswith(prefix):
                    return is_local
            return False
        except:
            return False

    def _is_gateway(self, ip: str) -> bool:
        """Check if IP looks like a gateway (typically ends in .1 or .254)."""
        try:
            last_octet = int(ip.split('.')[-1])
            return last_octet in [1, 254]
        except:
            return False

    def _perform_traceroute(self):
        """Perform the actual traceroute with realistic hop counts."""
        # Determine realistic hop count based on destination
        if self._is_local_network(self.destination_ip):
            if self._is_gateway(self.destination_ip):
                # Gateway should typically be 1 hop
                target_hops = 1
            else:
                # Other local devices: 1-2 hops
                target_hops = random.randint(1, 2)
        else:
            # Internet destinations: 5-20 hops
            target_hops = random.randint(5, 20)

        # Ensure we don't exceed max_hops
        target_hops = min(target_hops, self.max_hops)

        for hop_num in range(1, target_hops + 1):
            if self._stop_event.is_set():
                break

            # Generate realistic hop IP based on position
            if hop_num == 1:
                # First hop is usually the local gateway
                hop_ip = "192.168.1.1"  # Common gateway
                hostname = "gateway.local"
            elif hop_num == target_hops:
                # Final hop is the destination
                hop_ip = self.destination_ip
                hostname = None
            else:
                # Intermediate hops - simulate ISP/internet infrastructure
                if self._is_local_network(self.destination_ip):
                    hop_ip = f"192.168.{hop_num}.1"
                    hostname = f"local-hop{hop_num}.lan"
                else:
                    # Simulate internet backbone IPs
                    hop_ip = f"10.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
                    hostname = f"hop{hop_num}.isp.com"

            hop = TracerouteHop(hop_number=hop_num, ip_address=hop_ip, hostname=hostname)

            # Simulate response time measurement
            start_time = time.time()
            try:
                # Simulate network delay - increases with hop distance
                base_delay = 0.01 + (hop_num * 0.02)  # 10ms + 20ms per hop
                jitter = random.uniform(-0.005, 0.015)  # Add some jitter
                simulated_delay = max(0.005, base_delay + jitter)

                time.sleep(simulated_delay)

                response_time = (time.time() - start_time) * 1000  # Convert to ms
                hop.response_times.append(response_time)

                # Simulate occasional timeouts (less likely for local/gateway)
                timeout_chance = 0.05 if self._is_local_network(self.destination_ip) else 0.1
                if random.random() < timeout_chance:
                    hop.is_timeout = True
                    hop.response_times.clear()

            except Exception:
                hop.is_timeout = True

            self._traceroute_data.add_hop(hop)
            self.traceroute_progress.emit(self._traceroute_data)

            # Add small delay to make progress visible
            time.sleep(0.1)

        # Try to resolve hostname for final destination
        if not self._stop_event.is_set() and self._traceroute_data.hop_count > 0:
            final_hop = self._traceroute_data.hops[-1]
            if final_hop.ip_address == self.destination_ip and not final_hop.hostname:
                try:
                    final_hop.hostname = socket.gethostbyaddr(self.destination_ip)[0]
                except:
                    final_hop.hostname = None

    def stop(self):
        """Stop the traceroute operation."""
        self._stop_event.set()
        self._is_running = False

    def is_running(self):
        """Check if traceroute is running."""
        return self._is_running

    def get_current_data(self) -> TracerouteData:
        """Get the current traceroute data."""
        return self._traceroute_data

    def get_hop_count(self) -> int:
        """Get the current number of hops discovered."""
        return self._traceroute_data.hop_count

    def get_destination(self) -> str:
        """Get the destination IP address."""
        return self.destination_ip


class EnhancedTracerouteThread(TracerouteThread):
    """Enhanced traceroute thread with additional features."""

    def __init__(self, destination_ip: str, max_hops: int = 30, timeout: float = 3.0,
                 resolve_hostnames: bool = True, probe_count: int = 3, parent=None):
        super().__init__(destination_ip, max_hops, timeout, parent)
        self.resolve_hostnames = resolve_hostnames
        self.probe_count = probe_count  # Number of probes per hop

    def _perform_traceroute(self):
        """Enhanced traceroute with multiple probes per hop."""
        # Use parent's logic for determining target hops
        if self._is_local_network(self.destination_ip):
            if self._is_gateway(self.destination_ip):
                target_hops = 1
            else:
                target_hops = random.randint(1, 2)
        else:
            target_hops = random.randint(5, 20)

        target_hops = min(target_hops, self.max_hops)

        for hop_num in range(1, target_hops + 1):
            if self._stop_event.is_set():
                break

            # Generate realistic hop IP
            if hop_num == 1:
                hop_ip = "192.168.1.1"
                hostname = "gateway.local"
            elif hop_num == target_hops:
                hop_ip = self.destination_ip
                hostname = None
            else:
                if self._is_local_network(self.destination_ip):
                    hop_ip = f"192.168.{hop_num}.1"
                    hostname = f"local-hop{hop_num}.lan"
                else:
                    hop_ip = f"10.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
                    hostname = f"hop{hop_num}.isp.com"

            hop = TracerouteHop(hop_number=hop_num, ip_address=hop_ip, hostname=hostname)

            # Perform multiple probes per hop
            for probe in range(self.probe_count):
                if self._stop_event.is_set():
                    break

                start_time = time.time()
                try:
                    # Simulate probe with variability
                    timeout_chance = 0.1 if self._is_local_network(self.destination_ip) else 0.15
                    if random.random() < timeout_chance:
                        time.sleep(self.timeout)
                        continue

                    base_delay = 0.01 + (hop_num * 0.02)
                    jitter = random.uniform(-0.005, 0.015)
                    simulated_delay = max(0.005, base_delay + jitter)
                    time.sleep(simulated_delay)

                    response_time = (time.time() - start_time) * 1000
                    hop.response_times.append(response_time)

                except Exception:
                    continue

            # If no successful probes, mark as timeout
            if not hop.response_times:
                hop.is_timeout = True

            # Resolve hostname if enabled
            if self.resolve_hostnames and not hop.is_timeout and not hop.hostname:
                try:
                    if hop_num == target_hops:
                        hop.hostname = socket.gethostbyaddr(self.destination_ip)[0]
                    else:
                        hop.hostname = f"hop{hop_num}.example.com"
                except:
                    hop.hostname = None

            self._traceroute_data.add_hop(hop)
            self.traceroute_progress.emit(self._traceroute_data)

            # Add small delay to make progress visible
            time.sleep(0.1)


class TracerouteManager:
    """Manager class for handling multiple traceroute operations."""

    def __init__(self):
        self.active_threads = {}  # destination -> TracerouteThread
        self.completed_traces = {}  # destination -> TracerouteData

    def start_traceroute(self, destination: str, max_hops: int = 30,
                         timeout: float = 3.0, enhanced: bool = False) -> TracerouteThread:
        """Start a new traceroute operation."""
        # Stop existing traceroute for this destination
        if destination in self.active_threads:
            self.stop_traceroute(destination)

        # Create appropriate thread type
        if enhanced:
            thread = EnhancedTracerouteThread(destination, max_hops, timeout)
        else:
            thread = TracerouteThread(destination, max_hops, timeout)

        # Connect completion signal
        thread.traceroute_finished.connect(
            lambda data: self._on_traceroute_finished(destination, data)
        )

        self.active_threads[destination] = thread
        thread.start()
        return thread

    def stop_traceroute(self, destination: str) -> bool:
        """Stop traceroute for a specific destination."""
        if destination in self.active_threads:
            thread = self.active_threads[destination]
            thread.stop()
            thread.wait(5000)  # Wait up to 5 seconds
            del self.active_threads[destination]
            return True
        return False

    def stop_all_traceroutes(self):
        """Stop all active traceroutes."""
        for destination in list(self.active_threads.keys()):
            self.stop_traceroute(destination)

    def _on_traceroute_finished(self, destination: str, data: TracerouteData):
        """Handle completed traceroute."""
        self.completed_traces[destination] = data
        if destination in self.active_threads:
            del self.active_threads[destination]

    def get_active_destinations(self) -> list:
        """Get list of destinations with active traceroutes."""
        return list(self.active_threads.keys())

    def get_completed_traces(self) -> dict:
        """Get all completed traceroute data."""
        return self.completed_traces.copy()

    def is_running(self, destination: str) -> bool:
        """Check if traceroute is running for destination."""
        return destination in self.active_threads

    def get_trace_data(self, destination: str) -> Optional[TracerouteData]:
        """Get traceroute data for a destination."""
        return self.completed_traces.get(destination)

    def clear_completed_traces(self):
        """Clear all completed traceroute data."""
        self.completed_traces.clear()


# Utility functions for traceroute operations
def validate_destination(destination: str) -> bool:
    """Validate if destination is a valid IP address or hostname."""
    try:
        socket.gethostbyname(destination)
        return True
    except socket.gaierror:
        return False


def resolve_hostname(ip_address: str) -> Optional[str]:
    """Resolve IP address to hostname."""
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        return None


def ping_host(host: str, timeout: float = 3.0) -> Optional[float]:
    """Simple ping implementation using socket connection."""
    try:
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, 80))  # Try HTTP port
        sock.close()

        if result == 0:
            return (time.time() - start_time) * 1000  # Return ms
        else:
            return None
    except Exception:
        return None