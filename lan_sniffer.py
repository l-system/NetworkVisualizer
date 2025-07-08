# lan_sniffer.py

from __future__ import annotations

import time
import threading
from collections import Counter
from typing import Dict, Optional

from PyQt6.QtCore import QThread, pyqtSignal

from scapy.all import sniff
from scapy.layers.inet import IP
from network_logger import logger
from data_structures import TrafficData


class LANSnifferThread(QThread):
    """Background sniffer that reports throughput by source IP.

    Emits
    -----
    traffic_update(dict[str, TrafficData])
        Mapping of ``src_ip → TrafficData`` captured in the last *refresh_interval*
        seconds.
    """

    traffic_update = pyqtSignal(dict)

    def __init__(
        self,
        iface: Optional[str] = None,
        refresh_interval: float = 2.0,
        parent=None,
    ) -> None:
        """Args
        ----
        iface
            Name of the interface to sniff on. *None* → scapy chooses default.
        refresh_interval
            How often to emit the ``traffic_update`` signal (in seconds).
        """
        super().__init__(parent)
        self.iface = iface
        self.refresh_interval = refresh_interval

        # Thread-safe shutdown signaling
        self._stop_event = threading.Event()

        # Protected shared data - separate upload/download counters
        self._upload_counters: Counter[str] = Counter()
        self._download_counters: Counter[str] = Counter()
        self._counters_lock = threading.Lock()

        # Emission timing
        self._last_emit = time.time()
        self._emit_lock = threading.Lock()

        # Track local network to distinguish upload/download
        self._local_networks = self._get_local_networks()

    def _get_local_networks(self) -> set[str]:
        """Get common local network prefixes."""
        return {
            '192.168.',
            '10.',
            '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.',
            '172.24.', '172.25.', '172.26.', '172.27.',
            '172.28.', '172.29.', '172.30.', '172.31.',
            '127.',
            '169.254.'
        }

    def _is_local_ip(self, ip: str) -> bool:
        """Check if an IP address is local."""
        return any(ip.startswith(prefix) for prefix in self._local_networks)

    def _process_packet(self, pkt) -> None:
        """Count packet length by *src IP* and classify as upload/download."""
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            packet_size = len(pkt)

            with self._counters_lock:
                # If source is local and destination is external, it's upload
                if self._is_local_ip(src_ip) and not self._is_local_ip(dst_ip):
                    self._upload_counters[src_ip] += packet_size
                # If source is external and destination is local, it's download
                elif not self._is_local_ip(src_ip) and self._is_local_ip(dst_ip):
                    self._download_counters[dst_ip] += packet_size
                # For local-to-local traffic, count as both upload and download
                elif self._is_local_ip(src_ip) and self._is_local_ip(dst_ip):
                    self._upload_counters[src_ip] += packet_size
                    self._download_counters[dst_ip] += packet_size

        # Check if it's time to emit (with proper locking)
        now = time.time()
        should_emit = False

        with self._emit_lock:
            if now - self._last_emit >= self.refresh_interval:
                should_emit = True
                self._last_emit = now

        if should_emit:
            self._emit_traffic_update()

        # Check for stop signal
        if self._stop_event.is_set():
            raise KeyboardInterrupt  # Force *sniff* to return

    def _emit_traffic_update(self) -> None:
        """Safely emit traffic update as TrafficData objects and clear counters."""
        with self._counters_lock:
            if self._upload_counters or self._download_counters:
                # Get all unique IPs from both counters
                all_ips = set(self._upload_counters.keys()) | set(self._download_counters.keys())

                # Create TrafficData objects for each IP
                traffic_data = {}
                for ip in all_ips:
                    upload_bytes = self._upload_counters.get(ip, 0)
                    download_bytes = self._download_counters.get(ip, 0)

                    # Convert bytes to rate (bytes per second)
                    upload_rate = upload_bytes / self.refresh_interval
                    download_rate = download_bytes / self.refresh_interval

                    traffic_data[ip] = TrafficData(
                        upload_rate=upload_rate,
                        download_rate=download_rate,
                        upload_total=upload_bytes,
                        download_total=download_bytes
                    )

                # Clear counters
                self._upload_counters.clear()
                self._download_counters.clear()

                # Emit outside the lock to avoid holding it during signal emission
                self.traffic_update.emit(traffic_data)

    def run(self) -> None:
        """Main thread execution."""
        logger.info("LANSnifferThread started on %s", self.iface or "default iface")
        try:
            sniff(
                iface=self.iface,
                prn=self._process_packet,
                store=False,
                promisc=True,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except KeyboardInterrupt:
            pass
        except Exception as e:
            logger.error("Error in LANSnifferThread: %s", e)
        finally:
            logger.info("LANSnifferThread stopped.")

    def stop(self) -> None:
        """Signal the sniffer to stop (returns immediately)."""
        self._stop_event.set()

    def wait_for_stop(self, timeout: Optional[float] = None) -> bool:
        """Wait for the thread to actually stop.

        Args:
            timeout: Maximum time to wait in seconds

        Returns:
            True if thread stopped within timeout, False otherwise
        """
        return self.wait(timeout or 5000)  # QThread.wait() uses milliseconds