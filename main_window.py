# main_window.py

import logging
import psutil
from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import (
    QLabel, QListWidget, QMenu, QMessageBox, QTabWidget, QVBoxLayout, QWidget,
    QSplitter, QPushButton, QMainWindow
)

# Import constants
from constants import (
    WINDOW_TITLE, WINDOW_WIDTH, WINDOW_HEIGHT, MAX_CONNECTIONS, TIMER_INTERVAL_MS,
    POLL_INTERVAL_MS, GRACE_PERIOD_COUNT, COLOR_BACKGROUND, COLOR_FOREGROUND,
    COLOR_TEXT_PRIMARY, COLOR_TEXT_SECONDARY, COLOR_BORDER, COLOR_ACCENT
)

# Import data structures
from data_structures import (
    NetworkConnection, ConnectionStatus, ConnectionManager, DNSCacheManager,
    TrafficData, TracerouteData, create_network_connection, PortScanResult
)

# Import the separate components
from widgets import NetworkTrafficWidget, NetworkVisualizationWidget, LANParticleView
from port_scan import PortScannerThread
from traceroute_thread import TracerouteThread
from dns_resolver import DNSResolverThread
from lan_sniffer import LANSnifferThread


class NetworkVisualizer(QMainWindow):
    def __init__(self):
        super().__init__()

        # ============================================================================
        # CORE STATE VARIABLES
        # ============================================================================

        # Visualization mode and traffic tracking
        self.current_mode = 'traceroute'
        self.prev_recv = 0
        self.prev_sent = 0
        self.prev_recv_total = 0
        self.prev_sent_total = 0
        self.current_traffic_data = TrafficData()

        # Visualization update control
        self.visualization_needs_update = False

        # ============================================================================
        # TRACEROUTE MANAGEMENT
        # ============================================================================

        # Traceroute threading and status
        self.traceroute_threads = {}
        self.traceroute_status = {}
        self.traceroute_completed = set()  # Track which destinations have completed traceroutes
        self.hop_counts = {}  # Store hop counts separately for persistence

        # ============================================================================
        # NETWORK ANALYSIS THREADS
        # ============================================================================

        # Individual worker threads (initialized as None)
        self.port_scanner_thread = None
        self.dns_resolver_thread = None
        self.lan_sniffer_thread = None

        # ============================================================================
        # CACHING AND DATA MANAGEMENT
        # ============================================================================

        # DNS and connection management
        self.dns_cache = {}  # Cache for resolved hostnames
        self.connection_manager = ConnectionManager(max_connections=MAX_CONNECTIONS)
        self.dns_cache_manager = DNSCacheManager(max_entries=1000)

        # ============================================================================
        # UI COMPONENTS (initialized as None, set up in init_ui)
        # ============================================================================

        # Tab and list widgets
        self.tabs = None
        self.connections_list = None
        self.ports_list = None

        # Main widget components
        self.traffic_widget = None
        self.visualization_widget = None
        self.lan_particle_view = None

        # Layout and control widgets
        self.toggle_button = None
        self.visualization_layout = None
        self.connection_count_label = None

        # ============================================================================
        # TIMERS (initialized as None, set up in setup_timers)
        # ============================================================================

        self.traffic_timer = None
        self.connection_timer = None

        # ============================================================================
        # INITIALIZATION SEQUENCE
        # ============================================================================

        # Setup window properties
        self.setup_window()

        # Initialize user interface
        self.init_ui()

        # Setup and start timers
        self.setup_timers()

        # Start DNS resolution service
        self.start_dns_resolver()

        # Begin initial connection polling
        self.poll_connections()


    def setup_window(self):
        """Setup main window properties"""
        self.setWindowTitle(WINDOW_TITLE)
        self.resize(WINDOW_WIDTH, WINDOW_HEIGHT)
        self.setStyleSheet(self.get_style_sheet())

    def get_style_sheet(self):
        """Return the application stylesheet"""
        return f"""
            QWidget {{
                background-color: {COLOR_BACKGROUND};
                color: {COLOR_TEXT_PRIMARY};
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 12px;
            }}
            QLabel#connectionLabel {{
                font-size: 14px;
                font-weight: bold;
                color: {COLOR_TEXT_PRIMARY};
                background: transparent;
                margin: 5px 0px;
            }}
            QListWidget {{
                background-color: {COLOR_FOREGROUND};
                border: 1px solid {COLOR_BORDER};
                border-radius: 5px;
                padding: 5px;
                selection-background-color: {COLOR_ACCENT};
            }}
            QTabWidget::pane {{
                border: 1px solid {COLOR_BORDER};
                background-color: {COLOR_FOREGROUND};
                border-radius: 5px;
            }}
            QTabWidget::tab-bar {{
                alignment: left;
            }}
            QTabBar::tab {{
                background-color: {COLOR_BACKGROUND};
                color: {COLOR_TEXT_SECONDARY};
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
            }}
            QTabBar::tab:selected {{
                background-color: {COLOR_ACCENT};
                color: white;
            }}
            QSplitter::handle {{
                background-color: {COLOR_BORDER};
            }}
            QSplitter::handle:horizontal {{
                width: 3px;
            }}
            QSplitter::handle:vertical {{
                height: 3px;
            }}
            QPushButton {{
                background-color: {COLOR_FOREGROUND};
                border: 1px solid {COLOR_BORDER};
                border-radius: 5px;
                padding: 8px 16px;
                color: {COLOR_TEXT_PRIMARY};
            }}
            QPushButton:hover {{
                background-color: {COLOR_ACCENT};
                color: white;
            }}
            QPushButton:checked {{
                background-color: {COLOR_ACCENT};
                color: white;
            }}
        """

    def init_ui(self):
        """Initialize the user interface with simplified layout"""
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(10)

        # Network Traffic Panel - Full width at top (no button above it now)
        self.traffic_widget = NetworkTrafficWidget()
        main_layout.addWidget(self.traffic_widget)

        # Create horizontal splitter for bottom section
        bottom_splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(bottom_splitter)

        # Left panel - Simplified connections panel (now includes toggle button)
        left_panel = self.create_simplified_connections_panel()
        bottom_splitter.addWidget(left_panel)

        # Right panel - Network Visualizer
        self.visualization_widget = NetworkVisualizationWidget()
        self.lan_particle_view = LANParticleView()
        self.visualization_layout = QVBoxLayout()
        self.visualization_layout.setContentsMargins(0, 0, 0, 0)
        self.visualization_layout.addWidget(self.visualization_widget)
        self.lan_particle_view.hide()
        self.visualization_layout.addWidget(self.lan_particle_view)

        visualization_container = QWidget()
        visualization_container.setLayout(self.visualization_layout)
        bottom_splitter.addWidget(visualization_container)

        # Set initial proportions for bottom section: 40% left, 60% right
        bottom_splitter.setSizes([600, 400])

        # Set stretch factors
        bottom_splitter.setStretchFactor(0, 0)  # Connections panel has minimal stretch
        bottom_splitter.setStretchFactor(1, 1)  # Visualization gets most space

    def create_simplified_connections_panel(self):
        """Create simplified connections panel with integrated toggle button"""
        # Create simple widget container
        connections_widget = QWidget()
        connections_widget.setMinimumWidth(300)

        # Single layout for the entire left panel
        layout = QVBoxLayout(connections_widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Connection count label
        self.connection_count_label = QLabel("Network Connections (0)")
        self.connection_count_label.setObjectName("connectionLabel")
        layout.addWidget(self.connection_count_label)

        # Create container for tabs and toggle button
        tabs_container = QWidget()
        tabs_layout = QVBoxLayout(tabs_container)
        tabs_layout.setContentsMargins(0, 0, 0, 0)
        tabs_layout.setSpacing(5)

        # Create tabs for connections and ports
        self.tabs = QTabWidget()
        tabs_layout.addWidget(self.tabs)

        # Create connections tab
        self.connections_list = QListWidget()
        self.connections_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.connections_list.customContextMenuRequested.connect(self.show_context_menu)
        self.tabs.addTab(self.connections_list, "Active Connections (0)")

        # Create ports tab
        self.ports_list = QListWidget()
        self.tabs.addTab(self.ports_list, "Open Ports")

        # Add toggle button below the tabs
        self.toggle_button = QPushButton("Packet View")
        self.toggle_button.setCheckable(True)
        self.toggle_button.clicked.connect(self.toggle_visualization_mode)
        # Make the button a bit more compact
        self.toggle_button.setMaximumHeight(35)
        tabs_layout.addWidget(self.toggle_button)

        # Add the tabs container to the main layout
        layout.addWidget(tabs_container)

        return connections_widget

    def setup_timers(self):
        """Initialize and start timers"""
        self.traffic_timer = QTimer()
        self.traffic_timer.timeout.connect(self.update_traffic_info)
        self.traffic_timer.start(TIMER_INTERVAL_MS)

        self.connection_timer = QTimer()
        self.connection_timer.timeout.connect(self.poll_connections)
        self.connection_timer.start(POLL_INTERVAL_MS)

    def set_visualization_mode(self, mode: str):
        """Switch between 'traceroute' and 'particle' visualizations with immediate UI response."""
        if mode == self.current_mode:
            return

        if mode == 'particle':
            # Switch to LAN particle view
            if not self.lan_sniffer_thread:
                self.lan_sniffer_thread = LANSnifferThread()
                self.lan_sniffer_thread.traffic_update.connect(self.handle_lan_traffic_update)
                self.lan_sniffer_thread.start()

            self.visualization_widget.hide()
            self.lan_particle_view.show()
            self.current_mode = 'particle'

        elif mode == 'traceroute':
            # Switch back to traceroute view
            if self.lan_sniffer_thread:
                self.lan_sniffer_thread.stop()
                self.lan_sniffer_thread.wait()
                self.lan_sniffer_thread = None

            self.lan_particle_view.hide()

            # CRITICAL: Set mode first, then show widget
            self.current_mode = 'traceroute'
            self.visualization_widget.show()

    def toggle_visualization_mode(self):
        """Switch visualizer and update button text with instant feedback"""
        # Disable button temporarily to prevent double-clicks
        self.toggle_button.setEnabled(False)

        if self.toggle_button.isChecked():
            self.toggle_button.setText("Traceroute Mode")
            self.set_visualization_mode("particle")
        else:
            self.toggle_button.setText("Particle View")
            self.set_visualization_mode("traceroute")

        # Re-enable button after a short delay
        QTimer.singleShot(100, lambda: self.toggle_button.setEnabled(True))

    def handle_lan_traffic_update(self, traffic_data):
        """Handle traffic updates from LAN sniffer thread"""
        if isinstance(traffic_data, TrafficData):
            # Update particle view with TrafficData object
            self.lan_particle_view.update_particles(traffic_data)
        else:
            # Handle legacy format - convert to TrafficData
            # Assume traffic_data is a dictionary with download_rate and upload_rate
            traffic_obj = TrafficData(
                download_rate=traffic_data.get('download_rate', 0.0),
                upload_rate=traffic_data.get('upload_rate', 0.0)
            )
            self.lan_particle_view.update_particles(traffic_obj)

    def show_context_menu(self, pos):
        """Show context menu for connection items"""
        item = self.connections_list.itemAt(pos)
        if not item:
            return

        # Extract IP from display text (handle hostname format)
        item_text = item.text()
        ip_address = item_text.split(' ')[0]  # Extract IP from display text

        menu = QMenu()

        scan_action = QAction(f"Scan Ports on {ip_address}", self)
        scan_action.triggered.connect(lambda: self.start_port_scan(ip_address))
        menu.addAction(scan_action)

        # Add DNS refresh action
        refresh_dns_action = QAction(f"Refresh DNS for {ip_address}", self)
        refresh_dns_action.triggered.connect(lambda: self.refresh_single_dns(ip_address))
        menu.addAction(refresh_dns_action)

        menu.exec(self.connections_list.mapToGlobal(pos))

    def refresh_single_dns(self, ip_address):
        """Refresh DNS resolution for a single IP address"""
        try:
            import socket
            hostname, *_ = socket.gethostbyaddr(ip_address)
            self.dns_cache_manager.set(ip_address, hostname)
            self.update_connections_display()
            QMessageBox.information(self, "DNS Refresh", f"Resolved {ip_address} to {hostname}")
        except socket.herror:
            QMessageBox.warning(self, "DNS Refresh", f"Could not resolve hostname for {ip_address}")

    def start_port_scan(self, ip_address):
        """Start port scanning for the given IP address"""
        if self.port_scanner_thread and self.port_scanner_thread.isRunning():
            self.port_scanner_thread.stop()
            self.port_scanner_thread.wait()

        self.ports_list.clear()
        self.ports_list.addItem(f"Scanning ports on {ip_address}...")

        self.port_scanner_thread = PortScannerThread(ip_address)
        self.port_scanner_thread.scan_result.connect(self.display_port_results)
        self.port_scanner_thread.start()

        QMessageBox.information(self, "Port Scan", f"Started scanning {ip_address}")

    def display_port_results(self, scan_result):
        """Display port scan results"""
        self.ports_list.clear()

        # Extract open ports from PortScanResult
        if isinstance(scan_result, PortScanResult):
            open_ports = scan_result.open_ports
        else:
            open_ports = []

        if open_ports:
            for port in open_ports:
                # port is an integer, not a dict
                self.ports_list.addItem(f"Port {port} (TCP) - OPEN")
        else:
            self.ports_list.addItem("No open ports found in scan range")

    def get_active_connections(self):
        """Get list of active network connections using proper data structures"""
        try:
            connections = psutil.net_connections(kind='inet')
            active_connections = []
            seen = set()

            for conn in connections:
                if conn.raddr and conn.raddr.ip not in seen:
                    # Create NetworkConnection object
                    network_conn = create_network_connection(
                        src_ip=conn.laddr.ip if conn.laddr else "0.0.0.0",
                        dest_ip=conn.raddr.ip,
                        src_port=conn.laddr.port if conn.laddr else 0,
                        dest_port=conn.raddr.port,
                        protocol="TCP" if conn.type == 1 else "UDP",
                        status=ConnectionStatus.ESTABLISHED if conn.status == 'ESTABLISHED' else ConnectionStatus.UNKNOWN,
                        pid=conn.pid
                    )

                    # Add to connection manager
                    self.connection_manager.add_connection(network_conn)

                    # Add to active list
                    active_connections.append(network_conn)
                    seen.add(conn.raddr.ip)

                    if len(active_connections) >= MAX_CONNECTIONS:
                        break

            return active_connections
        except Exception as e:
            logging.error(f"Error getting connections: {e}")
            return []

    def start_dns_resolver(self):
        """Start the DNS resolver thread"""
        if not self.dns_resolver_thread:
            self.dns_resolver_thread = DNSResolverThread(interval=10.0)  # Resolve every 10 seconds
            self.dns_resolver_thread.resolved.connect(self.handle_dns_results)
            self.dns_resolver_thread.start()
            logging.info("DNS resolver thread started")

    def handle_dns_results(self, connections_data):
        """Handle DNS resolution results and update cache"""
        for conn in connections_data:
            # Check if conn is a NetworkConnection object or dictionary
            if isinstance(conn, NetworkConnection):
                remote_ip = conn.dest_ip
                hostname = conn.hostname
            else:
                # Handle dictionary format (legacy)
                remote_ip = conn['remote'].split(':')[0] if ':' in conn['remote'] else conn['remote']
                hostname = conn.get('hostname')

            if hostname:
                self.dns_cache_manager.set(remote_ip, hostname)

        # Trigger UI update to show resolved hostnames
        self.update_connections_display()

    def update_connections_display(self):
        """Update connections display with proper data structures"""
        try:
            # Get current connections
            current_connections = self.get_active_connections()

            # Clear and update connections list
            self.connections_list.clear()

            for conn in current_connections:
                # Get hostname from cache
                hostname = self.dns_cache_manager.get(conn.dest_ip)
                if hostname:
                    display_text = f"{conn.dest_ip} ({hostname}) - {conn.protocol}:{conn.dest_port}"
                else:
                    display_text = f"{conn.dest_ip} - {conn.protocol}:{conn.dest_port}"

                self.connections_list.addItem(display_text)

            # Update tab title with connection count
            connection_count = len(current_connections)
            self.tabs.setTabText(0, f"Active Connections ({connection_count})")

            # Update connection count label
            self.connection_count_label.setText(f"Network Connections ({connection_count})")

            # Only update visualization if there's new traceroute data
            if self.visualization_needs_update:
                # Convert hop_counts to TracerouteData format for visualization
                traceroute_data = {}
                for destination, hop_count in self.hop_counts.items():
                    traceroute_data[destination] = TracerouteData(
                        destination_ip=destination
                    )

                # Update visualization
                self.visualization_widget.update_traceroute_data(traceroute_data)
                self.visualization_needs_update = False

        except Exception as e:
            logging.error(f"Error updating connections display: {e}")

    def poll_connections(self):
        """Poll for active connections and update display with smart visualization updates"""
        current_connections = self.get_active_connections()
        current_ips = {conn.dest_ip for conn in current_connections}

        # Start traceroute for new connections (only if we don't already have data)
        for conn in current_connections:
            destination = conn.dest_ip
            if (destination not in self.traceroute_threads and
                    destination not in self.traceroute_completed):
                self.start_traceroute(destination)

        # Clean up old connections
        for destination in list(self.traceroute_threads.keys()):
            if destination not in current_ips:
                self.traceroute_status[destination] = self.traceroute_status.get(destination, 0) + 1
                if self.traceroute_status[destination] > GRACE_PERIOD_COUNT:
                    self.cleanup_traceroute_data(destination)
                    self.dns_cache_manager.remove(destination)
                    self.traceroute_completed.discard(destination)
            else:
                self.traceroute_status.pop(destination, None)

        # Update the display with current connections
        self.update_connections_display()

        # OPTIMIZED: Only update visualization if in traceroute mode AND widget is visible
        if (self.current_mode == 'traceroute' and
                self.visualization_widget.isVisible() and
                self.hop_counts):
            self.visualization_widget.update_traceroute_data(self.hop_counts.copy())

    def cleanup_traceroute_data(self, destination):
        """Clean up traceroute data for a destination"""
        if destination in self.traceroute_threads:
            thread = self.traceroute_threads[destination]
            if thread.isRunning():
                thread.stop()
                thread.wait()
            del self.traceroute_threads[destination]

        # Remove from status tracking and hop counts
        self.traceroute_status.pop(destination, None)
        self.hop_counts.pop(destination, None)
        self.traceroute_completed.discard(destination)

        logging.info(f"Cleaned up traceroute data for {destination}")

        # OPTIMIZED: Only update if in traceroute mode AND widget is visible
        if (self.current_mode == 'traceroute' and
                self.visualization_widget.isVisible()):
            self.visualization_widget.update_traceroute_data(self.hop_counts.copy())

    def start_traceroute(self, destination):
        """Start traceroute for the given destination"""
        if destination not in self.traceroute_threads:
            thread = TracerouteThread(destination)
            thread.traceroute_done.connect(self.handle_traceroute_result)
            thread.start()
            self.traceroute_threads[destination] = thread
            logging.info(f"Started traceroute for {destination}")

    def handle_traceroute_result(self, destination, output, hop_count):
        """Handle traceroute completion with conditional updates"""
        # Store hop count in persistent dictionary
        self.hop_counts[destination] = hop_count
        self.traceroute_completed.add(destination)

        logging.info(f"Traceroute complete for {destination}: {hop_count} hops")

        # Remove the thread since it's completed
        if destination in self.traceroute_threads:
            del self.traceroute_threads[destination]

        # OPTIMIZED: Only update if in traceroute mode AND widget is visible
        if (self.current_mode == 'traceroute' and
                self.visualization_widget.isVisible()):
            self.visualization_widget.update_traceroute_data(self.hop_counts.copy())

    def start_traceroute(self, destination):
        """Start traceroute for the given destination"""
        if destination not in self.traceroute_threads:
            thread = TracerouteThread(destination)
            # Fixed signal connection - was traceroute_complete, now traceroute_done
            thread.traceroute_done.connect(self.handle_traceroute_result)
            thread.start()
            self.traceroute_threads[destination] = thread
            logging.info(f"Started traceroute for {destination}")

    def handle_traceroute_result(self, destination, output, hop_count):
        """Handle traceroute completion"""
        # Store hop count in persistent dictionary
        self.hop_counts[destination] = hop_count
        logging.info(f"Traceroute complete for {destination}: {hop_count} hops")

        # Update visualization immediately
        self.visualization_widget.update_traceroute_data(self.hop_counts.copy())

    def update_traffic_info(self):
        """Update network traffic information using TrafficData objects"""
        try:
            net_stats = psutil.net_io_counters()
            current_recv = net_stats.bytes_recv
            current_sent = net_stats.bytes_sent

            # Calculate rates in MB/s
            recv_speed = (current_recv - self.prev_recv) / (1024 * 1024)  # MB/s
            sent_speed = (current_sent - self.prev_sent) / (1024 * 1024)  # MB/s

            # Update TrafficData object
            self.current_traffic_data.update(
                upload=sent_speed,
                download=recv_speed,
                upload_total=current_sent,
                download_total=current_recv
            )

            # Update traffic widget with TrafficData object
            self.traffic_widget.update_traffic_data(self.current_traffic_data)

            # Update LAN particle view if in LAN mode
            if self.current_mode == 'particle' and hasattr(self, 'lan_particle_view'):
                self.lan_particle_view.update_particles(self.current_traffic_data)

            # Store previous values for next calculation
            self.prev_recv = current_recv
            self.prev_sent = current_sent

        except Exception as e:
            logging.error(f"Error updating traffic info: {e}")

    def get_current_traffic_data(self) -> TrafficData:
        """Get current traffic data as TrafficData object"""
        return self.current_traffic_data

    def closeEvent(self, event):
        """Handle window close event - cleanup threads"""
        if self.dns_resolver_thread and self.dns_resolver_thread.isRunning():
            self.dns_resolver_thread.stop()
            self.dns_resolver_thread.wait()

        # Clean up traceroute threads
        for thread in self.traceroute_threads.values():
            if thread.isRunning():
                thread.stop()  # Now this method exists
                thread.wait()

        if self.port_scanner_thread and self.port_scanner_thread.isRunning():
            self.port_scanner_thread.stop()
            self.port_scanner_thread.wait()

        if self.lan_sniffer_thread and self.lan_sniffer_thread.isRunning():
            self.lan_sniffer_thread.stop()
            self.lan_sniffer_thread.wait()

        event.accept()