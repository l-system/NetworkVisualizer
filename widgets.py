# widgets.py

from PyQt6.QtWidgets import QWidget, QGraphicsView, QGraphicsScene, QGraphicsItem
from PyQt6.QtGui import QPainter, QPaintEvent, QPen, QColor, QBrush, QFont
from PyQt6.QtCore import QRectF, Qt, QTimer, QPointF, QDateTime
import random
import math
import time
from constants import (
    COLOR_ACCENT, COLOR_CONNECTION, COLOR_SENT, COLOR_RECEIVED,
    COLOR_BACKGROUND, COLOR_TEXT_PRIMARY, COLOR_TEXT_SECONDARY,
    FONT_FAMILY, FONT_SIZE_NORMAL, FONT_SIZE_TITLE,
    MAX_CONNECTIONS, MAX_HOPS, MAX_DATA_POINTS, DAMPING,
    TIMER_INTERVAL_MS, MAX_TRAFFIC, COLOR_GRID_CENTER
)
from data_structures import (
    TrafficData, TracerouteData, TracerouteHop, TracerouteStatus
)

class NetworkTrafficWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.upload_data = [0.0] * MAX_DATA_POINTS
        self.download_data = [0.0] * MAX_DATA_POINTS
        self.current_traffic = TrafficData()  # Store current traffic data
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_display)
        self.timer.start(TIMER_INTERVAL_MS)
        self.setMinimumHeight(120)
        self.is_initialized = False  # Flag to prevent initial spike

    def update_traffic_data(self, traffic_data: TrafficData):
        """Update traffic data with TrafficData object"""
        if not isinstance(traffic_data, TrafficData):
            # Handle legacy calls with individual parameters
            if isinstance(traffic_data, (int, float)):
                # Assume first param is download, second is upload
                download_rate = traffic_data
                upload_rate = getattr(self, '_temp_upload', 0.0)
                traffic_data = TrafficData(
                    download_rate=download_rate,
                    upload_rate=upload_rate,
                    timestamp=QDateTime.currentDateTime()
                )
            else:
                return

        # Store current traffic data
        self.current_traffic = traffic_data

        # Skip the first few updates to avoid initial spike
        if not self.is_initialized:
            self.is_initialized = True
            return

        # Normalize speeds using MAX_TRAFFIC constant
        download_value = min(traffic_data.download_rate / MAX_TRAFFIC, 1.0)
        upload_value = min(traffic_data.upload_rate / MAX_TRAFFIC, 1.0)

        # Update data arrays
        self.upload_data.pop(0)
        self.upload_data.append(upload_value)
        self.download_data.pop(0)
        self.download_data.append(download_value)

        self.update()

    def update_display(self):
        """Periodic update for smooth animation"""
        self.update()

    def paintEvent(self, event: QPaintEvent):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()
        margin = 20

        # Draw background using constant
        background_color = QColor(COLOR_BACKGROUND)
        painter.fillRect(0, 0, w, h, background_color)

        # Calculate chart area
        chart_x = margin
        chart_y = 50  # More space for title and current values
        chart_w = w - 2 * margin
        chart_h = h - chart_y - margin - 40  # More space for legend
        center_y = chart_y + chart_h // 2

        # Draw grid lines
        grid_color = QColor(COLOR_BACKGROUND)
        grid_color = grid_color.lighter(150)
        painter.setPen(QPen(grid_color, 1))
        for i in range(5):
            grid_y = chart_y + (chart_h * i) // 4
            painter.drawLine(chart_x, grid_y, chart_x + chart_w, grid_y)

        # Draw center line (baseline) with new color
        painter.setPen(QPen(QColor(COLOR_GRID_CENTER), 1))
        painter.drawLine(chart_x, center_y, chart_x + chart_w, center_y)

        # Draw download data (positive values, upward from center)
        download_color = QColor(COLOR_RECEIVED)
        self.draw_data_waveform(painter, self.download_data, chart_x, chart_y,
                                chart_w, chart_h, center_y, download_color, True)

        # Draw upload data (positive values, downward from center)
        upload_color = QColor(COLOR_SENT)
        self.draw_data_waveform(painter, self.upload_data, chart_x, chart_y,
                                chart_w, chart_h, center_y, upload_color, False)

        # Draw title
        painter.setPen(QPen(QColor(COLOR_TEXT_PRIMARY)))
        font = QFont(FONT_FAMILY, FONT_SIZE_TITLE, QFont.Weight.Bold)
        painter.setFont(font)
        title_rect = painter.fontMetrics().boundingRect("Network Traffic")
        painter.drawText(w // 2 - title_rect.width() // 2, 25, "Network Traffic")

        # Draw current values
        painter.setFont(QFont(FONT_FAMILY, FONT_SIZE_NORMAL))
        current_text = f"↓ {self.current_traffic.download_rate:.1f} MB/s  ↑ {self.current_traffic.upload_rate:.1f} MB/s"
        current_rect = painter.fontMetrics().boundingRect(current_text)
        painter.drawText(w // 2 - current_rect.width() // 2, 40, current_text)

        # Draw scale indicators
        painter.setPen(QPen(QColor(COLOR_TEXT_SECONDARY)))
        painter.setFont(QFont(FONT_FAMILY, FONT_SIZE_NORMAL - 2))

        # Scale labels
        max_label = f"{MAX_TRAFFIC:.0f} MB"
        painter.drawText(chart_x - 50, chart_y + 5, max_label)
        painter.drawText(chart_x - 50, chart_y + chart_h - 5, max_label)

    def draw_data_waveform(self, painter, data, x, y, w, h, center_y, color, is_upward=True):
        """Draw data as dots from center line (similar to bottom's display style)"""
        if len(data) < 2:
            return

        # Set up painter for drawing dots
        painter.setPen(QPen(color, 1))
        painter.setBrush(QBrush(color))

        step = w / (len(data) - 1) if len(data) > 1 else w
        max_distance = h // 2 - 10

        # Calculate dot positions and draw vertical bars of dots
        dot_size = 3
        dot_spacing = 4  # Space between dots in the vertical bar

        for i, value in enumerate(data):
            plot_x = x + i * step

            if value > 0:
                distance_from_center = int(value * max_distance)

                # Calculate number of dots needed for this bar
                num_dots = max(1, distance_from_center // dot_spacing)

                # Draw vertical bar of dots
                for dot_idx in range(num_dots):
                    if is_upward:
                        # Dots extending upward from center
                        dot_y = center_y - (dot_idx + 1) * dot_spacing
                    else:
                        # Dots extending downward from center
                        dot_y = center_y + (dot_idx + 1) * dot_spacing

                    # Draw individual dot
                    painter.drawEllipse(int(plot_x - dot_size / 2), int(dot_y - dot_size / 2), dot_size, dot_size)


class NetworkVisualizationWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.traceroute_data = {}  # Dictionary of {destination: TracerouteData}
        self.connections = []
        self.center_pos = QPointF(200, 200)
        self.current_time = 0.0
        self.setMinimumSize(400, 400)

        # Animation timer using constant
        self.animation_timer = QTimer(self)
        self.animation_timer.timeout.connect(self.update_animation)
        self.animation_timer.start(50)  # 20 FPS

    def update_animation(self):
        """Update animation time and refresh display"""
        self.current_time = time.time()
        self.update()

    def update_traceroute_data(self, traceroute_data: dict):
        """Update visualization with TracerouteData objects"""
        if not isinstance(traceroute_data, dict):
            return

        # Clear existing data to prevent stale entries
        self.traceroute_data.clear()

        # Ensure all entries are TracerouteData objects
        for destination, data in traceroute_data.items():
            if isinstance(data, TracerouteData):
                self.traceroute_data[destination] = data
            elif isinstance(data, int):
                # Handle integer hop count - create single hop representing destination
                hop_count = data

                # Validate hop count
                if hop_count <= 0:
                    continue

                # Create a single hop that represents the final destination
                destination_hop = TracerouteHop(
                    hop_number=hop_count,
                    ip_address=destination,
                    hostname=None,
                    response_times=[0.0]
                )

                # Create TracerouteData with single hop representing the destination
                traceroute_obj = TracerouteData(
                    destination_ip=destination,
                    hops=[destination_hop],
                    status=TracerouteStatus.COMPLETED
                )
                traceroute_obj.mark_completed()
                self.traceroute_data[destination] = traceroute_obj
            elif isinstance(data, list):
                # Handle list data - convert to TracerouteHop objects
                hops = []
                for i, hop_data in enumerate(data):
                    if isinstance(hop_data, TracerouteHop):
                        hops.append(hop_data)
                    else:
                        # Convert string/other data to TracerouteHop
                        hop = TracerouteHop(
                            hop_number=i + 1,
                            ip_address=str(hop_data),
                            hostname=None,
                            response_times=[0.0]
                        )
                        hops.append(hop)

                # Create TracerouteData with list of hops
                traceroute_obj = TracerouteData(
                    destination_ip=destination,
                    hops=hops,
                    status=TracerouteStatus.COMPLETED
                )
                traceroute_obj.mark_completed()
                self.traceroute_data[destination] = traceroute_obj

        # Force immediate repaint to show updated data
        self.update()

    def add_node(self, position: QPointF):
        """Add a node at the specified position"""
        node_id = f"manual_{len(self.traceroute_data)}"
        # Create TracerouteData with correct parameters
        traceroute_obj = TracerouteData(
            destination_ip=node_id,
            hops=[],
            status=TracerouteStatus.RUNNING
        )
        self.traceroute_data[node_id] = traceroute_obj
        self.update()

    def add_connection(self, p1: QPointF, p2: QPointF):
        """Add a connection between two points"""
        self.connections.append((p1, p2))
        self.update()

    def draw_central_hub(self, painter, cx, cy, area_size):
        """Draw the central glowing hub with dynamic sizing"""
        pulse = 0.2 * math.sin(self.current_time * 3.0) + 1.5
        base_size = max(5, min(10, area_size // 20))
        glow_size = base_size + pulse * (area_size // 60)

        accent_color = QColor(COLOR_ACCENT)

        # Draw multiple glow layers
        for i in range(4):
            alpha = int(64 * (1.0 - i * 0.2))
            size_mult = 1.0 + i * 1.4

            glow_color = QColor(accent_color)
            glow_color.setAlpha(alpha // 2)
            painter.setBrush(QBrush(glow_color))

            pen_color = QColor(accent_color)
            pen_color.setAlpha(alpha)
            painter.setPen(QPen(pen_color, 2))

            radius = int(glow_size * size_mult / 2)
            painter.drawEllipse(cx - radius, cy - radius, radius * 2, radius * 2)

        # Core
        painter.setBrush(QBrush(accent_color))
        painter.setPen(QPen(accent_color, 2))
        core_radius = int(base_size / 2)
        painter.drawEllipse(cx - core_radius, cy - core_radius, core_radius * 2, core_radius * 2)

    def draw_connections(self, painter, center_x, center_y, radius):
        """Draw network connections with hops"""
        connection_count = min(len(self.traceroute_data), MAX_CONNECTIONS)
        if connection_count == 0:
            return

        angle_step = 2 * math.pi / connection_count
        connection_color = QColor(COLOR_CONNECTION)

        for i, (destination, traceroute_data) in enumerate(list(self.traceroute_data.items())[:MAX_CONNECTIONS]):
            angle = i * angle_step + self.current_time * 0.1
            end_x = center_x + math.cos(angle) * radius
            end_y = center_y + math.sin(angle) * radius

            # Draw connection line
            painter.setPen(QPen(connection_color, 2))
            painter.drawLine(int(center_x), int(center_y), int(end_x), int(end_y))

            # Draw endpoint with hop count indicator
            endpoint_size = max(5, min(10, int(radius / 15)))
            color_phase = (i / connection_count) * 360
            endpoint_color = QColor()
            endpoint_color.setHsv(int(color_phase), 200, 255)

            painter.setBrush(QBrush(endpoint_color))
            painter.setPen(QPen(endpoint_color, 2))
            painter.drawEllipse(int(end_x) - endpoint_size // 2, int(end_y) - endpoint_size // 2,
                                endpoint_size, endpoint_size)

            # Get hop count from TracerouteData
            hop_count = 0
            if isinstance(traceroute_data, TracerouteData):
                # Check if this is a single-hop destination (converted from integer)
                if len(traceroute_data.hops) == 1:
                    # For single hop destinations, use the hop_number as the total hop count
                    hop_count = traceroute_data.hops[0].hop_number
                else:
                    # For multi-hop destinations, use the actual hop count
                    hop_count = traceroute_data.hop_count

                # Draw hop count label
                if hop_count > 0:
                    painter.setPen(QPen(QColor(COLOR_TEXT_PRIMARY)))
                    painter.setFont(QFont(FONT_FAMILY, FONT_SIZE_NORMAL - 2))

                    # Position label slightly outside the endpoint
                    label_x = end_x + (15 if end_x > center_x else -25)
                    label_y = end_y + (15 if end_y > center_y else -10)

                    painter.drawText(int(label_x), int(label_y), f"{hop_count}")

            # Draw hops - ensure we have a valid hop count
            if hop_count > 0:
                visible_hops = min(hop_count, MAX_HOPS)
                self.draw_hops(painter, int(center_x), int(center_y), int(end_x), int(end_y),
                               visible_hops, i, radius)

    def draw_hops(self, painter, start_x, start_y, end_x, end_y, hop_count, connection_index, radius):
        """Draw hop indicators evenly spaced along connection path"""
        # Validate inputs
        if hop_count <= 0 or radius <= 0:
            return

        hop_size = max(2, min(5, int(radius / 25)))

        # Limit hops for performance and visual clarity
        visible_hops = min(int(hop_count), MAX_HOPS)

        if visible_hops <= 0:
            return

        # Calculate hop positions as percentages along the line
        hop_positions = []

        if visible_hops == 1:
            # Single hop goes at 50%
            hop_positions.append(0.5)
        elif visible_hops == 2:
            # Two hops at 33% and 66%
            hop_positions.extend([0.33, 0.66])
        else:
            # For 3+ hops, distribute evenly with margins
            start_percent = 0.1
            end_percent = 0.9

            if visible_hops == 3:
                hop_positions.extend([0.25, 0.5, 0.75])
            else:
                # For 4+ hops, distribute evenly in the available space
                for h in range(visible_hops):
                    position = start_percent + (end_percent - start_percent) * h / (visible_hops - 1)
                    hop_positions.append(position)

        # Draw hops at calculated positions
        for h, position in enumerate(hop_positions):
            hop_x = start_x + (end_x - start_x) * position
            hop_y = start_y + (end_y - start_y) * position

            # Animated color cycling
            color_phase = math.sin(self.current_time * -2.0 + h * 0.3 + connection_index) * 0.5 + 0.5

            # Create animated hop color
            hop_color = QColor()
            hue = int((180 + color_phase * 60) % 360)  # Cycle through blue-cyan range
            hop_color.setHsv(hue, 200, 255)

            painter.setBrush(QBrush(hop_color))
            painter.setPen(QPen(hop_color))

            # Pulsing size with staggered timing
            pulse = math.sin(self.current_time * 4.0 + h * 0.5 + connection_index) * 0.3 + 0.7
            size = max(1, int(hop_size * pulse))
            painter.drawEllipse(int(hop_x) - size, int(hop_y) - size, size * 2, size * 2)

    def paintEvent(self, event: QPaintEvent):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Draw background using constant
        background_color = QColor(COLOR_BACKGROUND)
        painter.fillRect(0, 0, self.width(), self.height(), background_color)

        # Calculate center and radius
        center_x = int(self.width() / 2)
        center_y = int(self.height() / 2)
        self.center_pos = QPointF(center_x, center_y)

        # Calculate radius based on widget size
        area_size = min(self.width(), self.height())
        radius = area_size * 0.45

        # Draw connections first (so they appear behind the hub)
        self.draw_connections(painter, center_x, center_y, radius)

        # Draw the dynamic central hub
        self.draw_central_hub(painter, center_x, center_y, area_size)

        # Draw any manual connections
        manual_color = QColor(COLOR_TEXT_SECONDARY)
        manual_pen = QPen(manual_color, 1)
        painter.setPen(manual_pen)
        for p1, p2 in self.connections:
            painter.drawLine(p1, p2)


class LANParticleItem(QGraphicsItem):
    def __init__(self):
        super().__init__()
        self.color = QColor(
            random.randint(100, 255),
            random.randint(100, 255),
            random.randint(100, 255)
        )
        self.size = random.uniform(4.0, 8.0)
        self.velocity = QPointF(
            random.uniform(-2, 2),
            random.uniform(-2, 2)
        )
        self.life = 500

    def boundingRect(self) -> QRectF:
        return QRectF(-self.size / 2, -self.size / 2, self.size, self.size)

    def paint(self, painter: QPainter, option, widget=None):
        alpha = int(255 * (self.life / 500))
        color = QColor(self.color)
        color.setAlpha(alpha)

        painter.setBrush(QBrush(color))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(self.boundingRect())

    def advance(self, phase):
        """Animate the particle"""
        if phase == 0:
            return

        pos = self.pos() + self.velocity
        self.setPos(pos)
        self.life -= 1

        scene_rect = self.scene().sceneRect() if self.scene() else QRectF(0, 0, 400, 300)

        # Apply damping from constants
        if pos.x() <= scene_rect.left() or pos.x() >= scene_rect.right():
            self.velocity.setX(-self.velocity.x() * DAMPING)
        if pos.y() <= scene_rect.top() or pos.y() >= scene_rect.bottom():
            self.velocity.setY(-self.velocity.y() * DAMPING)

        self.velocity *= DAMPING


class LANParticleView(QGraphicsView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)

        self.current_traffic = TrafficData()  # Store current traffic data

        # Set dark background using constant
        background_color = QColor(COLOR_BACKGROUND)
        self.setStyleSheet(f"background-color: {background_color.name()};")

        self.particle_timer = QTimer()
        self.particle_timer.timeout.connect(self.spawn_particle)
        self.particle_timer.start(200)

        self.animation_timer = QTimer()
        self.animation_timer.timeout.connect(self.animate_particles)
        self.animation_timer.start(50)

        self.setSceneRect(0, 0, 400, 300)

    def update_particles(self, traffic_data: TrafficData):
        """Update particles based on network traffic using TrafficData structure"""
        if not isinstance(traffic_data, TrafficData):
            return

        self.current_traffic = traffic_data

        # Adjust timer interval based on traffic (more traffic = more particles)
        total_traffic = traffic_data.total_rate
        interval = max(50, 300 - int(total_traffic * 10))
        self.particle_timer.setInterval(interval)

        # Adjust particle colors based on traffic type
        if traffic_data.download_rate > traffic_data.upload_rate:
            # More download traffic - bias towards blue/green
            self.particle_color_bias = 'download'
        elif traffic_data.upload_rate > traffic_data.download_rate:
            # More upload traffic - bias towards red/orange
            self.particle_color_bias = 'upload'
        else:
            self.particle_color_bias = 'balanced'

    def spawn_particle(self):
        """Create a new particle"""
        item = LANParticleItem()

        # Adjust particle properties based on traffic
        if hasattr(self, 'particle_color_bias'):
            if self.particle_color_bias == 'download':
                item.color = QColor(
                    random.randint(50, 150),  # Lower red
                    random.randint(150, 255),  # Higher green
                    random.randint(150, 255)  # Higher blue
                )
            elif self.particle_color_bias == 'upload':
                item.color = QColor(
                    random.randint(150, 255),  # Higher red
                    random.randint(150, 255),  # Higher green
                    random.randint(50, 150)  # Lower blue
                )

        x = random.randint(0, int(self.scene.width()))
        y = random.randint(0, int(self.scene.height()))
        item.setPos(x, y)
        self.scene.addItem(item)

        # Remove old particles to prevent memory issues
        items = self.scene.items()
        if len(items) > 150:
            oldest_items = items[-50:]
            for old_item in oldest_items:
                if isinstance(old_item, LANParticleItem):
                    self.scene.removeItem(old_item)

    def animate_particles(self):
        """Animate all particles and remove dead ones"""
        items_to_remove = []

        for item in self.scene.items():
            if isinstance(item, LANParticleItem):
                item.advance(1)

                if item.life <= 0:
                    items_to_remove.append(item)

        for item in items_to_remove:
            self.scene.removeItem(item)

        self.scene.update()