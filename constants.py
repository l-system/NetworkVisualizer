# UI Style settings
FONT_FAMILY = "Segoe UI"  # or "Arial", "Roboto", etc.
FONT_SIZE_TITLE = 14
FONT_SIZE_TRAFFIC = 16
FONT_SIZE_NORMAL = 12
AXIS_LABEL_FONT_SIZE = 12  # Font size for axis labels in plots

COLOR_BACKGROUND = "#1a1a1a"
COLOR_FOREGROUND = "#2d2d2d"
COLOR_BACKGROUND_MAIN = "#31363b"
COLOR_FOREGROUND_MAIN = "#4d4d4d"
COLOR_BACKGROUND_FRAME = "#eff0f1"
COLOR_FOREGROUND_FRAME = "#f0f0f0"

COLOR_TEXT_PRIMARY = "#ffffff"
COLOR_TEXT_SECONDARY = "#cccccc"
COLOR_BORDER = "#555555"

COLOR_ACCENT = "#00ccff"
COLOR_SENT = "#ff6b6b"
COLOR_RECEIVED = "#4ecdc4"
COLOR_CONNECTION = "#66b3ff"
COLOR_HOP = "#ffcc66"
COLOR_GRID_CENTER = "#e6e6e6"

BORDER_RADIUS = 8  # px, rounded corners for frames/buttons
BORDER_WIDTH = 1  # px
PADDING = 10  # px padding inside widgets

WINDOW_OPACITY = 0.95  # Optional, if you want slight transparency

# Window and Visualization dimensions
WINDOW_TITLE = "Network Visualizer"
WINDOW_WIDTH = 1920
WINDOW_HEIGHT = 1080
VISUALIZATION_WIDTH = 1024
VISUALIZATION_HEIGHT = 600

# Network settings
MAX_CONNECTIONS = 30
MAX_HOPS = 8

# Timing settings
POLL_INTERVAL_MS = 5000
TIMER_INTERVAL_MS = 1000
TIMEOUT_DURATION = 30
PORTS_UPDATE_INTERVAL_MS = 10000

# Grace period settings
GRACE_PERIOD_COUNT = 3

# Data visualization settings
MAX_DATA_POINTS = 200
MAX_TRAFFIC = 1.0  # MB/s normalization factor
FIGURE_SIZE = (6, 2)

# Plotting colors and styles
PLOT_COLOR_RECEIVED = "blue"
PLOT_COLOR_SENT = "red"
PLOT_LINE_WIDTH = 1
SMOOTHING = 3

# Constants
REPULSION_FORCE = 0.5
DAMPING = 0.98
MIN_DISTANCE = 5.0

# Miscellaneous
Y_AXIS_MULTIPLIER = 5
ACTIVE_CONNECTIONS_LABEL_TEXT = "Active Connections: 0"
