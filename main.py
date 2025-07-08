# main.py

import sys
import os
import shutil
import traceback
from PyQt6.QtWidgets import QApplication, QMessageBox
from main_window import NetworkVisualizer
from network_logger import logger


def escalate_if_needed():
    """Re‑executes the current process as root via pkexec if not already elevated."""
    if os.name == "nt":
        # Windows – elevation handled differently; skip for now.
        return

    # If already running as root, nothing to do
    try:
        if os.geteuid() == 0:
            return
    except AttributeError:
        # os.geteuid() may not exist on some platforms
        return

    pkexec_path = shutil.which("pkexec")
    if not pkexec_path:
        warning = (
            "pkexec not found — please install PolicyKit or run this program with sudo.\n"
            "Continuing without root; traceroute may fail."
        )
        logger.warning(warning)
        print(warning)
        return

    # Build pkexec command that preserves necessary environment variables for GUI apps
    env_args = ["env"]
    if "DISPLAY" in os.environ:
        env_args.append(f"DISPLAY={os.environ['DISPLAY']}")
    if "XAUTHORITY" in os.environ:
        env_args.append(f"XAUTHORITY={os.environ['XAUTHORITY']}")
    if "VIRTUAL_ENV" in os.environ:
        env_args.append(f"VIRTUAL_ENV={os.environ['VIRTUAL_ENV']}")

    cmd = [pkexec_path] + env_args + [sys.executable] + sys.argv
    logger.info("Re‑executing with elevated privileges via pkexec: %s", " ".join(cmd))

    # Replace current process with elevated one.
    os.execvp(cmd[0], cmd)


def exception_hook(exc_type, exc_value, exc_traceback):
    """Global Qt‑friendly exception handler that logs and shows a dialog."""
    tb = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    logger.critical("Unhandled exception:\n%s", tb)

    QMessageBox.critical(
        None,
        "Application Error",
        f"An unexpected error occurred:\n{exc_value}"
    )
    sys.exit(1)


def main() -> None:
    # Elevate privileges if needed **before** any Qt objects are created
    escalate_if_needed()

    # Install global exception hook for uncaught errors
    sys.excepthook = exception_hook

    # Start Qt application
    app = QApplication(sys.argv)
    visualizer = NetworkVisualizer()
    visualizer.show()
    logger.info("Network Visualizer started.")
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
