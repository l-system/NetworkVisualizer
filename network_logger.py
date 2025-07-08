import logging

class NetworkLogger:
    def __init__(self, name='NetworkVisualizer'):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        # Create console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

    def info(self, message):
        self.logger.info(message)

    def warning(self, message):
        self.logger.warning(message)

    def error(self, message):
        self.logger.error(message)

# Instantiate a global logger
logger = NetworkLogger().logger  # Use NetworkLogger here
