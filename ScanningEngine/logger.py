import logging
import sys
from config import LOGS_DIR


class ScanLogger:
    def __init__(self, name, log_file=None):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)

        if not self.logger.handlers:
            formatter = logging.Formatter(
                '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
                '%Y-%m-%d %H:%M:%S'
            )

            console = logging.StreamHandler(sys.stdout)
            console.setFormatter(formatter)
            self.logger.addHandler(console)

            if log_file:
                file_handler = logging.FileHandler(LOGS_DIR / log_file)
                file_handler.setFormatter(formatter)
                self.logger.addHandler(file_handler)

    def info(self, msg):
        self.logger.info(msg)

    def warning(self, msg):
        self.logger.warning(msg)

    def error(self, msg):
        self.logger.error(msg)

