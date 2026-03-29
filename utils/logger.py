import logging
import os
from datetime import datetime

class Logger:
    def __init__(self, log_dir: str = "logs"):
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        self.log_filename = os.path.join(log_dir, f"shadowrecon_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler(self.log_filename),
                # logging.StreamHandler() # Handled by Rich CLI
            ]
        )
        self.logger = logging.getLogger("ShadowRecon")

    def info(self, message: str):
        self.logger.info(message)

    def error(self, message: str):
        self.logger.error(message)

    def warning(self, message: str):
        self.logger.warning(message)

# Global logger instance
logger = Logger()
