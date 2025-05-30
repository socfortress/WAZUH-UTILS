from app import app
from loguru import logger

logger.add(
    "debug.log",
    format="{time} {level} {message}",
    level="INFO",
    rotation="10 MB",
    compression="zip",
)
logger.debug("Starting SOCFortress Wazuh Utils Application...")

if __name__ == "__main__":
    app.run(debug=True)