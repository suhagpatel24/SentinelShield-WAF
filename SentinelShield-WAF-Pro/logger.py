import logging
logging.basicConfig(
    filename="sentinelshield.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)
logger=logging.getLogger("sentinelshield")
def log_alert(message):
    logger.warning(message)
