import logging
from database import create_alert

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("sentinelshield")


def log_alert(ip_address_or_message, attack_type=None, url=None, incident_id=None):
    """Write an alert to the application log and PostgreSQL."""
    if attack_type is None:
        title = "SentinelShield Alert"
        message = str(ip_address_or_message)[:1000]
    else:
        title = f"{attack_type} detected"
        message = f"Source IP: {ip_address_or_message}; path: {url or '/'}"[:1000]
    logger.warning("%s: %s", title, message)
    try:
        create_alert("WARNING", title, message, incident_id)
    except Exception:
        logger.exception("Could not save alert to PostgreSQL")
