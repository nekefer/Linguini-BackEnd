import logging
import sys
from pythonjsonlogger import jsonlogger
from .config import get_settings

LOG_FORMAT_JSON = "%(timestamp)s %(level)s %(name)s %(message)s"
LOG_FORMAT_STANDARD = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


class ProductionJSONFormatter(jsonlogger.JsonFormatter):
    """Minimal JSON formatter for production logging"""
    
    def add_fields(self, log_record, record, message_dict):
        super().add_fields(log_record, record, message_dict)
        log_record["timestamp"] = record.created
        log_record["level"] = record.levelname
        log_record["module"] = record.name
        log_record["location"] = f"{record.filename}:{record.funcName}:{record.lineno}"


def configure_logging():
    """Configure logging based on environment (development vs production)"""
    settings = get_settings()
    
    # Root logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # Capture everything
    
    # Remove existing handlers to avoid duplicates
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, settings.log_level))
    
    # Choose format based on environment
    if settings.is_production:
        formatter = ProductionJSONFormatter(LOG_FORMAT_JSON)
    else:
        formatter = logging.Formatter(LOG_FORMAT_STANDARD)
    
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Reduce noise from third-party librar`ies
    logging.getLogger("sqlalchemy").setLevel(logging.WARNING)
    logging.getLogger("fastapi").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("authlib").setLevel(logging.WARNING)
    
    logger = logging.getLogger(__name__)
    logger.info(f"Logging configured for {settings.environment}")


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance"""
    return logging.getLogger(name) 