import logging

LOG_FORMAT_DEBUG = "%(levelname)s:%(message)s:%(pathname)s:%(funcName)s:%(lineno)d"
LOG_FORMAT_STANDARD = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

def configure_logging(log_level: str = "INFO"):
    """Configure logging with the specified level"""
    log_level = str(log_level).upper()
    
    # Validate log level
    valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
    if log_level not in valid_levels:
        log_level = "INFO"
    
    # Get the actual logging level
    level = getattr(logging, log_level, logging.INFO)
    
    # Use debug format for DEBUG level, standard format for others
    if log_level == "DEBUG":
        logging.basicConfig(
            level=level, 
            format=LOG_FORMAT_DEBUG,
            force=True  # Override any existing configuration
        )
    else:
        logging.basicConfig(
            level=level, 
            format=LOG_FORMAT_STANDARD,
            force=True  # Override any existing configuration
        )
    
    # Log the configuration
    logger = logging.getLogger(__name__)
    logger.info(f"Logging configured with level: {log_level}")

def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with the specified name"""
    return logging.getLogger(name) 