import logging
from .config import get_settings

logger = logging.getLogger(__name__)


def init_sentry():
    """Initialize Sentry error tracking (production only)
    
    Sentry is disabled in development to avoid overhead.
    Only initializes if SENTRY_DSN is configured and environment is production.
    """
    settings = get_settings()
    
    # Skip if no DSN configured
    if not settings.sentry_dsn:
        logger.debug("Sentry not configured (SENTRY_DSN not set)")
        return
    
    # Skip if not in production
    if not settings.is_production:
        logger.debug("Sentry disabled in development mode")
        return
    
    try:
        import sentry_sdk
        from sentry_sdk.integrations.fastapi import FastApiIntegration
        from sentry_sdk.integrations.starlette import StarletteIntegration
        from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
        from sentry_sdk.integrations.logging import LoggingIntegration
        
        # Initialize Sentry with FastAPI integrations
        sentry_sdk.init(
            dsn=settings.sentry_dsn,
            integrations=[
                FastApiIntegration(),
                StarletteIntegration(),
                SqlalchemyIntegration(),
                LoggingIntegration(
                    level=logging.INFO,  # Capture info and above
                    event_level=logging.ERROR,  # Send errors to Sentry
                ),
            ],
            traces_sample_rate=0.1,  # Sample 10% of transactions
            environment=settings.environment,
            enable_logs=True,  # Enable logging to Sentry
        )
        
        logger.info("Sentry initialized successfully with log capture enabled")
        
    except ImportError:
        logger.warning("sentry-sdk not installed, skipping Sentry initialization")
    except Exception as e:
        logger.error(f"Failed to initialize Sentry: {str(e)}")
