from fastapi import FastAPI
from .database.core import engine, Base
from .api import register_routes
from .logging import configure_logging, get_logger
from .sentry import init_sentry
from .config import get_settings
from .rate_limiter import limiter, rate_limit_error_handler
from .middleware.security import SecurityHeadersMiddleware
from .middleware.logging import RequestLoggingMiddleware
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from slowapi.errors import RateLimitExceeded

# Initialize logging FIRST
configure_logging()

# Initialize Sentry (production only)
init_sentry()

logger = get_logger(__name__)
settings = get_settings()

app = FastAPI(
    title="Linguini API",
    description="Language learning platform API with YouTube integration",
    version="1.0.0"
)

# Add rate limiter state to app
app.state.limiter = limiter

# Add rate limit error handler
app.add_exception_handler(RateLimitExceeded, rate_limit_error_handler)

# Add middleware (order matters!)
app.add_middleware(RequestLoggingMiddleware)  # Log all requests
app.add_middleware(SecurityHeadersMiddleware)  # Add security headers

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key  # Use validated SECRET_KEY from settings
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,  # Use CORS origins from settings
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)

# Only create tables in development environment
if settings.is_development:
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created successfully (development mode)")

register_routes(app)


@app.on_event("startup")
async def startup_event():
    """Log application startup"""
    logger.info(
        "Application started",
        extra={"environment": settings.environment, "debug": settings.is_development}
    )


@app.on_event("shutdown")
async def shutdown_event():
    """Log application shutdown"""
    logger.info("Application shutting down")