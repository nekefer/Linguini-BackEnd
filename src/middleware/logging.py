import uuid
import time
import logging
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from ..config import get_settings
from ..auth.service import verify_token

logger = logging.getLogger("access")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log all requests with timing and request IDs for debugging"""
    
    async def dispatch(self, request: Request, call_next):
        # Generate unique request ID for tracing requests through system
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        user_id = None

        # Try to extract user_id from the access_token cookie (best-effort)
        try:
            token = request.cookies.get("access_token")
            if token:
                settings = get_settings()
                token_data = verify_token(token, settings.jwt_secret_key, settings.algorithm)
                user_id = token_data.user_id
                request.state.user_id = user_id
        except Exception:
            # If token is missing/invalid, keep user_id as None without failing the request
            user_id = None
        
        start_time = time.time()
        
        # Log incoming request
        logger.info(
            f"{request.method} {request.url.path}",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "client_ip": request.client.host if request.client else "unknown",
                "user_id": user_id,
            }
        )
        
        try:
            response = await call_next(request)
        except Exception as e:
            # Log request that failed with exception
            duration = time.time() - start_time
            logger.error(
                f"{request.method} {request.url.path} - Exception",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "duration_ms": round(duration * 1000, 2),
                    "error": str(e),
                    "user_id": user_id,
                },
                exc_info=True,
            )
            raise
        
        # Log response with status code and duration
        duration = time.time() - start_time
        logger.info(
            f"{request.method} {request.url.path} - {response.status_code}",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": round(duration * 1000, 2),
                "user_id": user_id,
            }
        )
        
        # Add request ID to response headers for debugging
        response.headers["X-Request-ID"] = request_id
        
        return response
