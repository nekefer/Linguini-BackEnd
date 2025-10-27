"""
Security middleware for adding security headers to all responses.
"""
from fastapi import Request
from fastapi.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware
import logging

logger = logging.getLogger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all HTTP responses.
    Protects against common web vulnerabilities.
    """
    
    async def dispatch(self, request: Request, call_next):
        """Add security headers to the response."""
        response = await call_next(request)
        
        # Security headers to prevent common attacks
        security_headers = {
            # Prevent MIME type sniffing attacks
            "X-Content-Type-Options": "nosniff",
            
            # Prevent clickjacking attacks
            "X-Frame-Options": "DENY",
            
            # Enable XSS protection
            "X-XSS-Protection": "1; mode=block",
            
            # Control referrer information
            "Referrer-Policy": "strict-origin-when-cross-origin",
            
            # Prevent information disclosure
            "X-Permitted-Cross-Domain-Policies": "none",
            
            # Remove server information
            "Server": "",  # Remove server header
        }
        
        # Add HTTPS-only headers if request is secure
        if request.url.scheme == "https":
            security_headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        
        # Add Content Security Policy for additional protection
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://accounts.google.com; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "connect-src 'self' https://oauth2.googleapis.com https://www.googleapis.com; "
            "frame-src 'none'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        security_headers["Content-Security-Policy"] = csp_policy
        
        # Apply all security headers
        for header, value in security_headers.items():
            if value:  # Only set non-empty values
                response.headers[header] = value
        
        # Log security header application (in debug mode)
        logger.debug(f"Applied security headers to {request.method} {request.url.path}")
        
        return response
