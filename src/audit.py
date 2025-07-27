import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from uuid import UUID
from .logging import get_logger

# Create dedicated audit logger
audit_logger = get_logger("audit")

class AuthEventType:
    """Constants for authentication event types"""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    REGISTRATION_SUCCESS = "registration_success"
    REGISTRATION_FAILURE = "registration_failure"
    LOGOUT = "logout"
    TOKEN_REFRESH_SUCCESS = "token_refresh_success"
    TOKEN_REFRESH_FAILURE = "token_refresh_failure"
    OAUTH_LOGIN_SUCCESS = "oauth_login_success"
    OAUTH_LOGIN_FAILURE = "oauth_login_failure"
    PASSWORD_CHANGE = "password_change"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"

def log_auth_event(
    event_type: str,
    user_id: Optional[UUID] = None,
    email: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    success: bool = True
):
    """
    Log authentication events with structured data for security monitoring.
    
    Args:
        event_type: Type of authentication event (use AuthEventType constants)
        user_id: UUID of the user (if available)
        email: Email of the user (if available)
        ip_address: IP address of the request
        user_agent: User agent string from the request
        details: Additional details specific to the event
        success: Whether the event was successful or not
    """
    event_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": event_type,
        "success": success,
        "user_id": str(user_id) if user_id else None,
        "email": email,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "details": details or {}
    }
    
    # Remove None values for cleaner logs
    event_data = {k: v for k, v in event_data.items() if v is not None}
    
    # Log at INFO level for successful events, WARNING for failures
    log_level = logging.INFO if success else logging.WARNING
    
    audit_logger.log(
        log_level,
        f"AUTH_EVENT: {event_type}",
        extra={
            "audit_event": True,
            "event_data": json.dumps(event_data, default=str)
        }
    )

def extract_request_info(request) -> Dict[str, str]:
    """Extract IP address and user agent from request for audit logging"""
    return {
        "ip_address": getattr(request, "client", {}).get("host") if hasattr(request, "client") else None,
        "user_agent": request.headers.get("user-agent") if hasattr(request, "headers") else None
    }