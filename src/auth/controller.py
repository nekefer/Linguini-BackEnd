from typing import Annotated
from datetime import timedelta
from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse
from starlette import status
from . import  models
from . import service
from fastapi.security import OAuth2PasswordRequestForm
from ..database.core import DbSession
from ..rate_limiter import limiter, RATE_LIMITS
from ..exceptions import AuthenticationError
from .google.oauth_config import oauth  # fixed import
from ..config import get_settings, Settings
from ..entities.user import User
import urllib.parse
import logging
from sqlalchemy.orm import Session

router = APIRouter(
    prefix='/auth',
    tags=['auth']
)

@router.post("/", status_code=status.HTTP_201_CREATED)
@limiter.limit(RATE_LIMITS["auth_register"])
async def register_user(
    request: Request, 
    db: DbSession,
    register_user_request: models.RegisterUserRequest,
    settings: Annotated[Settings, Depends(get_settings)]
):
    """Register user and automatically log them in by setting auth cookies."""
    # Create the user
    service.register_user(db, register_user_request)
    
    # Log successful registration
    logging.info(
        f"New user registered: {register_user_request.email}, "
        f"IP: {request.client.host}, "
        f"User-Agent: {request.headers.get('user-agent', 'unknown')}"
    )
    
    # Automatically log them in after registration
    user = db.query(User).filter(User.email == register_user_request.email).first()
    if not user:
        raise AuthenticationError("User creation failed")
    
    # Create token pair for the new user
    jwt_token = service.create_token_pair(user, settings, db)
    
    # Create response with success message
    response = JSONResponse(content={
        "message": "User registered and logged in successfully",
        "user": {
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name
        }
    })
    
    # Set authentication cookies
    response.set_cookie(
        key="access_token",
        value=jwt_token.access_token,
        httponly=True,
        secure=settings.is_production,
        samesite="lax",
        max_age=settings.access_token_expire_minutes * 60,
        path="/"
    )
    
    response.set_cookie(
        key="refresh_token",
        value=jwt_token.refresh_token,
        httponly=True,
        secure=settings.is_production,
        samesite="lax",
        max_age=settings.refresh_token_expire_days * 24 * 60 * 60,
        path="/"
    )
    
    return response


@router.post("/token", response_model=models.Token)
@limiter.limit(RATE_LIMITS["auth_login"])
async def login_for_access_token(
    request: Request,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: DbSession,
    settings: Annotated[Settings, Depends(get_settings)]
):
    """Login endpoint that sets both access and refresh tokens."""
    token_data = service.login_for_access_token(form_data, db, settings)
    
    # Log successful login
    logging.info(
        f"User logged in via password: {form_data.username}, "
        f"IP: {request.client.host}, "
        f"User-Agent: {request.headers.get('user-agent', 'unknown')}"
    )
    
    # Create response with token data
    response = JSONResponse(content={
        "access_token": token_data.access_token,
        "refresh_token": token_data.refresh_token,  # ✅ Add refresh token
        "token_type": token_data.token_type,
        "expires_in": token_data.expires_in
    })
    
    # Set both JWT tokens in HttpOnly cookies
    response.set_cookie(
        key="access_token",
        value=token_data.access_token,
        httponly=True,
        secure=settings.is_production,
        samesite="lax",
        max_age=settings.access_token_expire_minutes * 60,
        path="/"
    )
    
    # ✅ Add refresh token cookie
    response.set_cookie(
        key="refresh_token",
        value=token_data.refresh_token,
        httponly=True,
        secure=settings.is_production,
        samesite="lax",
        max_age=settings.refresh_token_expire_days * 24 * 60 * 60,
        path="/"
    )
    
    return response

@router.get("/google/login")
@limiter.limit(RATE_LIMITS["auth_google_login"])
async def google_login(request: Request):
    """🎯 Unified Google OAuth - handles both registration and login automatically."""
    redirect_uri = request.url_for('google_auth')
    
    # Simple state parameter for CSRF protection (no intent needed)
    import secrets
    state = secrets.token_urlsafe(32)
    
    # access_type='offline' + prompt='consent' ensures we get a refresh_token
    # This allows us to refresh expired access tokens without user re-authentication
    return await oauth.google.authorize_redirect(
        request, 
        redirect_uri=redirect_uri, 
        state=state,
        access_type='offline',  # Request offline access (refresh token)
        prompt='consent'  # Force consent screen to get refresh token every time
    )


# Handle the OAuth callback from Google
@router.get("/google/callback")
@limiter.limit(RATE_LIMITS["auth_google_callback"])
async def google_auth(
    request: Request,
    db: DbSession,
    settings: Annotated[Settings, Depends(get_settings)]
):
    """
    🎯 Unified Google OAuth callback - automatically handles registration and login.
    No matter which page the user came from, this will:
    - Create account if user doesn't exist
    - Log in if user already exists
    """
    try:
        # Get full token response from Google (includes access_token, refresh_token, expires_in)
        token = await oauth.google.authorize_access_token(request)
        
        user_info = token.get("userinfo") or {}
        
        if not user_info:
            raise AuthenticationError("Google OAuth failed - no user info received")
        
        # Extract user info from the user_info dict
        user_email = user_info.get("email", "")
        
        # 🎯 UNIFIED GOOGLE OAUTH APPROACH
        # No matter if they came from login or register page:
        # - If user exists → Log them in
        # - If user doesn't exist → Create account and log them in
        # This eliminates confusing error messages!
        
        # Pass full token dict to service (includes access_token, refresh_token, expires_in)
        jwt_token = service.google_authenticate_user(db, user_info, settings, google_tokens=token)
        
        # Create response with redirect to frontend
        # Always redirect to dashboard for seamless experience
        redirect_url = f"{settings.frontend_url}/dashboard"

        
        response = RedirectResponse(url=redirect_url)
        
        # Set JWT token in HttpOnly cookie
        response.set_cookie(
            key="access_token",
            value=jwt_token.access_token,
            httponly=True,
            secure=settings.is_production,  # Use secure cookies in production
            samesite="lax",
            max_age=3600,  # 1 hour
            path="/"
        )
        
        # ✅ Add refresh token cookie
        response.set_cookie(
            key="refresh_token",
            value=jwt_token.refresh_token,  # ✅ Add this
            httponly=True,
            secure=settings.is_production,
            samesite="lax",
            max_age=settings.refresh_token_expire_days * 24 * 60 * 60,
            path="/"
        )
        
        return response
        
    except KeyError as e:
        logging.error(f"Missing required OAuth field: {str(e)}")
        error_url = f"{settings.frontend_url}/?error=incomplete_oauth_data"
        return RedirectResponse(url=error_url)
    except AuthenticationError as e:
        logging.error(f"Authentication failed: {str(e)}")
        error_url = f"{settings.frontend_url}/?error=authentication_failed"
        return RedirectResponse(url=error_url)
    except Exception as e:
        logging.error(f"Unexpected OAuth error: {str(e)}", exc_info=True)
        error_url = f"{settings.frontend_url}/?error=server_error"
        return RedirectResponse(url=error_url)


@router.get("/me", response_model=models.UserResponse)
@limiter.limit(RATE_LIMITS["user_profile"])
async def get_current_user_info(request: Request, current_user: service.CurrentUser, db: DbSession):
    """Get current user information."""
    try:
        user_id = current_user.get_uuid()
        if not user_id:
            raise AuthenticationError("Invalid user token")
        
        # ✅ Replace the broken function call with direct database query
        user = db.query(User).filter(User.id == user_id).first()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        return models.UserResponse(
            id=user.id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            auth_method=user.auth_method,
            avatar_url=user.avatar_url,
            is_active=user.is_active,
            created_at=user.created_at.isoformat(),
            updated_at=user.updated_at.isoformat()
        )
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except HTTPException:
        raise  # Re-raise HTTP exceptions as-is
    except Exception as e:
        logging.error(f"Unexpected error in get_current_user_info: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to get user information")


@router.post("/logout")
@limiter.limit(RATE_LIMITS["general"])
async def logout(request: Request, db: DbSession, settings: Annotated[Settings, Depends(get_settings)]):
    """✅ UPDATED: Logout endpoint - clears all cookies including Google tokens."""
    try:
        # Create response
        response = JSONResponse(content={"message": "Successfully logged out"})
        
        # Clear all auth cookies with proper settings
        response.delete_cookie(
            key="access_token",
            path="/",
            secure=settings.is_production,
            httponly=True,
            samesite="lax"
        )
        
        response.delete_cookie(
            key="refresh_token",
            path="/",
            secure=settings.is_production,
            httponly=True,
            samesite="lax"
        )
        
        return response
        
    except AuthenticationError as e:
        # User wasn't authenticated, but that's okay for logout
        logging.info(f"Logout attempted without valid authentication: {str(e)}")
        response = JSONResponse(content={"message": "Logged out"})
        # Clear cookies anyway
        response.delete_cookie(key="access_token", path="/")
        response.delete_cookie(key="refresh_token", path="/")
        return response
    except Exception as e:
        # Unexpected error during logout
        logging.error(f"Error during logout: {str(e)}", exc_info=True)
        response = JSONResponse(content={"message": "Logged out (some cleanup failed)"})
        # Clear cookies anyway
        response.delete_cookie(key="access_token", path="/")
        response.delete_cookie(key="refresh_token", path="/")
        
        return response


@router.put("/change-password", status_code=status.HTTP_200_OK)
@limiter.limit(RATE_LIMITS["change-password"])
async def change_password(
    request: Request,
    password_change: models.PasswordChange,
    db: DbSession,
    current_user: service.CurrentUser
):
    """Change user password. Requires authentication."""
    try:
        service.change_password(db, current_user.get_uuid(), password_change)
        return {"message": "Password changed successfully"}
    except AuthenticationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logging.error(f"Unexpected error in change_password: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to change password")


@router.post("/refresh")
@limiter.limit(RATE_LIMITS["auth_refresh"])
async def refresh_tokens(
    request: Request,
    db: DbSession,
    settings: Annotated[Settings, Depends(get_settings)]
):
    """✅ UPDATED: Refresh access token using refresh token (stateless)."""
    try:
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=401, detail="No refresh token provided")
        
        # ✅ Verify refresh token and get new token pair (no database lookup for token validation)
        new_tokens = service.refresh_token_pair(refresh_token, db, settings)
        
        # Create response
        response = JSONResponse(content={
            "access_token": new_tokens.access_token,
            "refresh_token": new_tokens.refresh_token,
            "token_type": new_tokens.token_type,
            "expires_in": new_tokens.expires_in
        })
        
        # Set new cookies
        response.set_cookie(
            key="access_token",
            value=new_tokens.access_token,
            httponly=True,
            secure=settings.is_production,
            samesite="lax",
            max_age=settings.access_token_expire_minutes * 60,
            path="/"
        )
        
        response.set_cookie(
            key="refresh_token",
            value=new_tokens.refresh_token,
            httponly=True,
            secure=settings.is_production,
            samesite="lax",
            max_age=settings.refresh_token_expire_days * 24 * 60 * 60,
            path="/"
        )
        
        return response
        
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        logging.error(f"Unexpected error in refresh_tokens: {str(e)}", exc_info=True)
        raise HTTPException(status_code=401, detail="Invalid refresh token")
