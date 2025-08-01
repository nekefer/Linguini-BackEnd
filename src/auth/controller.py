from typing import Annotated
from datetime import timedelta
from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse
from starlette import status
from . import  models
from . import service
from fastapi.security import OAuth2PasswordRequestForm
from ..database.core import DbSession
from ..rate_limiter import limiter
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
@limiter.limit("5/hour")
async def register_user(request: Request, db: DbSession,
                      register_user_request: models.RegisterUserRequest):
    service.register_user(db, register_user_request)


@router.post("/token", response_model=models.Token)
async def login_for_access_token(
    request: Request,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: DbSession,
    settings: Annotated[Settings, Depends(get_settings)]
):
    """Login endpoint that sets both access and refresh tokens."""
    token_data = service.login_for_access_token(form_data, db, settings)
    
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
async def google_login(request: Request):
    """Redirect to Google OAuth with intent parameter."""
    redirect_uri = request.url_for('google_auth')
    
    # Get intent from query parameter (login or register)
    intent = request.query_params.get("intent", "login")
    
    # Create state parameter with intent
    state = f"intent={intent}"
    
    return await oauth.google.authorize_redirect(request, redirect_uri=redirect_uri, state=state)


# Handle the OAuth callback from Google
@router.get("/google/callback")
async def google_auth(
    request: Request,
    db: DbSession,
    settings: Annotated[Settings, Depends(get_settings)]
):
    """Handle Google OAuth callback and set JWT token in HttpOnly cookie."""
    try:
        # Get token from Google
        token = await oauth.google.authorize_access_token(request)
        user_info = token.get("userinfo") or {}
        
        if not user_info:
            raise AuthenticationError("Google OAuth failed - no user info received")
        
        # Extract user info from the user_info dict
        user_email = user_info.get("email", "")
        
        # Check if user exists BEFORE calling the authentication service
        existing_user = db.query(User).filter(User.email == user_email).first()
        is_new_user = existing_user is None
        
        # Get the intent from the state parameter (login vs register)
        state = request.query_params.get("state", "")
        intent = "login"  # Default to login
        
        # Extract intent from state if available
        if "intent=" in state:
            try:
                intent = state.split("intent=")[1].split("&")[0]
            except:
                intent = "login"
        
        # Handle the case where user exists but is trying to register
        if existing_user and intent == "register":
            # User already exists, redirect to login page with error
            error_url = f"{settings.frontend_url}/login?error=user_exists"
            return RedirectResponse(url=error_url)
        
        # Handle the case where user doesn't exist but is trying to login
        if not existing_user and intent == "login":
            # User doesn't exist, redirect to register page with error
            error_url = f"{settings.frontend_url}/register?error=user_not_found"
            return RedirectResponse(url=error_url)
        
        # Now proceed with authentication/registration
        jwt_token = service.google_authenticate_user(db, user_info, settings)
        
        # Create response with redirect to frontend
        # Redirect to different pages based on whether it's a new user
        if is_new_user:
            redirect_url = f"{settings.frontend_url}/"  # Root page for new users
        else:
            redirect_url = f"{settings.frontend_url}/dashboard"  # Dashboard for existing users
        
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
        
        # Set user info in a separate cookie
        response.set_cookie(
            key="user_email",
            value=user_email,
            httponly=False,  # Allow JavaScript access for display
            secure=settings.is_production,
            samesite="lax",
            max_age=3600,
            path="/"
        )
        
        # Set user type cookie (new vs existing)
        response.set_cookie(
            key="user_type",
            value="new" if is_new_user else "existing",
            httponly=False,
            secure=settings.is_production,
            samesite="lax",
            max_age=3600,
            path="/"
        )
        
        return response
        
    except Exception as e:
        logging.error(f"Google OAuth error: {str(e)}")
        error_url = f"{settings.frontend_url}/?error=oauth_failed"
        return RedirectResponse(url=error_url)


@router.get("/me", response_model=models.UserResponse)
async def get_current_user_info(current_user: service.CurrentUser, db: DbSession):
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
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to get user information")


@router.post("/logout")
async def logout(request: Request, db: DbSession, settings: Annotated[Settings, Depends(get_settings)]):
    """Logout endpoint - revokes refresh token and clears all cookies."""
    try:
        # Get refresh token from cookie
        refresh_token = request.cookies.get("refresh_token")
        
        # Revoke refresh token if it exists
        if refresh_token:
            service.revoke_refresh_token(refresh_token, db)
        
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
        
        response.delete_cookie(
            key="user_email",
            path="/",
            secure=settings.is_production,
            httponly=False,
            samesite="lax"
        )
        
        response.delete_cookie(
            key="user_type",
            path="/",
            secure=settings.is_production,
            httponly=False,
            samesite="lax"
        )
        
        return response
        
    except Exception as e:
        # Even if revocation fails, still clear cookies
        response = JSONResponse(content={"message": "Logged out (some cleanup failed)"})
        
        # Clear cookies anyway
        response.delete_cookie(key="access_token", path="/")
        response.delete_cookie(key="refresh_token", path="/")
        response.delete_cookie(key="user_email", path="/")
        response.delete_cookie(key="user_type", path="/")
        
        return response


@router.put("/change-password", status_code=status.HTTP_200_OK)
async def change_password(
    password_change: models.PasswordChange,
    db: DbSession,
    current_user: service.CurrentUser
):
    """Change user password. Requires authentication."""
    try:
        service.change_password(db, current_user.get_uuid(), password_change)
        return {"message": "Password changed successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/refresh")
async def refresh_tokens(
    request: Request,
    db: DbSession,
    settings: Annotated[Settings, Depends(get_settings)]
):
    """Refresh access token using refresh token."""
    try:
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=401, detail="No refresh token provided")
        
        # Verify refresh token and get new token pair
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
        
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid refresh token")






