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
from ..users.service import get_user_by_id
from .google.oauth_config import oauth  # fixed import
from ..config import get_settings, Settings

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
    """Login endpoint that also sets HttpOnly cookies for consistency."""
    token_data = service.login_for_access_token(form_data, db, settings)
    
    # Create response with token data
    response = JSONResponse(content={
        "access_token": token_data.access_token,
        "token_type": token_data.token_type
    })
    
    # Set JWT token in HttpOnly cookie for consistency
    response.set_cookie(
        key="access_token",
        value=token_data.access_token,
        httponly=True,
        secure=False,  # Set to True in production with HTTPS
        samesite="lax",
        max_age=3600,  # 1 hour
        path="/"
    )
    
    return response

@router.get("/google/login")
async def google_login(request: Request):
    redirect_uri = request.url_for('google_auth')
    # print("LOGIN COOKIES:", request.cookies)
    return await oauth.google.authorize_redirect(request, redirect_uri=redirect_uri)


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
        
        # Authenticate or register user
        auth_result = service.google_authenticate_user(db, user_info, settings)
        jwt_token = auth_result["token"]
        user_data = auth_result["user"]
        is_new_user = auth_result["is_new_user"]
        
        # Create response with redirect to frontend
        # Redirect to different pages based on whether it's a new user
        if is_new_user:
            redirect_url = "http://localhost:5173/welcome"  # Welcome page for new users
        else:
            redirect_url = "http://localhost:5173/dashboard"  # Dashboard for existing users
        
        response = RedirectResponse(url=redirect_url)
        
        # Set JWT token in HttpOnly cookie
        response.set_cookie(
            key="access_token",
            value=jwt_token.access_token,
            httponly=True,
            secure=False,  # Set to True in production with HTTPS
            samesite="lax",
            max_age=3600,  # 1 hour
            path="/"
        )
        
        # Set user info in a separate cookie
        response.set_cookie(
            key="user_email",
            value=user_data["email"],
            httponly=False,  # Allow JavaScript access for display
            secure=False,
            samesite="lax",
            max_age=3600,
            path="/"
        )
        
        # Set user type cookie (new vs existing)
        response.set_cookie(
            key="user_type",
            value="new" if is_new_user else "existing",
            httponly=False,
            secure=False,
            samesite="lax",
            max_age=3600,
            path="/"
        )
        
        return response
        
    except AuthenticationError as e:
        # Redirect to frontend with error
        error_param = urllib.parse.quote(str(e.detail))
        redirect_url = f"http://localhost:5173/?error={error_param}"
        return RedirectResponse(url=redirect_url)
        
    except Exception as e:
        print(f"Google OAuth error: {str(e)}")
        # Redirect to frontend with error
        error_param = urllib.parse.quote("Google OAuth failed")
        redirect_url = f"http://localhost:5173/?error={error_param}"
        return RedirectResponse(url=redirect_url)


@router.get("/me", response_model=models.UserResponse)
async def get_current_user_info(current_user: service.CurrentUser, db: DbSession):
    """Get current user information."""
    try:
        user_id = current_user.get_uuid()
        if not user_id:
            raise AuthenticationError("Invalid user token")
        
        user = get_user_by_id(db, user_id)
        
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
async def logout():
    """Logout endpoint - clears HttpOnly cookies."""
    response = JSONResponse(content={"message": "Successfully logged out"})
    
    # Clear the JWT token cookie
    response.delete_cookie(
        key="access_token",
        path="/"
    )
    
    # Clear the user email cookie
    response.delete_cookie(
        key="user_email",
        path="/"
    )
    
    # Clear the user type cookie
    response.delete_cookie(
        key="user_type",
        path="/"
    )
    
    return response







