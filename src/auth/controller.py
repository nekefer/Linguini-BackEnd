from typing import Annotated
from datetime import timedelta
from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import JSONResponse
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
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
                                 db: DbSession,
                                 settings: Annotated[Settings, Depends(get_settings)]):
    
    return service.login_for_access_token(form_data, db, settings)

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
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info = token.get("userinfo") or {}
        google_access_token = token.get("access_token")
       
        # Use your service to authenticate or register the user
        jwt_token = service.google_authenticate_user(db, user_info, settings)
        print("user_info:", user_info)
        print('token:', token)
        # return {
        #     "access_token": jwt_token.access_token,
        #     "token_type": jwt_token.token_type,
        #     "google_access_token": google_access_token  # <-- Add this for testing
        # }
        return token
    except Exception as e:
        import traceback
        print("Error:", traceback.format_exc())
        return {"error": str(e)}


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


# @router.post("/logout")
# async def logout():
#     """Logout endpoint."""
#     return {"message": "Successfully logged out"}







