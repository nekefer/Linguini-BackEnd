from typing import Annotated
from datetime import timedelta
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from starlette import status
from . import  models
from . import service
from fastapi.security import OAuth2PasswordRequestForm
from ..database.core import DbSession
from ..rate_limiter import limiter
from .google.oauth_config import oauth  # fixed import
from .google.config import Settings    # fixed import
from functools import lru_cache
from dotenv import load_dotenv

load_dotenv()

router = APIRouter(
    prefix='/auth',
    tags=['auth']
)

@lru_cache
def get_settings():
    return Settings()

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
       
        # Use your service to authenticate or register the user
        jwt_token = service.google_authenticate_user(db, user_info, settings)
        print("user_info:", user_info)
        return {"access_token": jwt_token.access_token, "token_type": jwt_token.token_type}
    except Exception as e:
        import traceback
        print("Error:", traceback.format_exc())
        return {"error": str(e)}







