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
from ..auth.oauth_config import oauth
from ..utils.config import Settings
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
                                 db: DbSession):
    return service.login_for_access_token(form_data, db)

@router.get("/google/login")
async def google_login(request: Request):
    redirect_uri = request.url_for('google_auth')
    return await oauth.google.authorize_redirect(request, redirect_uri=redirect_uri)


# @router.get("/google/callback")
# async def google_auth(request: Request):
#     token = await oauth.google.authorize_access_token(request)
#     user = await oauth.google.parse_id_token(request, token)

#     return JSONResponse(content={"user":user})


# Handle the OAuth callback from Google
@router.get("/google/callback")
async def google_auth(request: Request,settings: Annotated[Settings, Depends(get_settings)]):
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info = token.get("userinfo") or {}

        # Extract user details
        username = user_info.get("email")  # Use email as username
        print("User Info:", user_info)  # Debugging step

        # Generate a JWT token with auth_method="google"
        access_token = service.create_access_token(
            username,
            109,
            expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        )

        return {"access_token": access_token, "token": token}
    except Exception as e:
        import traceback
        print("Error:", traceback.format_exc())  # Debugging step
        return {"error": str(e)}







