from fastapi import APIRouter, status, Request, Cookie
from uuid import UUID

from ..database.core import DbSession
from . import models
from . import service
from ..auth.service import CurrentUser, verify_token
from ..config import get_settings

router = APIRouter(
    prefix="/users",
    tags=["Users"]
)


@router.get("/me", response_model=models.UserResponse)
def get_current_user(
    current_user: CurrentUser = None,
    db: DbSession = None,
    auth_token: str = Cookie(default=None),
    request: Request = None
):
    # Try to get user from Authorization header (JWT in Bearer)
    if current_user:
        return service.get_user_by_id(db, current_user.get_uuid())
    # If not, try to get user from httpOnly cookie (Google login)
    if auth_token:
        settings = get_settings()
        token_data = verify_token(auth_token, settings.jwt_secret_key, settings.algorithm)
        return service.get_user_by_id(db, UUID(token_data.user_id))
    # If neither, unauthorized
    return {"error": "Not authenticated"}


@router.put("/change-password", status_code=status.HTTP_200_OK)
def change_password(
    password_change: models.PasswordChange,
    db: DbSession,
    current_user: CurrentUser
):
    service.change_password(db, current_user.get_uuid(), password_change)
