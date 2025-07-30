from fastapi import APIRouter, status, HTTPException
from uuid import UUID

from ..database.core import DbSession
from . import models
from . import service
from ..auth.service import CurrentUser

router = APIRouter(
    prefix="/users",
    tags=["Users"]
)


@router.get("/me", response_model=models.UserResponse)
def get_current_user(
    current_user: CurrentUser,  # ✅ Required dependency (not optional)
    db: DbSession
):
    """
    Get current user information.
    Requires authentication.
    """
    try:
        user_id = current_user.get_uuid()
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid user token")
        
        return service.get_user_by_id(db, user_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to get user information")


@router.put("/change-password", status_code=status.HTTP_200_OK)
def change_password(
    password_change: models.PasswordChange,
    db: DbSession,
    current_user: CurrentUser  # ✅ Already protected
):
    """
    Change user password.
    Requires authentication.
    """
    try:
        service.change_password(db, current_user.get_uuid(), password_change)
        return {"message": "Password changed successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
