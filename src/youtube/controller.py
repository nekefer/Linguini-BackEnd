from fastapi import APIRouter, Query, Depends, HTTPException
from .service import get_last_liked_video
from .models import LikedVideo
from ..auth.service import CurrentUser
from ..database.core import DbSession

router = APIRouter(
    prefix="/youtube",
    tags=["youtube"]
)

@router.get("/last-liked-video", response_model=LikedVideo)
async def last_liked_video(
    current_user: CurrentUser,  # ✅ Add authentication dependency
    db: DbSession,
    google_access_token: str = Query(..., description="Google OAuth access token")
):
    """
    Endpoint to get the last video liked by the user.
    Requires authentication.
    """
    # Verify user is authenticated
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    return await get_last_liked_video(google_access_token)
