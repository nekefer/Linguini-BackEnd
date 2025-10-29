from fastapi import APIRouter, Cookie, HTTPException
from typing import Optional
from .service import get_last_liked_video
from .models import LikedVideo
from ..auth.service import CurrentUser

router = APIRouter(
    prefix="/youtube",
    tags=["youtube"]
)

@router.get("/last-liked-video", response_model=LikedVideo)
async def last_liked_video(
    current_user: CurrentUser,
    google_access_token: Optional[str] = Cookie(None)
):
    """
    ✅ SECURE: Endpoint to get the last video liked by the user.
    Reads Google access token from HttpOnly cookie (frontend never sees it).
    """
    # Validate user is authenticated (JWT check)
    if not current_user.get_uuid():
        raise HTTPException(status_code=401, detail="User not authenticated")
    
    # Check if Google token exists in cookie
    if not google_access_token:
        raise HTTPException(
            status_code=400, 
            detail="No Google access token found. Please sign in with Google to access YouTube features."
        )
    
    # Fetch and return the last liked video
    return await get_last_liked_video(google_access_token)
