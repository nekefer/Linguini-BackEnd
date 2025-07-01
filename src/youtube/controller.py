from fastapi import APIRouter, Query
from .service import get_last_liked_video
from .models import LikedVideo

router = APIRouter(
    prefix="/youtube",
    tags=["youtube"]
)

@router.get("/last-liked-video", response_model=LikedVideo)
async def last_liked_video(google_access_token: str = Query(..., description="Google OAuth access token")):
    """
    Endpoint to get the last video liked by the user.
    """
    return await get_last_liked_video(google_access_token)
