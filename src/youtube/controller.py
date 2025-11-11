from fastapi import APIRouter, Cookie, HTTPException, Query
from typing import Optional
from .service import get_last_liked_video, get_trending_videos
from .models import LikedVideo, TrendingVideosResponse
from ..auth.service import CurrentUser

router = APIRouter(
    prefix="/youtube",
    tags=["youtube"]
)

@router.get("/trending", response_model=TrendingVideosResponse)
async def trending_videos(
    region: str = Query(default="US", description="ISO 3166-1 alpha-2 country code"),
    max_results: int = Query(default=25, ge=1, le=50, description="Number of results (1-50)"),
    page_token: Optional[str] = Query(default=None, description="Pagination token"),
    category_id: Optional[str] = Query(default=None, description="Category ID (e.g., '10' for Music)")
):
    """
    PUBLIC: Get trending videos from YouTube.
    No authentication required - uses API key.
    Results are cached for 15 minutes.
    """
    return await get_trending_videos(
        region=region,
        max_results=max_results,
        page_token=page_token,
        category_id=category_id
    )


@router.get("/last-liked-video", response_model=LikedVideo)
async def last_liked_video(
    current_user: CurrentUser,
    google_access_token: Optional[str] = Cookie(None)
):
    """
    SECURE: Endpoint to get the last video liked by the user.
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
