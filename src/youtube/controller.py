from fastapi import APIRouter, Cookie, HTTPException, Query, Depends
from typing import Optional, Annotated
from .service import get_last_liked_video, get_trending_videos
from .models import LikedVideo, TrendingVideosResponse
from ..auth.service import CurrentUser, get_valid_google_token
from ..database.core import get_db
from sqlalchemy.orm import Session
from ..config import get_settings, Settings

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
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)]
):
    """
    SECURE: Endpoint to get the last video liked by the user.
    Automatically refreshes Google token if expired.
    """
    # Validate user is authenticated (JWT check)
    if not current_user.get_uuid():
        raise HTTPException(status_code=401, detail="User not authenticated")
    
    try:
        # Get fresh Google token (auto-refreshes if needed)
        google_token = get_valid_google_token(db, current_user.get_uuid(), settings)
        
        # Fetch and return the last liked video
        return await get_last_liked_video(google_token)
        
    except Exception as e:
        if "No Google" in str(e) or "reconnect" in str(e):
            raise HTTPException(
                status_code=400, 
                detail="Google account not connected. Please sign in with Google."
            )
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch liked video: {str(e)}"
        )
