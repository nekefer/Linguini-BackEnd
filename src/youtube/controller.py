from fastapi import APIRouter, Query, Depends, HTTPException, Request
from typing import List, Optional
from ..auth.service import CurrentUser
from ..database.core import DbSession
from ..rate_limiter import limiter
from .service import YouTubeService, YouTubeDatabaseService
from ..entities.video import Video
from ..entities.playlist import Playlist
from ..entities.user_video_history import UserVideoHistory
import logging

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/youtube",
    tags=["youtube"]
)


@router.get("/liked-videos")
@limiter.limit("30/minute")  # Rate limiting for YouTube API calls
async def get_liked_videos(
    request: Request,
    current_user: CurrentUser,
    db: DbSession,
    google_access_token: str = Query(..., description="Google OAuth access token"),
    max_results: int = Query(50, description="Maximum number of videos to return")
):
    """
    Get user's liked videos from YouTube.
    Requires authentication and Google OAuth token.
    """
    try:
        # Initialize YouTube service
        youtube_service = YouTubeService(google_access_token)
        db_service = YouTubeDatabaseService(db)
        
        # Get liked videos from YouTube API
        liked_videos_data = await youtube_service.get_user_liked_videos(max_results)
        
        # Save videos to database
        saved_videos = await db_service.save_videos_batch(liked_videos_data)
        
        # Convert to response format
        videos_response = [video.to_dict() for video in saved_videos]
        
        logger.info(f"Retrieved {len(videos_response)} liked videos for user {current_user.get_uuid()}")
        
        return {
            "videos": videos_response,
            "total_count": len(videos_response),
            "message": "Liked videos retrieved successfully"
        }
        
    except Exception as e:
        logger.error(f"Error retrieving liked videos: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve liked videos: {str(e)}")


@router.get("/video/{video_id}")
@limiter.limit("60/minute")
async def get_video_details(
    request: Request,
    video_id: str,
    current_user: CurrentUser,
    google_access_token: str = Query(..., description="Google OAuth access token")
):
    """
    Get detailed information about a specific video.
    """
    try:
        youtube_service = YouTubeService(google_access_token)
        video_data = await youtube_service.get_video_details(video_id)
        
        if not video_data:
            raise HTTPException(status_code=404, detail="Video not found")
        
        return {
            "video": video_data,
            "message": "Video details retrieved successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving video details for {video_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve video details: {str(e)}")


@router.get("/search")
@limiter.limit("30/minute")
async def search_videos(
    request: Request,
    current_user: CurrentUser,
    google_access_token: str = Query(..., description="Google OAuth access token"),
    query: str = Query(..., description="Search query"),
    max_results: int = Query(25, description="Maximum number of results")
):
    """
    Search for videos on YouTube.
    """
    try:
        youtube_service = YouTubeService(google_access_token)
        videos_data = await youtube_service.search_videos(query, max_results)
        
        return {
            "videos": videos_data,
            "total_count": len(videos_data),
            "query": query,
            "message": "Search completed successfully"
        }
        
    except Exception as e:
        logger.error(f"Error searching videos for query '{query}': {e}")
        raise HTTPException(status_code=500, detail=f"Failed to search videos: {str(e)}")


@router.get("/playlists")
@limiter.limit("30/minute")
async def get_user_playlists(
    request: Request,
    current_user: CurrentUser,
    google_access_token: str = Query(..., description="Google OAuth access token"),
    max_results: int = Query(50, description="Maximum number of playlists")
):
    """
    Get user's YouTube playlists.
    """
    try:
        youtube_service = YouTubeService(google_access_token)
        playlists_data = await youtube_service.get_user_playlists(max_results)
        
        return {
            "playlists": playlists_data,
            "total_count": len(playlists_data),
            "message": "Playlists retrieved successfully"
        }
        
    except Exception as e:
        logger.error(f"Error retrieving playlists: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve playlists: {str(e)}")


@router.get("/playlist/{playlist_id}/videos")
@limiter.limit("30/minute")
async def get_playlist_videos(
    request: Request,
    playlist_id: str,
    current_user: CurrentUser,
    google_access_token: str = Query(..., description="Google OAuth access token"),
    max_results: int = Query(50, description="Maximum number of videos")
):
    """
    Get videos from a specific playlist.
    """
    try:
        youtube_service = YouTubeService(google_access_token)
        videos_data = await youtube_service.get_playlist_videos(playlist_id, max_results)
        
        return {
            "videos": videos_data,
            "playlist_id": playlist_id,
            "total_count": len(videos_data),
            "message": "Playlist videos retrieved successfully"
        }
        
    except Exception as e:
        logger.error(f"Error retrieving playlist videos for {playlist_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve playlist videos: {str(e)}")


@router.post("/video/{video_id}/track")
@limiter.limit("100/minute")
async def track_video_interaction(
    request: Request,
    video_id: str,
    current_user: CurrentUser,
    db: DbSession,
    watch_time: int = Query(0, description="Watch time in seconds"),
    is_liked: bool = Query(False, description="Whether user liked the video")
):
    """
    Track user interaction with a video.
    """
    try:
        db_service = YouTubeDatabaseService(db)
        
        # Find video in database
        video = db.query(Video).filter(Video.youtube_id == video_id).first()
        if not video:
            raise HTTPException(status_code=404, detail="Video not found in database")
        
        # Track interaction
        history = await db_service.track_video_interaction(
            user_id=str(current_user.get_uuid()),
            video_id=str(video.id),
            watch_time=watch_time,
            is_liked=is_liked
        )
        
        return {
            "interaction": history.to_dict(),
            "message": "Video interaction tracked successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error tracking video interaction: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to track video interaction: {str(e)}")


@router.get("/user/history")
@limiter.limit("60/minute")
async def get_user_video_history(
    request: Request,
    current_user: CurrentUser,
    db: DbSession,
    limit: int = Query(50, description="Maximum number of history items")
):
    """
    Get user's video interaction history.
    """
    try:
        user_id = str(current_user.get_uuid())
        
        # Get user's video history
        history = db.query(UserVideoHistory).filter(
            UserVideoHistory.user_id == user_id
        ).order_by(UserVideoHistory.last_watched_at.desc()).limit(limit).all()
        
        history_data = [item.to_dict() for item in history]
        
        return {
            "history": history_data,
            "total_count": len(history_data),
            "message": "Video history retrieved successfully"
        }
        
    except Exception as e:
        logger.error(f"Error retrieving video history: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve video history: {str(e)}")
