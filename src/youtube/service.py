"""
YouTube service for interacting with YouTube Data API v3.
"""
import logging
from typing import List, Dict, Optional, Any
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
import httpx
from datetime import datetime, timedelta

from ..config import get_settings
from ..entities.video import Video
from ..entities.playlist import Playlist
from ..entities.user_video_history import UserVideoHistory
from ..database.core import DbSession

logger = logging.getLogger(__name__)


class YouTubeService:
    """Service for YouTube Data API v3 operations."""
    
    def __init__(self, access_token: str):
        """Initialize YouTube service with access token."""
        self.access_token = access_token
        self.settings = get_settings()
        
        # Create credentials object
        self.credentials = Credentials(
            token=access_token,
            refresh_token=None,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=self.settings.google_client_id,
            client_secret=self.settings.google_client_secret
        )
        
        # Build YouTube service
        self.youtube = build('youtube', 'v3', credentials=self.credentials)
    
    async def get_user_liked_videos(self, max_results: int = 50) -> List[Dict[str, Any]]:
        """Get user's liked videos from YouTube."""
        try:
            # Get liked videos from YouTube
            request = self.youtube.videos().list(
                part="snippet,statistics,contentDetails",
                myRating="like",
                maxResults=max_results
            )
            
            response = request.execute()
            
            liked_videos = []
            for item in response.get('items', []):
                video_data = self._extract_video_data(item)
                liked_videos.append(video_data)
            
            logger.info(f"Retrieved {len(liked_videos)} liked videos")
            return liked_videos
            
        except Exception as e:
            logger.error(f"Error fetching liked videos: {e}")
            raise Exception(f"Failed to fetch liked videos: {str(e)}")
    
    async def get_video_details(self, video_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific video."""
        try:
            request = self.youtube.videos().list(
                part="snippet,statistics,contentDetails",
                id=video_id
            )
            
            response = request.execute()
            
            if not response.get('items'):
                return None
            
            video_data = self._extract_video_data(response['items'][0])
            return video_data
            
        except Exception as e:
            logger.error(f"Error fetching video details for {video_id}: {e}")
            raise Exception(f"Failed to fetch video details: {str(e)}")
    
    async def search_videos(self, query: str, max_results: int = 25) -> List[Dict[str, Any]]:
        """Search for videos on YouTube."""
        try:
            request = self.youtube.search().list(
                part="snippet",
                q=query,
                type="video",
                maxResults=max_results,
                order="relevance"
            )
            
            response = request.execute()
            
            videos = []
            for item in response.get('items', []):
                # Get additional video details
                video_id = item['id']['videoId']
                video_details = await self.get_video_details(video_id)
                if video_details:
                    videos.append(video_details)
            
            logger.info(f"Found {len(videos)} videos for query: {query}")
            return videos
            
        except Exception as e:
            logger.error(f"Error searching videos for query '{query}': {e}")
            raise Exception(f"Failed to search videos: {str(e)}")
    
    async def get_user_playlists(self, max_results: int = 50) -> List[Dict[str, Any]]:
        """Get user's YouTube playlists."""
        try:
            request = self.youtube.playlists().list(
                part="snippet,contentDetails",
                mine=True,
                maxResults=max_results
            )
            
            response = request.execute()
            
            playlists = []
            for item in response.get('items', []):
                playlist_data = self._extract_playlist_data(item)
                playlists.append(playlist_data)
            
            logger.info(f"Retrieved {len(playlists)} playlists")
            return playlists
            
        except Exception as e:
            logger.error(f"Error fetching playlists: {e}")
            raise Exception(f"Failed to fetch playlists: {str(e)}")
    
    async def get_playlist_videos(self, playlist_id: str, max_results: int = 50) -> List[Dict[str, Any]]:
        """Get videos from a specific playlist."""
        try:
            request = self.youtube.playlistItems().list(
                part="snippet",
                playlistId=playlist_id,
                maxResults=max_results
            )
            
            response = request.execute()
            
            videos = []
            for item in response.get('items', []):
                video_id = item['snippet']['resourceId']['videoId']
                video_details = await self.get_video_details(video_id)
                if video_details:
                    videos.append(video_details)
            
            logger.info(f"Retrieved {len(videos)} videos from playlist {playlist_id}")
            return videos
            
        except Exception as e:
            logger.error(f"Error fetching playlist videos for {playlist_id}: {e}")
            raise Exception(f"Failed to fetch playlist videos: {str(e)}")
    
    def _extract_video_data(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Extract video data from YouTube API response."""
        snippet = item.get('snippet', {})
        statistics = item.get('statistics', {})
        content_details = item.get('contentDetails', {})
        
        # Extract thumbnails
        thumbnails = snippet.get('thumbnails', {})
        
        return {
            'youtube_id': item['id'],
            'title': snippet.get('title', ''),
            'description': snippet.get('description', ''),
            'thumbnail_url': thumbnails.get('default', {}).get('url', ''),
            'thumbnail_medium_url': thumbnails.get('medium', {}).get('url', ''),
            'thumbnail_high_url': thumbnails.get('high', {}).get('url', ''),
            'duration': content_details.get('duration', ''),
            'published_at': datetime.fromisoformat(snippet.get('publishedAt', '').replace('Z', '+00:00')),
            'view_count': int(statistics.get('viewCount', 0)),
            'like_count': int(statistics.get('likeCount', 0)),
            'comment_count': int(statistics.get('commentCount', 0)),
            'channel_id': snippet.get('channelId', ''),
            'channel_title': snippet.get('channelTitle', ''),
            'category_id': snippet.get('categoryId', ''),
            'tags': snippet.get('tags', []),
            'privacy_status': snippet.get('privacyStatus', 'public')
        }
    
    def _extract_playlist_data(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Extract playlist data from YouTube API response."""
        snippet = item.get('snippet', {})
        content_details = item.get('contentDetails', {})
        
        thumbnails = snippet.get('thumbnails', {})
        
        return {
            'youtube_id': item['id'],
            'title': snippet.get('title', ''),
            'description': snippet.get('description', ''),
            'thumbnail_url': thumbnails.get('default', {}).get('url', ''),
            'item_count': int(content_details.get('itemCount', 0)),
            'privacy_status': snippet.get('privacyStatus', 'private')
        }


class YouTubeDatabaseService:
    """Service for managing YouTube data in the database."""
    
    def __init__(self, db: DbSession):
        self.db = db
    
    async def save_video(self, video_data: Dict[str, Any]) -> Video:
        """Save or update video in database."""
        # Check if video already exists
        existing_video = self.db.query(Video).filter(
            Video.youtube_id == video_data['youtube_id']
        ).first()
        
        if existing_video:
            # Update existing video
            for key, value in video_data.items():
                if hasattr(existing_video, key):
                    setattr(existing_video, key, value)
            existing_video.updated_at = datetime.utcnow()
            self.db.commit()
            return existing_video
        else:
            # Create new video
            video = Video(**video_data)
            self.db.add(video)
            self.db.commit()
            self.db.refresh(video)
            return video
    
    async def save_videos_batch(self, videos_data: List[Dict[str, Any]]) -> List[Video]:
        """Save multiple videos in batch."""
        saved_videos = []
        
        for video_data in videos_data:
            video = await self.save_video(video_data)
            saved_videos.append(video)
        
        return saved_videos
    
    async def get_user_liked_videos_from_db(self, user_id: str, limit: int = 50) -> List[Video]:
        """Get user's liked videos from database."""
        # This would need to be implemented based on your specific requirements
        # For now, return all videos (you might want to implement user-specific logic)
        videos = self.db.query(Video).limit(limit).all()
        return videos
    
    async def track_video_interaction(self, user_id: str, video_id: str, 
                                   watch_time: int = 0, is_liked: bool = False) -> UserVideoHistory:
        """Track user interaction with a video."""
        # Check if interaction already exists
        existing_history = self.db.query(UserVideoHistory).filter(
            UserVideoHistory.user_id == user_id,
            UserVideoHistory.video_id == video_id
        ).first()
        
        if existing_history:
            # Update existing history
            existing_history.watch_time_seconds += watch_time
            existing_history.last_watched_at = datetime.utcnow()
            if is_liked:
                existing_history.is_liked = True
                existing_history.liked_at = datetime.utcnow()
            self.db.commit()
            return existing_history
        else:
            # Create new history
            history = UserVideoHistory(
                user_id=user_id,
                video_id=video_id,
                watch_time_seconds=watch_time,
                is_liked=is_liked,
                liked_at=datetime.utcnow() if is_liked else None
            )
            self.db.add(history)
            self.db.commit()
            self.db.refresh(history)
            return history