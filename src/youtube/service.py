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
<<<<<<< Updated upstream
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
=======
from fastapi import HTTPException
from typing import List, Optional
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import re
from .models import LikedVideo, TrendingVideo, CaptionsResponse, CaptionSegment, VocabResponse, VocabItem

YOUTUBE_API = "https://www.googleapis.com/youtube/v3"

# Simple in-memory cache for trending videos
_trending_cache = {}
_cache_expiry = {}

async def get_last_liked_video(google_access_token: str) -> LikedVideo:
    """
    Fetch the last video liked by the user using the YouTube Data API (async with httpx).
    """
    playlist_id = "LL"
    url = "https://www.googleapis.com/youtube/v3/playlistItems"
    params = {
        "part": "snippet",
        "playlistId": playlist_id,
        "maxResults": 1
    }
    headers = {
        "Authorization": f"Bearer {google_access_token}"
    }
    async with httpx.AsyncClient() as client:
        response = await client.get(url, params=params, headers=headers)
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to fetch liked videos")
    items = response.json().get("items", [])
    if not items:
        raise HTTPException(status_code=404, detail="No liked videos found")
    video = items[0]["snippet"]
    return LikedVideo(
        video_id=video["resourceId"]["videoId"],
        title=video["title"],
        description=video["description"],
        thumbnails=video["thumbnails"]
    )

async def get_trending_videos(
    api_key: str, 
    region: str = "US", 
    lang: Optional[str] = None, 
    max_results: int = 20
) -> List[TrendingVideo]:
    """
    Fetch trending videos by region, optionally filter by language.
    Uses 15-minute caching to reduce API quota usage.
    """
    cache_key = f"{region}_{lang}_{max_results}"
    
    # Check cache
    if cache_key in _trending_cache:
        if datetime.utcnow() < _cache_expiry[cache_key]:
            print(f"✅ Cache HIT for {cache_key}")
            return _trending_cache[cache_key]
    
    print(f"❌ Cache MISS for {cache_key} - calling YouTube API")
    
    # Call YouTube Data API
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.get(
            f"{YOUTUBE_API}/videos",
            params={
                "part": "snippet",
                "chart": "mostPopular",
                "regionCode": region,
                "maxResults": max_results,
                "key": api_key,
            },
        )
    
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    
    data = response.json()
    items = []
    
    for it in data.get("items", []):
        snippet = it.get("snippet", {})
        thumbnails = snippet.get("thumbnails", {})
        thumb = thumbnails.get("high", {}).get("url") or thumbnails.get("default", {}).get("url", "")
        
        video_lang = snippet.get("defaultAudioLanguage") or snippet.get("defaultLanguage")
        
        items.append(
            TrendingVideo(
                video_id=it["id"],
                title=snippet.get("title", ""),
                channel_title=snippet.get("channelTitle", ""),
                thumbnail=thumb,
                lang=video_lang,
            )
        )
    
    # Filter by language if provided
    if lang:
        items = [v for v in items if v.lang and v.lang.startswith(lang)]
    
    # Store in cache for 15 minutes
    _trending_cache[cache_key] = items
    _cache_expiry[cache_key] = datetime.utcnow() + timedelta(minutes=15)
    
    return items

async def get_captions(video_id: str, lang: Optional[str] = None) -> CaptionsResponse:
    """
    Fetch captions using youtube-transcript-api (unofficial but widely used).
    Uses the new API: YouTubeTranscriptApi().fetch(video_id, languages=[...])
    """
    try:
        from youtube_transcript_api import YouTubeTranscriptApi
        
        # Initialize the API
        ytt_api = YouTubeTranscriptApi()
        
        # Fetch transcript with optional language preference
        if lang:
            fetched_transcript = ytt_api.fetch(video_id, languages=[lang, 'en'])
        else:
            fetched_transcript = ytt_api.fetch(video_id)
        
        # Convert FetchedTranscript to our CaptionSegment format
        segments = [
            CaptionSegment(
                start=snippet.start, 
                duration=snippet.duration, 
                text=snippet.text
            ) 
            for snippet in fetched_transcript
        ]
        
        return CaptionsResponse(
            lang=fetched_transcript.language_code, 
            source="auto" if fetched_transcript.is_generated else "human", 
            segments=segments
        )
        
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"No captions available: {str(e)}")

async def extract_vocab(
    captions: CaptionsResponse, 
    lang: str, 
    top_n: int = 50
) -> VocabResponse:
    """
    Extract vocabulary from captions with frequency and examples.
    Basic tokenization - can be enhanced with spaCy later.
    """
    # Combine all caption text
    text = " ".join(s.text for s in captions.segments)
    
    # Tokenize (basic word splitting)
    tokens = [t.lower() for t in re.findall(r"\b\w+\b", text)]
    
    # Remove common stopwords (basic list)
    STOP = set("the a an and or to of in on for with is are was were i you he she it they we at be by as from this that these those my your his her its our their what which who whom when where why how can could would should may might must will do does did have has had am".split())
    filtered_tokens = [t for t in tokens if t not in STOP and len(t) > 2]
    
    # Count occurrences
    counts = Counter(filtered_tokens).most_common(top_n)
    
    # Build examples for each word
    examples = defaultdict(list)
    for seg in captions.segments:
        for t in re.findall(r"\b\w+\b", seg.text.lower()):
            if t in dict(counts) and len(examples[t]) < 3:
                examples[t].append({
                    "text": seg.text, 
                    "ts": seg.start
                })
    
    items = [
        VocabItem(lemma=word, count=count, examples=examples[word]) 
        for word, count in counts
    ]
    
    return VocabResponse(lang=lang, tokens=items)
>>>>>>> Stashed changes
