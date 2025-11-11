import httpx
import asyncio
from typing import Optional
from fastapi import HTTPException
from cachetools import TTLCache
from .models import LikedVideo, TrendingVideo, TrendingVideosResponse
from ..config import get_settings

# Cache for trending videos (15-minute TTL, max 128 entries)
_TRENDING_CACHE = TTLCache(maxsize=128, ttl=900)

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
    region: str = "US",
    max_results: int = 25,
    page_token: Optional[str] = None,
    category_id: Optional[str] = None
) -> TrendingVideosResponse:
    """
    Fetch trending videos from YouTube Data API v3.
    Uses in-memory caching with 15-minute TTL.
    
    Args:
        region: ISO 3166-1 alpha-2 country code (e.g., "US", "GB", "JP")
        max_results: Number of results to return (1-50)
        page_token: Token for pagination
        category_id: Optional category filter (e.g., "10" for Music)
    
    Returns:
        TrendingVideosResponse with items, pagination token, and metadata
    """
    settings = get_settings()
    
    # Generate cache key as a tuple to avoid collisions
    # (prevents "None" string from conflicting with None value)
    cache_key = (region, max_results, page_token, category_id)
    
    # Check cache (TTLCache handles expiration automatically)
    if cache_key in _TRENDING_CACHE:
        return _TRENDING_CACHE[cache_key]
    
    # Build request
    url = "https://www.googleapis.com/youtube/v3/videos"
    params = {
        "part": "snippet",
        "chart": "mostPopular",
        "regionCode": region,
        "maxResults": min(max_results, 50),
        "key": settings.youtube_api_key
    }
    
    if page_token:
        params["pageToken"] = page_token
    if category_id:
        params["videoCategoryId"] = category_id
    
    # Make API request with retry logic (reuse a single HTTP client)
    max_retries = 3
    retry_delay = 1.5

    async with httpx.AsyncClient() as client:
        for attempt in range(max_retries):
            try:
                response = await client.get(url, params=params, timeout=10.0)

                if response.status_code == 200:
                    data = response.json()

                    # Parse videos
                    videos = []
                    for item in data.get("items", []):
                        snippet = item["snippet"]
                        videos.append(TrendingVideo(
                            video_id=item["id"],
                            title=snippet["title"],
                            description=snippet["description"],
                            thumbnails=snippet["thumbnails"],
                            channel_title=snippet["channelTitle"],
                            published_at=snippet["publishedAt"]
                        ))

                    # Build response
                    result = TrendingVideosResponse(
                        items=videos,
                        next_page_token=data.get("nextPageToken"),
                        region=region,
                        category=category_id
                    )

                    # Cache result (TTLCache handles expiration and size limits)
                    _TRENDING_CACHE[cache_key] = result

                    return result

                elif response.status_code == 429:  # Rate limit
                    if attempt < max_retries - 1:
                        await asyncio.sleep(retry_delay)
                        retry_delay *= 2
                        continue
                    else:
                        raise HTTPException(
                            status_code=429,
                            detail="YouTube API rate limit exceeded. Please try again later."
                        )

                else:
                    raise HTTPException(
                        status_code=response.status_code,
                        detail=f"YouTube API error: {response.text}"
                    )

            except httpx.RequestError as e:
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 2
                    continue
                else:
                    raise HTTPException(
                        status_code=503,
                        detail=f"Failed to connect to YouTube API: {str(e)}"
                    )
    
    # Should never reach here, but just in case
    raise HTTPException(status_code=500, detail="Unexpected error fetching trending videos")
