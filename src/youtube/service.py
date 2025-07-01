import httpx
from fastapi import HTTPException
from .models import LikedVideo

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
