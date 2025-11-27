from pydantic import BaseModel
from typing import Optional, List

class LikedVideo(BaseModel):
    video_id: str
    title: str
    description: str
    thumbnails: dict

class TrendingVideo(BaseModel):
    video_id: str
    title: str
    description: str
    thumbnails: dict
    channel_title: str
    published_at: str

class TrendingVideosResponse(BaseModel):
    items: list[TrendingVideo]
    next_page_token: Optional[str]
    region: str
    category: Optional[str]

class Caption(BaseModel):
    """Individual caption entry with timestamp"""
    text: str
    start: float
    duration: float

class CaptionsResponse(BaseModel):
    """Response model for video captions"""
    video_id: str
    language: str
    captions: List[Caption]
