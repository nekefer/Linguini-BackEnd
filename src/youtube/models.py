from pydantic import BaseModel
from typing import List, Optional

class LikedVideo(BaseModel):
    video_id: str
    title: str
    description: str
    thumbnails: dict

class TrendingVideo(BaseModel):
    """Model for trending video data"""
    video_id: str
    title: str
    channel_title: str
    thumbnail: str
    lang: Optional[str] = None

class CaptionSegment(BaseModel):
    """Model for a single caption segment with timing"""
    start: float
    duration: float
    text: str

class CaptionsResponse(BaseModel):
    """Model for caption response with metadata"""
    lang: str
    source: str  # "human" | "auto" | "unknown"
    segments: List[CaptionSegment]

class VocabItem(BaseModel):
    """Model for a vocabulary word with frequency and examples"""
    lemma: str
    count: int
    examples: List[dict]  # List of {text: str, ts: float}

class VocabResponse(BaseModel):
    """Model for vocabulary extraction response"""
    lang: str
    tokens: List[VocabItem]
