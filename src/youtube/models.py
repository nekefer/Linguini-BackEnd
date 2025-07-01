from pydantic import BaseModel

class LikedVideo(BaseModel):
    video_id: str
    title: str
    description: str
    thumbnails: dict
