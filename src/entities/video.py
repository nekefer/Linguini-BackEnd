"""
Video entity model for storing YouTube video information.
"""
from sqlalchemy import Column, String, Integer, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

from ..database.core import Base


class Video(Base):
    """YouTube video entity model."""
    
    __tablename__ = "videos"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # YouTube-specific fields
    youtube_id = Column(String(50), unique=True, nullable=False, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    thumbnail_url = Column(String(1000))
    thumbnail_medium_url = Column(String(1000))
    thumbnail_high_url = Column(String(1000))
    
    # Video metadata
    duration = Column(String(20))  # ISO 8601 duration format (PT4M13S)
    published_at = Column(DateTime)
    view_count = Column(Integer, default=0)
    like_count = Column(Integer, default=0)
    comment_count = Column(Integer, default=0)
    
    # Channel information
    channel_id = Column(String(100), nullable=False)
    channel_title = Column(String(200), nullable=False)
    channel_thumbnail_url = Column(String(1000))
    
    # Video categorization
    category_id = Column(String(20))
    category_title = Column(String(100))
    tags = Column(Text)  # JSON string of tags
    
    # Video status
    privacy_status = Column(String(20), default="public")
    is_live_content = Column(Boolean, default=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    playlists = relationship("PlaylistVideo", back_populates="video")
    user_history = relationship("UserVideoHistory", back_populates="video")
    
    def __repr__(self):
        return f"<Video(id={self.id}, youtube_id={self.youtube_id}, title='{self.title[:50]}...')>"
    
    def to_dict(self):
        """Convert video to dictionary for API responses."""
        return {
            "id": str(self.id),
            "youtube_id": self.youtube_id,
            "title": self.title,
            "description": self.description,
            "thumbnail_url": self.thumbnail_url,
            "thumbnail_medium_url": self.thumbnail_medium_url,
            "thumbnail_high_url": self.thumbnail_high_url,
            "duration": self.duration,
            "published_at": self.published_at.isoformat() if self.published_at else None,
            "view_count": self.view_count,
            "like_count": self.like_count,
            "comment_count": self.comment_count,
            "channel_id": self.channel_id,
            "channel_title": self.channel_title,
            "channel_thumbnail_url": self.channel_thumbnail_url,
            "category_id": self.category_id,
            "category_title": self.category_title,
            "tags": self.tags,
            "privacy_status": self.privacy_status,
            "is_live_content": self.is_live_content,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }

