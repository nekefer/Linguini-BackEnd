"""
Playlist entity model for storing YouTube playlists.
"""
from sqlalchemy import Column, String, Text, Boolean, ForeignKey, Integer, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

from ..database.core import Base


class Playlist(Base):
    """YouTube playlist entity model."""
    
    __tablename__ = "playlists"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Playlist identification
    youtube_id = Column(String(50), unique=True, nullable=True)  # Nullable for custom playlists
    title = Column(String(200), nullable=False)
    description = Column(Text)
    thumbnail_url = Column(String(1000))
    
    # Playlist metadata
    item_count = Column(Integer, default=0)
    privacy_status = Column(String(20), default="private")  # private, unlisted, public
    
    # Ownership
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    is_custom = Column(Boolean, default=True)  # True for user-created, False for YouTube playlists
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="playlists")
    videos = relationship("PlaylistVideo", back_populates="playlist")
    
    def __repr__(self):
        return f"<Playlist(id={self.id}, title='{self.title}', user_id={self.user_id})>"
    
    def to_dict(self):
        """Convert playlist to dictionary for API responses."""
        return {
            "id": str(self.id),
            "youtube_id": self.youtube_id,
            "title": self.title,
            "description": self.description,
            "thumbnail_url": self.thumbnail_url,
            "item_count": self.item_count,
            "privacy_status": self.privacy_status,
            "user_id": str(self.user_id),
            "is_custom": self.is_custom,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }
