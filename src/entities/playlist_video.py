"""
PlaylistVideo junction table for many-to-many relationship between playlists and videos.
"""
from sqlalchemy import Column, ForeignKey, Integer, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

from ..database.core import Base


class PlaylistVideo(Base):
    """Junction table for playlist-video many-to-many relationship."""
    
    __tablename__ = "playlist_videos"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Foreign keys
    playlist_id = Column(UUID(as_uuid=True), ForeignKey("playlists.id"), nullable=False)
    video_id = Column(UUID(as_uuid=True), ForeignKey("videos.id"), nullable=False)
    
    # Ordering within playlist
    position = Column(Integer, nullable=False, default=0)
    
    # Timestamps
    added_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    playlist = relationship("Playlist", back_populates="videos")
    video = relationship("Video", back_populates="playlists")
    
    def __repr__(self):
        return f"<PlaylistVideo(playlist_id={self.playlist_id}, video_id={self.video_id}, position={self.position})>"
    
    def to_dict(self):
        """Convert playlist video to dictionary for API responses."""
        return {
            "id": str(self.id),
            "playlist_id": str(self.playlist_id),
            "video_id": str(self.video_id),
            "position": self.position,
            "added_at": self.added_at.isoformat()
        }

