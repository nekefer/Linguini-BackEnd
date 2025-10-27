"""
UserVideoHistory entity for tracking user interactions with videos.
"""
from sqlalchemy import Column, String, Integer, DateTime, Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

from ..database.core import Base


class UserVideoHistory(Base):
    """User video interaction history."""
    
    __tablename__ = "user_video_history"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Foreign keys
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    video_id = Column(UUID(as_uuid=True), ForeignKey("videos.id"), nullable=False)
    
    # Interaction data
    watch_time_seconds = Column(Integer, default=0)  # How long user watched
    completion_percentage = Column(Integer, default=0)  # 0-100
    is_liked = Column(Boolean, default=False)
    is_disliked = Column(Boolean, default=False)
    is_saved = Column(Boolean, default=False)  # Saved to watch later
    
    # Interaction timestamps
    first_watched_at = Column(DateTime, default=datetime.utcnow)
    last_watched_at = Column(DateTime, default=datetime.utcnow)
    liked_at = Column(DateTime, nullable=True)
    saved_at = Column(DateTime, nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="video_history")
    video = relationship("Video", back_populates="user_history")
    
    def __repr__(self):
        return f"<UserVideoHistory(user_id={self.user_id}, video_id={self.video_id}, watch_time={self.watch_time_seconds}s)>"
    
    def to_dict(self):
        """Convert user video history to dictionary for API responses."""
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "video_id": str(self.video_id),
            "watch_time_seconds": self.watch_time_seconds,
            "completion_percentage": self.completion_percentage,
            "is_liked": self.is_liked,
            "is_disliked": self.is_disliked,
            "is_saved": self.is_saved,
            "first_watched_at": self.first_watched_at.isoformat(),
            "last_watched_at": self.last_watched_at.isoformat(),
            "liked_at": self.liked_at.isoformat() if self.liked_at else None,
            "saved_at": self.saved_at.isoformat() if self.saved_at else None
        }

