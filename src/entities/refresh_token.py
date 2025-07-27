from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from datetime import datetime, timedelta
from ..database.core import Base

class RefreshToken(Base):
    __tablename__ = 'refresh_tokens'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    token_hash = Column(String, unique=True, nullable=False)  # Hashed refresh token
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_revoked = Column(Boolean, default=False)
    revoked_at = Column(DateTime, nullable=True)
    device_info = Column(String, nullable=True)  # Optional device/browser info
    ip_address = Column(String, nullable=True)   # IP address when token was created

    # Relationship to user
    user = relationship("User", back_populates="refresh_tokens")

    @classmethod
    def create(cls, user_id: UUID, token_hash: str, expires_in_days: int = 30, 
               device_info: str = None, ip_address: str = None):
        """Create a new refresh token with expiration"""
        return cls(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=datetime.utcnow() + timedelta(days=expires_in_days),
            device_info=device_info,
            ip_address=ip_address
        )

    def is_expired(self) -> bool:
        """Check if the refresh token is expired"""
        return datetime.utcnow() > self.expires_at

    def is_valid(self) -> bool:
        """Check if the refresh token is valid (not expired and not revoked)"""
        return not self.is_expired() and not self.is_revoked

    def revoke(self):
        """Revoke the refresh token"""
        self.is_revoked = True
        self.revoked_at = datetime.utcnow()

    def __repr__(self):
        return f"<RefreshToken(user_id='{self.user_id}', expires_at='{self.expires_at}', is_revoked={self.is_revoked})>"