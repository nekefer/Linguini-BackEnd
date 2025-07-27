import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Tuple
from uuid import UUID
from sqlalchemy.orm import Session
from passlib.context import CryptContext

from ..entities.refresh_token import RefreshToken
from ..entities.user import User
from ..exceptions import AuthenticationError

# Use the same password context for consistency
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class RefreshTokenService:
    """Service for managing refresh tokens with secure hashing"""
    
    @staticmethod
    def generate_token() -> str:
        """Generate a cryptographically secure random token"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def hash_token(token: str) -> str:
        """Hash a refresh token using bcrypt"""
        return pwd_context.hash(token)
    
    @staticmethod
    def verify_token(token: str, hashed_token: str) -> bool:
        """Verify a token against its hash"""
        return pwd_context.verify(token, hashed_token)
    
    @staticmethod
    def create_refresh_token(
        db: Session,
        user_id: UUID,
        device_info: Optional[str] = None,
        ip_address: Optional[str] = None,
        expires_in_days: int = 30
    ) -> Tuple[str, RefreshToken]:
        """
        Create a new refresh token for a user
        Returns tuple of (plain_token, refresh_token_entity)
        """
        # Generate plain token
        plain_token = RefreshTokenService.generate_token()
        
        # Hash the token for storage
        token_hash = RefreshTokenService.hash_token(plain_token)
        
        # Create refresh token entity
        refresh_token = RefreshToken.create(
            user_id=user_id,
            token_hash=token_hash,
            expires_in_days=expires_in_days,
            device_info=device_info,
            ip_address=ip_address
        )
        
        # Save to database
        db.add(refresh_token)
        db.commit()
        db.refresh(refresh_token)
        
        return plain_token, refresh_token
    
    @staticmethod
    def verify_and_get_refresh_token(
        db: Session,
        token: str
    ) -> Optional[RefreshToken]:
        """
        Verify a refresh token and return the entity if valid
        Returns None if token is invalid, expired, or revoked
        """
        # Get all non-revoked refresh tokens
        refresh_tokens = db.query(RefreshToken).filter(
            RefreshToken.is_revoked == False
        ).all()
        
        # Check each token hash until we find a match
        for refresh_token in refresh_tokens:
            if RefreshTokenService.verify_token(token, refresh_token.token_hash):
                # Found matching token, check if it's still valid
                if refresh_token.is_valid():
                    return refresh_token
                else:
                    # Token is expired, mark as revoked
                    refresh_token.revoke()
                    db.commit()
                    return None
        
        # No matching token found
        return None
    
    @staticmethod
    def revoke_token(db: Session, token: str) -> bool:
        """
        Revoke a specific refresh token
        Returns True if token was found and revoked, False otherwise
        """
        refresh_token = RefreshTokenService.verify_and_get_refresh_token(db, token)
        if refresh_token:
            refresh_token.revoke()
            db.commit()
            return True
        return False
    
    @staticmethod
    def revoke_all_user_tokens(db: Session, user_id: UUID) -> int:
        """
        Revoke all refresh tokens for a user
        Returns number of tokens revoked
        """
        tokens = db.query(RefreshToken).filter(
            RefreshToken.user_id == user_id,
            RefreshToken.is_revoked == False
        ).all()
        
        count = 0
        for token in tokens:
            token.revoke()
            count += 1
        
        db.commit()
        return count
    
    @staticmethod
    def cleanup_expired_tokens(db: Session) -> int:
        """
        Clean up expired refresh tokens from the database
        Returns number of tokens cleaned up
        """
        now = datetime.utcnow()
        expired_tokens = db.query(RefreshToken).filter(
            RefreshToken.expires_at < now
        ).all()
        
        count = 0
        for token in expired_tokens:
            if not token.is_revoked:
                token.revoke()
                count += 1
        
        db.commit()
        return count
    
    @staticmethod
    def get_user_active_tokens(db: Session, user_id: UUID) -> list[RefreshToken]:
        """Get all active (non-revoked, non-expired) tokens for a user"""
        return db.query(RefreshToken).filter(
            RefreshToken.user_id == user_id,
            RefreshToken.is_revoked == False,
            RefreshToken.expires_at > datetime.utcnow()
        ).all()