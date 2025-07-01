from uuid import UUID
from pydantic import BaseModel, EmailStr, Field, field_validator
import re

class RegisterUserRequest(BaseModel):
    email: EmailStr
    first_name: str = Field(..., min_length=1, max_length=50)
    last_name: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=8, max_length=128)
    
    @field_validator('first_name', 'last_name')
    @classmethod
    def validate_name(cls, v):
        if not re.match(r'^[a-zA-Z\s\'-]+$', v):
            raise ValueError('Name can only contain letters, spaces, hyphens, and apostrophes')
        return v.strip()
    
    @field_validator('password')
    @classmethod
    def validate_password_strength(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        return v

class Token(BaseModel):
    access_token: str
    token_type: str
    
class TokenData(BaseModel):
    user_id: str | None = None

    def get_uuid(self) -> UUID | None:
        if self.user_id:
            return UUID(self.user_id)
        return None

class UserResponse(BaseModel):
    """Response model for user data (without sensitive information)."""
    id: UUID
    email: str
    first_name: str
    last_name: str
    auth_method: str
    avatar_url: str | None = None
    is_active: bool
    created_at: str  # ISO format string
    updated_at: str  # ISO format string