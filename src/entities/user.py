from sqlalchemy import Column, String
from sqlalchemy.dialects.postgresql import UUID
import uuid
from ..database.core import Base 

class User(Base):
    __tablename__ = 'users'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String, unique=True, nullable=False)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    password_hash = Column(String, nullable=True)  # Now nullable for Google users
    google_id = Column(String, nullable=True)      # For Google OAuth users
    auth_method = Column(String, nullable=False, default='password')  # 'password' or 'google'
    avatar_url = Column(String, nullable=True)     # Optional profile picture

    def __repr__(self):
        return f"<User(email='{self.email}', first_name='{self.first_name}', last_name='{self.last_name}', auth_method='{self.auth_method}')>"