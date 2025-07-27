"""
Simple table creation script without Alembic
Run this once to create all database tables
"""

from .core import engine, Base
from ..entities.user import User
from ..entities.refresh_token import RefreshToken

def create_all_tables():
    """Create all database tables"""
    print("Creating database tables...")
    Base.metadata.create_all(bind=engine)
    print("✅ All tables created successfully!")

if __name__ == "__main__":
    create_all_tables()