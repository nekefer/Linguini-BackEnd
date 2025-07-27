"""
Database initialization utilities
"""

import os
from sqlalchemy import text
from .core import engine, Base, SessionLocal
from ..entities.user import User
from ..entities.refresh_token import RefreshToken
from ..config import get_settings

def init_database():
    """
    Initialize the database with all tables
    This is equivalent to 'alembic upgrade head' but simpler
    """
    try:
        settings = get_settings()
        print(f"🔄 Initializing database at: {settings.database_url}")
        
        # Create all tables
        Base.metadata.create_all(bind=engine)
        
        print("✅ Database initialized successfully!")
        print("📋 Created tables:")
        print("   - users")
        print("   - refresh_tokens")
        
        return True
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")
        return False

def check_database_connection():
    """Check if database connection is working"""
    try:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            return True
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        return False

def reset_database():
    """
    ⚠️  WARNING: This will delete all data!
    Drops and recreates all tables
    """
    try:
        print("⚠️  WARNING: Dropping all tables...")
        Base.metadata.drop_all(bind=engine)
        print("🔄 Recreating tables...")
        Base.metadata.create_all(bind=engine)
        print("✅ Database reset complete!")
        return True
    except Exception as e:
        print(f"❌ Database reset failed: {e}")
        return False

if __name__ == "__main__":
    # When run directly, initialize the database
    if check_database_connection():
        init_database()
    else:
        print("Please check your database connection and try again.")