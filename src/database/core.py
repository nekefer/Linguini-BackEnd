from typing import Annotated
from fastapi import Depends
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from ..config import get_settings

settings = get_settings()

# Use the validated DATABASE_URL from settings
DATABASE_URL = settings.database_url

# The URL is already validated in the Settings class
engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
DbSession = Annotated[Session, Depends(get_db)]

