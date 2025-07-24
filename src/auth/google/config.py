from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # SQLAlchemy
    DATABASE_URL: str 

    # Google OAuth
    GOOGLE_CLIENT_ID: str
    GOOGLE_CLIENT_SECRET: str
    GOOGLE_REDIRECT_URI: str
    GOOGLE_AUTHORIZATION_URL: str 

    JWT_SECRET_KEY: str

    FRONTEND_URL: str 

    # Environment
    ENVIRONMENT: str

    model_config = SettingsConfigDict(env_file=".env")
