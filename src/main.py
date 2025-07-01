from fastapi import FastAPI
from .database.core import engine, Base
from .entities.user import User  # Import models to register them
from .api import register_routes
from .logging import configure_logging, LogLevels
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
import os


configure_logging(LogLevels.info)

# Validate SECRET_KEY
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable is required")
if len(SECRET_KEY) < 32:
    raise ValueError("SECRET_KEY must be at least 32 characters long for security")

app = FastAPI()

app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY  # Use validated SECRET_KEY
)

# Configure CORS
origins = [
    "http://localhost:5173",  # React dev server
    "http://127.0.0.1:5173",
    # Add production domain(s) here when deploying
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Allow specific origins
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)


# Only create tables in development environment
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
if ENVIRONMENT == "development":
    Base.metadata.create_all(bind=engine)
    print("Database tables created successfully (development mode)")

register_routes(app)