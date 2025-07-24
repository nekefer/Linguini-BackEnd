# Unified Configuration System

This project now uses a single, unified configuration system that consolidates all environment variables and settings into one place.

## Overview

The configuration system is built using Pydantic Settings, providing:
- **Type safety** with automatic validation
- **Single source of truth** for all configuration
- **Environment-specific settings** support
- **Structured configuration** with logical groupings
- **Comprehensive validation** with helpful error messages

## Configuration File

All configuration is managed through `src/config.py`, which defines:

### Settings Groups

1. **DatabaseSettings** - Database connection configuration
2. **AuthSettings** - Authentication and JWT configuration  
3. **GoogleOAuthSettings** - Google OAuth configuration
4. **AppSettings** - General application settings

### Main Settings Class

The `Settings` class combines all configuration and provides:
- Direct access to all environment variables
- Structured access through properties (`.database`, `.auth`, `.google_oauth`, `.app`)
- Convenience properties (`.cors_origins`, `.is_development`, `.is_production`)
- Automatic validation of all values

## Environment Variables

Copy `.env.example` to `.env` and configure the following variables:

### Required Variables
```bash
# Database
DATABASE_URL=sqlite:///./app.db

# Security
SECRET_KEY=your-32-character-secret-key-here-minimum-length
JWT_SECRET_KEY=your-jwt-secret-key-here

# Google OAuth
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8000/auth/google/callback

# Application
FRONTEND_URL=http://localhost:5173
```

### Optional Variables (with defaults)
```bash
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
GOOGLE_AUTHORIZATION_URL=https://accounts.google.com/o/oauth2/v2/auth
ENVIRONMENT=development
LOG_LEVEL=INFO
```

## Usage

### Basic Usage
```python
from src.config import get_settings

settings = get_settings()

# Direct access
database_url = settings.database_url
secret_key = settings.secret_key

# Structured access
db_config = settings.database
auth_config = settings.auth
oauth_config = settings.google_oauth
app_config = settings.app
```

### In FastAPI Dependencies
```python
from typing import Annotated
from fastapi import Depends
from src.config import get_settings, Settings

def my_endpoint(settings: Annotated[Settings, Depends(get_settings)]):
    # Use settings here
    pass
```

### Environment Checks
```python
settings = get_settings()

if settings.is_development:
    # Development-only code
    pass

if settings.is_production:
    # Production-only code
    pass
```

## Validation

The configuration system automatically validates:

- **Database URL format** - Must be valid PostgreSQL, SQLite, or MySQL URL
- **Secret key length** - Must be at least 32 characters
- **Log levels** - Must be valid Python logging level
- **Environment** - Must be 'development', 'staging', or 'production'
- **Required fields** - All required environment variables must be set

## Migration from Old System

The unified configuration replaces:
- `src/auth/google/config.py` (removed)
- Direct `os.getenv()` calls throughout the codebase
- Scattered environment variable validation

### Changes Made

1. **Database configuration** (`src/database/core.py`)
   - Now uses `settings.database_url` instead of `os.getenv("DATABASE_URL")`
   - Validation moved to config system

2. **Main application** (`src/main.py`)
   - Uses `settings.secret_key` instead of `os.getenv("SECRET_KEY")`
   - Uses `settings.cors_origins` for CORS configuration
   - Uses `settings.is_development` for environment checks

3. **Authentication** (`src/auth/`)
   - All auth services use the unified Settings class
   - OAuth configuration uses structured settings
   - Consistent JWT configuration across all auth components

4. **Logging** (`src/logging.py`)
   - Updated to use standard Python logging levels
   - Integrates with config system for log level setting

## Benefits

1. **Type Safety** - All configuration is typed and validated
2. **Single Source** - One place to manage all configuration
3. **Better Errors** - Clear validation messages for configuration issues
4. **Environment Support** - Easy to manage different environments
5. **Documentation** - Self-documenting configuration with descriptions
6. **Testing** - Easy to override configuration for tests
7. **Maintenance** - Centralized configuration is easier to maintain

## Testing

To test the configuration system:

```python
# Test basic import
from src.config import get_settings
settings = get_settings()
print("Configuration loaded successfully!")

# Test validation (this will raise an error if .env is not properly configured)
print(f"Database URL: {settings.database_url}")
print(f"Environment: {settings.environment}")
print(f"Is Development: {settings.is_development}")
```