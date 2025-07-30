from datetime import timedelta, datetime, timezone
from typing import Annotated
from uuid import UUID, uuid4
from fastapi import Depends, Request
from passlib.context import CryptContext
import jwt
from jwt import PyJWTError
from sqlalchemy.orm import Session
from src.entities.user import User
from src.entities.refresh_token import RefreshToken
from . import models
from fastapi.security import OAuth2PasswordRequestForm
from ..exceptions import AuthenticationError
from ..config import get_settings, Settings
import logging
import hashlib  # For token hashing - faster than bcrypt for frequent verification

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return bcrypt_context.hash(password)


def authenticate_user(email: str, password: str, db: Session) -> User | bool:
    user = db.query(User).filter(User.email == email).first()
    if not user:
        logging.warning(f"Failed authentication attempt for email: {email}")
        return False
    
    # Only allow password login if auth_method is 'password' or 'both'
    if user.auth_method not in ('password', 'both'):
        logging.warning(f"User {email} attempted password login but auth_method is '{user.auth_method}'")
        return False
    
    # Check if user has a password hash and verify it
    if not user.password_hash or not verify_password(password, user.password_hash):
        logging.warning(f"Failed authentication attempt for email: {email}")
        return False
    
    return user


def create_access_token(email: str, user_id: UUID, expires_delta: timedelta, secret_key: str, algorithm: str) -> str:
    encode = {
        'sub': email,
        'id': str(user_id),
        'exp': datetime.now(timezone.utc) + expires_delta
    }
    return jwt.encode(encode, secret_key, algorithm=algorithm)


def create_refresh_token(user_id: UUID, expires_delta: timedelta, secret_key: str, algorithm: str) -> str:
    """Create a refresh token with longer expiration."""
    encode = {
        'sub': str(user_id),
        'type': 'refresh',  # Distinguish from access tokens
        'exp': datetime.now(timezone.utc) + expires_delta
    }
    return jwt.encode(encode, secret_key, algorithm=algorithm)


def hash_token(token: str) -> str:
    """
    Hash a token for secure storage in database.
    
    We use SHA-256 instead of bcrypt because:
    - Tokens are verified frequently (every API call)
    - SHA-256 is fast and deterministic
    - bcrypt is slow by design (good for passwords, bad for performance)
    - Token security relies on JWT signature, not hash strength
    """
    return hashlib.sha256(token.encode()).hexdigest()


def store_refresh_token(db: Session, user_id: UUID, token: str, expires_at: datetime) -> None:
    token_hash = hash_token(token)
    
    # Revoke any existing tokens for this user
    db.query(RefreshToken).filter(
        RefreshToken.user_id == user_id,
        RefreshToken.is_revoked == False
    ).update({"is_revoked": True})
    
    refresh_token = RefreshToken(
        token_hash=token_hash,
        user_id=user_id,
        expires_at=expires_at
    )
    db.add(refresh_token)
    db.commit()


def verify_refresh_token(token: str, db: Session, settings: Settings) -> models.TokenData:
    """
    Verify refresh token and return user data.
    
    Checks:
    1. JWT signature and expiration
    2. Token type is 'refresh'
    3. Token hash exists in database
    4. Token is not revoked
    5. Token has not expired in database
    """
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.algorithm])
        
        if payload.get('type') != 'refresh':
            raise AuthenticationError("Invalid token type")
        
        user_id = payload.get('sub')
        if not user_id:
            raise AuthenticationError("Invalid refresh token")
        
        # Check if token exists in database and is not revoked
        token_hash = hash_token(token)
        db_token = db.query(RefreshToken).filter(
            RefreshToken.token_hash == token_hash,
            RefreshToken.is_revoked == False,
            RefreshToken.expires_at > datetime.now(timezone.utc)
        ).first()
        
        if not db_token:
            raise AuthenticationError("Invalid or expired refresh token")
        
        return models.TokenData(user_id=user_id, token_type="refresh")
        
    except PyJWTError as e:
        logging.warning(f"Refresh token verification failed: {str(e)}")
        raise AuthenticationError("Invalid refresh token")


def revoke_refresh_token(token: str, db: Session) -> None:
    """Revoke a refresh token by marking it as revoked in database."""
    token_hash = hash_token(token)
    db_token = db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()
    if db_token:
        db_token.is_revoked = True
        db.commit()


def create_token_pair(user: User, settings: Settings, db: Session) -> models.Token:
    """
    Create both access and refresh tokens.
    
    Access token: Short-lived (30 minutes) for API calls
    Refresh token: Long-lived (30 days) for getting new access tokens
    """
    # Create access token (short-lived)
    access_token = create_access_token(
        user.email, 
        user.id, 
        timedelta(minutes=settings.access_token_expire_minutes), 
        settings.jwt_secret_key, 
        settings.algorithm
    )
    
    # Create refresh token (long-lived)
    refresh_expires = timedelta(days=settings.refresh_token_expire_days)
    refresh_token = create_refresh_token(
        user.id, 
        refresh_expires, 
        settings.jwt_secret_key, 
        settings.algorithm
    )
    
    # Store refresh token hash for revocation tracking
    expires_at = datetime.now(timezone.utc) + refresh_expires
    store_refresh_token(db, user.id, refresh_token, expires_at)
    
    return models.Token(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_token_expire_minutes * 60
    )


def verify_token(token: str, secret_key: str, algorithm: str) -> models.TokenData:
    try:
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])
        user_id: str = payload.get('id')
        return models.TokenData(user_id=user_id)
    except PyJWTError as e:
        logging.warning(f"Token verification failed: {str(e)}")
        raise AuthenticationError()


def register_user(db: Session, register_user_request: models.RegisterUserRequest) -> None:
    "check if the user already exists, if raise an error, otherwise create a new user"
    existing_user = db.query(User).filter(User.email == register_user_request.email).first()
    if existing_user:
        raise AuthenticationError("A user with this email already exists.")
    try:
        create_user_model = User(
            id=uuid4(),
            email=register_user_request.email,
            first_name=register_user_request.first_name,
            last_name=register_user_request.last_name,
            password_hash=get_password_hash(register_user_request.password)
        )    
        db.add(create_user_model)
        db.commit()
    except Exception as e:
        db.rollback()  # Rollback on error to prevent partial data
        logging.error(f"Failed to register user: {register_user_request.email}. Error: {str(e)}")
        raise AuthenticationError(f"Registration failed: {str(e)}")


def get_current_user_from_cookie(request: Request, settings: Annotated[Settings, Depends(get_settings)]) -> models.TokenData:
    """Get current user from HttpOnly cookie instead of Authorization header."""
    token = request.cookies.get("access_token")
    if not token:
        raise AuthenticationError("No access token found in cookies")
    
    return verify_token(token, settings.jwt_secret_key, settings.algorithm)

# Cookie-based authentication for all endpoints
CurrentUser = Annotated[models.TokenData, Depends(get_current_user_from_cookie)]


def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
                                 db: Session, settings: Settings) -> models.Token:
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise AuthenticationError()
    return create_token_pair(user, settings, db)  # Use token pair instead of single token


def google_authenticate_user(db: Session, user_info: dict, settings: Settings) -> models.Token:
    """
    Authenticate or register a user using Google OAuth info.
    Returns a Token object with both access and refresh tokens.
    """
    email = user_info.get("email")
    first_name = user_info.get("given_name", "")
    last_name = user_info.get("family_name", "")
    google_id = user_info.get("sub")
    avatar_url = user_info.get("picture")
    
    if not email:
        logging.error("Google OAuth did not return an email.")
        raise AuthenticationError("Google OAuth did not return an email.")

    user = db.query(User).filter(User.email == email).first()
    
    if user:
        # Existing user - Login
        if not user.google_id and user.auth_method not in ('google', 'both'):
            logging.warning(f"User {email} attempted Google login but is not authorized for Google login.")
            raise AuthenticationError("Google login not enabled for this user.")
        
        # Update auth_method based on existing credentials
        if user.password_hash and user.auth_method != 'both':
            user.auth_method = 'both'  # User has both password and Google
        elif not user.password_hash and user.auth_method != 'google':
            user.auth_method = 'google'  # User only has Google
            
        # Update google_id and avatar_url if not set
        if not user.google_id:
            user.google_id = google_id
        if avatar_url:
            user.avatar_url = avatar_url
            
        db.commit()
        db.refresh(user)
        logging.info(f"Authenticated existing user via Google OAuth: {email}")
    else:
        # New user - Registration
        user = User(
            id=uuid4(),
            email=email,
            first_name=first_name,
            last_name=last_name,
            google_id=google_id,
            auth_method='google',
            avatar_url=avatar_url,
            password_hash=None
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        logging.info(f"Registered new user via Google OAuth: {email}")

    return create_token_pair(user, settings, db)  # Use token pair instead of single token


def change_password(db: Session, user_id: UUID, password_change: models.PasswordChange) -> None:
    """Change user password with validation."""
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise AuthenticationError("User not found")
        
        # Verify current password
        if not verify_password(password_change.current_password, user.password_hash):
            raise AuthenticationError("Invalid current password")
        
        # Verify new passwords match
        if password_change.new_password != password_change.new_password_confirm:
            raise AuthenticationError("New passwords do not match")
        
        # Update password
        user.password_hash = get_password_hash(password_change.new_password)
        db.commit()
        logging.info(f"Successfully changed password for user ID: {user_id}")
    except Exception as e:
        logging.error(f"Error during password change for user ID: {user_id}. Error: {str(e)}")
        raise
