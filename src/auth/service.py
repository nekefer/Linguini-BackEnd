from datetime import timedelta, datetime, timezone
from typing import Annotated, Optional
from uuid import UUID, uuid4
from fastapi import Depends, Request
from passlib.context import CryptContext
import jwt
from jwt import PyJWTError
from sqlalchemy.orm import Session
from src.entities.user import User
from . import models
from .refresh_token_service import RefreshTokenService
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from ..exceptions import AuthenticationError
from ..config import get_settings, Settings
from ..audit import log_auth_event, AuthEventType, extract_request_info
import logging

oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')
bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return bcrypt_context.hash(password)


def authenticate_user(email: str, password: str, db: Session, request: Optional[Request] = None) -> User | bool:
    request_info = extract_request_info(request) if request else {}
    
    user = db.query(User).filter(User.email == email).first()
    if not user:
        logging.warning(f"Failed authentication attempt for email: {email}")
        log_auth_event(
            AuthEventType.LOGIN_FAILURE,
            email=email,
            success=False,
            details={"reason": "user_not_found"},
            **request_info
        )
        return False
    
    # Only allow password login if auth_method is 'password' or 'both'
    if user.auth_method not in ('password', 'both'):
        logging.warning(f"User {email} attempted password login but auth_method is '{user.auth_method}'")
        log_auth_event(
            AuthEventType.LOGIN_FAILURE,
            user_id=user.id,
            email=email,
            success=False,
            details={"reason": "auth_method_mismatch", "auth_method": user.auth_method},
            **request_info
        )
        return False
    
    # Check if user has a password hash and verify it
    if not user.password_hash or not verify_password(password, user.password_hash):
        logging.warning(f"Failed authentication attempt for email: {email}")
        log_auth_event(
            AuthEventType.LOGIN_FAILURE,
            user_id=user.id,
            email=email,
            success=False,
            details={"reason": "invalid_credentials"},
            **request_info
        )
        return False
    
    return user


def create_access_token(email: str, user_id: UUID, expires_delta: timedelta, secret_key: str, algorithm: str) -> str:
    encode = {
        'sub': email,
        'id': str(user_id),
        'exp': datetime.now(timezone.utc) + expires_delta
    }
    return jwt.encode(encode, secret_key, algorithm=algorithm)


def verify_token(token: str, secret_key: str, algorithm: str) -> models.TokenData:
    try:
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])
        user_id: str = payload.get('id')
        return models.TokenData(user_id=user_id)
    except PyJWTError as e:
        logging.warning(f"Token verification failed: {str(e)}")
        raise AuthenticationError()


def register_user(db: Session, register_user_request: models.RegisterUserRequest, request: Optional[Request] = None) -> None:
    "check if the user already exists, if raise an error, otherwise create a new user"
    request_info = extract_request_info(request) if request else {}
    
    existing_user = db.query(User).filter(User.email == register_user_request.email).first()
    if existing_user:
        log_auth_event(
            AuthEventType.REGISTRATION_FAILURE,
            email=register_user_request.email,
            success=False,
            details={"reason": "email_already_exists"},
            **request_info
        )
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
        
        # Log successful registration
        log_auth_event(
            AuthEventType.REGISTRATION_SUCCESS,
            user_id=create_user_model.id,
            email=register_user_request.email,
            success=True,
            details={"auth_method": "password"},
            **request_info
        )
    except Exception as e:
        db.rollback()  # Rollback on error to prevent partial data
        logging.error(f"Failed to register user: {register_user_request.email}. Error: {str(e)}")
        log_auth_event(
            AuthEventType.REGISTRATION_FAILURE,
            email=register_user_request.email,
            success=False,
            details={"reason": "database_error", "error": str(e)},
            **request_info
        )
        raise AuthenticationError(f"Registration failed: {str(e)}")
    
    
def get_current_user(token: Annotated[str, Depends(oauth2_bearer)],  settings: Annotated[Settings, Depends(get_settings)]) -> models.TokenData:
    return verify_token(token, settings.jwt_secret_key, settings.algorithm)

CurrentUser = Annotated[models.TokenData, Depends(get_current_user)]


def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
                                 db: Session, settings=None, request: Optional[Request] = None) -> models.Token:
    request_info = extract_request_info(request) if request else {}
    
    user = authenticate_user(form_data.username, form_data.password, db, request)
    if not user:
        raise AuthenticationError()
    
    # Create access token
    access_token = create_access_token(user.email, user.id, timedelta(minutes=settings.access_token_expire_minutes), settings.jwt_secret_key, settings.algorithm)
    
    # Create refresh token
    device_info = request_info.get("user_agent") if request_info else None
    ip_address = request_info.get("ip_address") if request_info else None
    refresh_token, _ = RefreshTokenService.create_refresh_token(
        db=db,
        user_id=user.id,
        device_info=device_info,
        ip_address=ip_address
    )
    
    # Log successful login
    log_auth_event(
        AuthEventType.LOGIN_SUCCESS,
        user_id=user.id,
        email=user.email,
        success=True,
        details={"auth_method": "password"},
        **request_info
    )
    
    return models.Token(access_token=access_token, token_type='bearer', refresh_token=refresh_token)


def google_authenticate_user(db: Session, user_info: dict, settings) -> dict:
    """
    Authenticate or register a user using Google OAuth info.
    Returns a dict with token, user info, and whether it's a new registration.
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
    is_new_user = False
    
    if user:
        # Existing user - Login
        # Only allow Google login if user has a google_id or auth_method allows Google
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
        is_new_user = True
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

    # Create access token
    access_token = create_access_token(user.email, user.id, timedelta(minutes=settings.access_token_expire_minutes), settings.jwt_secret_key, settings.algorithm)
    
    # Create refresh token for Google OAuth
    refresh_token, _ = RefreshTokenService.create_refresh_token(
        db=db,
        user_id=user.id,
        device_info="Google OAuth",
        ip_address=None  # We don't have IP info in OAuth flow
    )
    
    # Log successful OAuth login
    log_auth_event(
        AuthEventType.OAUTH_LOGIN_SUCCESS,
        user_id=user.id,
        email=user.email,
        success=True,
        details={"auth_method": "google", "is_new_user": is_new_user}
    )
    
    return models.Token(access_token=access_token, token_type='bearer', refresh_token=refresh_token)


def refresh_access_token(refresh_token_request: models.RefreshTokenRequest, 
                        db: Session, settings: Settings, 
                        request: Optional[Request] = None) -> models.RefreshTokenResponse:
    """
    Refresh an access token using a valid refresh token
    """
    request_info = extract_request_info(request) if request else {}
    
    # Verify the refresh token
    refresh_token_entity = RefreshTokenService.verify_and_get_refresh_token(
        db, refresh_token_request.refresh_token
    )
    
    if not refresh_token_entity:
        log_auth_event(
            AuthEventType.TOKEN_REFRESH_FAILURE,
            success=False,
            details={"reason": "invalid_refresh_token"},
            **request_info
        )
        raise AuthenticationError("Invalid or expired refresh token")
    
    # Get the user
    user = db.query(User).filter(User.id == refresh_token_entity.user_id).first()
    if not user or not user.is_active:
        log_auth_event(
            AuthEventType.TOKEN_REFRESH_FAILURE,
            user_id=refresh_token_entity.user_id,
            success=False,
            details={"reason": "user_not_found_or_inactive"},
            **request_info
        )
        raise AuthenticationError("User not found or inactive")
    
    # Create new access token
    new_access_token = create_access_token(
        user.email, 
        user.id, 
        timedelta(minutes=settings.access_token_expire_minutes), 
        settings.jwt_secret_key, 
        settings.algorithm
    )
    
    # Create new refresh token and revoke the old one
    device_info = request_info.get("user_agent") if request_info else refresh_token_entity.device_info
    ip_address = request_info.get("ip_address") if request_info else refresh_token_entity.ip_address
    
    new_refresh_token, _ = RefreshTokenService.create_refresh_token(
        db=db,
        user_id=user.id,
        device_info=device_info,
        ip_address=ip_address
    )
    
    # Revoke the old refresh token
    refresh_token_entity.revoke()
    db.commit()
    
    # Log successful token refresh
    log_auth_event(
        AuthEventType.TOKEN_REFRESH_SUCCESS,
        user_id=user.id,
        email=user.email,
        success=True,
        details={"old_token_id": str(refresh_token_entity.id)},
        **request_info
    )
    
    return models.RefreshTokenResponse(
        access_token=new_access_token,
        token_type='bearer',
        refresh_token=new_refresh_token
    )


def logout_user(refresh_token: Optional[str], user_id: UUID, db: Session, 
               request: Optional[Request] = None) -> None:
    """
    Logout user by revoking refresh token(s)
    """
    request_info = extract_request_info(request) if request else {}
    
    revoked_count = 0
    if refresh_token:
        # Revoke specific refresh token
        if RefreshTokenService.revoke_token(db, refresh_token):
            revoked_count = 1
    else:
        # Revoke all user's refresh tokens
        revoked_count = RefreshTokenService.revoke_all_user_tokens(db, user_id)
    
    # Log logout
    log_auth_event(
        AuthEventType.LOGOUT,
        user_id=user_id,
        success=True,
        details={"revoked_tokens": revoked_count},
        **request_info
    )
