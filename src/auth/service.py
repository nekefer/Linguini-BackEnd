from datetime import timedelta, datetime, timezone
from typing import Annotated
from uuid import UUID, uuid4
from fastapi import Depends
from passlib.context import CryptContext
import jwt
from jwt import PyJWTError
from sqlalchemy.orm import Session
from src.entities.user import User
from . import models
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from ..exceptions import AuthenticationError
import logging

oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')
bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return bcrypt_context.hash(password)


def authenticate_user(email: str, password: str, db: Session) -> User | bool:
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password_hash):
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


def verify_token(token: str, secret_key: str, algorithm: str) -> models.TokenData:
    try:
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])
        user_id: str = payload.get('id')
        return models.TokenData(user_id=user_id)
    except PyJWTError as e:
        logging.warning(f"Token verification failed: {str(e)}")
        raise AuthenticationError()


def register_user(db: Session, register_user_request: models.RegisterUserRequest) -> None:
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
        logging.error(f"Failed to register user: {register_user_request.email}. Error: {str(e)}")
        raise
    
    
def get_current_user(token: Annotated[str, Depends(oauth2_bearer)], settings) -> models.TokenData:
    return verify_token(token, settings.JWT_SECRET_KEY, settings.ALGORITHM)

CurrentUser = Annotated[models.TokenData, Depends(get_current_user)]


def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
                                 db: Session, settings=None) -> models.Token:
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise AuthenticationError()
    token = create_access_token(user.email, user.id, timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES), settings.JWT_SECRET_KEY, settings.ALGORITHM)
    return models.Token(access_token=token, token_type='bearer')


def google_authenticate_user(db: Session, user_info: dict, settings) -> models.Token:
    """
    Authenticate or register a user using Google OAuth info, then return a JWT token.
    """
    email = user_info.get("email")
    first_name = user_info.get("given_name", "")
    last_name = user_info.get("family_name", "")
    google_id = user_info.get("sub")
    avatar_url = user_info.get("picture")
    full_name = user_info.get("name", f"{first_name} {last_name}")
    if not email:
        logging.error("Google OAuth did not return an email.")
        raise AuthenticationError("Google OAuth did not return an email.")

    user = db.query(User).filter(User.email == email).first()
    if user:
        # If user exists and has a password, set auth_method to 'both'
        if user.password_hash:
            user.auth_method = 'both'
        else:
            user.auth_method = 'google'
        # Update google_id and avatar_url if not set
        if not user.google_id:
            user.google_id = google_id
        if avatar_url:
            user.avatar_url = avatar_url
        db.commit()
        db.refresh(user)
        logging.info(f"Authenticated existing user via Google OAuth: {email}")
    else:
        # Register the user if not found
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

    token = create_access_token(user.email, user.id, timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES), settings.JWT_SECRET_KEY, settings.ALGORITHM)
    return models.Token(access_token=token, token_type='bearer')
