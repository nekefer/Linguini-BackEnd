# from datetime import timedelta, datetime, timezone
# from typing import Annotated
# from uuid import UUID
# import jwt
# from jwt import ExpiredSignatureError, PyJWTError
# from fastapi import Depends
# from fastapi.security import OAuth2PasswordBearer

# from ..exceptions import AuthenticationError
# from . import models

# # Constants
# SECRET_KEY = '45a24d2be0d523532801317d9806a16532a2eb09e46ad2ee21eb393290a3f613'
# ALGORITHM = 'HS256'
# ACCESS_TOKEN_EXPIRE_MINUTES = 30

# # OAuth2 scheme
# oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')


# def create_access_token(email: str, user_id: UUID, expires_delta: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)) -> str:
#     payload = {
#         'sub': email,
#         'id': str(user_id),
#         'exp': datetime.now(timezone.utc) + expires_delta
#     }
#     return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


# def verify_token(token: str) -> models.TokenData:
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         user_id: str = payload.get('id')
#         email: str = payload.get('sub')

#         if user_id is None or email is None:
#             raise AuthenticationError("Missing token fields")

#         return models.TokenData(user_id=user_id, email=email)

#     except ExpiredSignatureError:
#         raise AuthenticationError("Token has expired")
#     except PyJWTError as e:
#         raise AuthenticationError(f"Token verification failed: {str(e)}")


# def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]) -> models.TokenData:
#     return verify_token(token)

# CurrentUser = Annotated[models.TokenData, Depends(get_current_user)]
