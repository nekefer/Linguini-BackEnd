# src/auth/oauth_config.py
import os
from authlib.integrations.starlette_client import OAuth
from starlette.config import Config

config = Config('.env')
oauth = OAuth(config)

# Fixed configuration - ONLY use server_metadata_url for proper OpenID Connect
# oauth.register(
#     name='google',
#     client_id=config('GOOGLE_CLIENT_ID'),
#     client_secret=config('GOOGLE_CLIENT_SECRET'),
#     server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
#     client_kwargs={
#         'scope': 'openid email profile'
#     }
# )

# Alternative: If you need to use manual endpoints, ensure proper OpenID Connect parameters
oauth.register(
    name='google',
    client_id=config('GOOGLE_CLIENT_ID'),
    client_secret=config('GOOGLE_CLIENT_SECRET'),
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params={"scope": "openid email profile"},
    redirect_uri='http://127.0.0.1:8000/auth/google/callback',
    access_token_url="https://oauth2.googleapis.com/token",
    client_kwargs={"scope": "openid email profile"},
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration"
)

# JWT configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = "HS256"