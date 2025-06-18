# src/auth/oauth_config.py
from authlib.integrations.starlette_client import OAuth
from starlette.config import Config

config = Config('.env')
oauth = OAuth(config)

oauth.register(
    name='google',
    client_id=config('GOOGLE_CLIENT_ID'),
    client_secret=config('GOOGLE_CLIENT_SECRET'),
    authorize_url=config('GOOGLE_AUTHORIZATION_URL'),
    authorize_params={"scope": "openid email profile"},
    redirect_uri=config('GOOGLE_REDIRECT_URI'),
    access_token_url="https://oauth2.googleapis.com/token",
    client_kwargs={"scope": "openid email profile"},
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration"
)