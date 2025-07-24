# src/auth/oauth_config.py
from authlib.integrations.starlette_client import OAuth
from ...config import get_settings

settings = get_settings()
oauth = OAuth()

oauth.register(
    name='google',
    client_id=settings.google_client_id,
    client_secret=settings.google_client_secret,
    authorize_url=settings.google_authorization_url,
    authorize_params={"scope": settings.google_oauth.scope},
    redirect_uri=settings.google_redirect_uri,
    access_token_url=settings.google_oauth.token_url,
    client_kwargs={"scope": settings.google_oauth.scope},
    server_metadata_url=settings.google_oauth.server_metadata_url
)