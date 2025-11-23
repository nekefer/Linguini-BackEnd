import logging
from functools import lru_cache
from typing import Optional
from cryptography.fernet import Fernet, InvalidToken
from ..config import get_settings

logger = logging.getLogger("security.crypto")

@lru_cache(maxsize=1)
def _get_fernet() -> Fernet:
    settings = get_settings()
    key = settings.google_token_enc_key
    if not key:
        raise RuntimeError("GOOGLE_TOKEN_ENC_KEY not set in config. Generate one with: python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())' and add to .env")
    try:
        return Fernet(key)
    except Exception as e:
        raise RuntimeError(f"Invalid GOOGLE_TOKEN_ENC_KEY: {e}")

def encrypt_token(value: Optional[str]) -> Optional[str]:
    if not value:
        return value
    try:
        f = _get_fernet()
        return f.encrypt(value.encode()).decode()
    except Exception as e:
        logger.error(f"Failed to encrypt token: {e}")
        return value  # fallback (should not happen)

def decrypt_token(value: Optional[str]) -> Optional[str]:
    if not value:
        return value
    try:
        f = _get_fernet()
        return f.decrypt(value.encode()).decode()
    except InvalidToken:
        # Likely plaintext from before migration – return as-is
        logger.debug("Token appears to be plaintext; returning original value.")
        return value
    except Exception as e:
        logger.error(f"Failed to decrypt token: {e}")
        return None
