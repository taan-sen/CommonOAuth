# auth/token_handler.py

import time
import jwt
import secrets

SECRET_KEY = "your-service-a-secret-key"  # Change to your own secret
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 1800  # 30 minutes

# For demo purposes, using an in-memory store for refresh tokens. In production, use Redis or a database.
refresh_token_store = {}

class TokenManager:
    @staticmethod
    def generate_tokens(email: str):
        access_payload = {
            "sub": email,
            "exp": time.time() + ACCESS_TOKEN_EXPIRE_SECONDS
        }
        access_token = jwt.encode(access_payload, SECRET_KEY, algorithm=ALGORITHM)
        
        # Generate a refresh token (our internal one)
        refresh_token = secrets.token_urlsafe(32)
        refresh_token_store[refresh_token] = email
        
        return access_token, refresh_token

    @staticmethod
    def verify_token(token: str):
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            return payload.get("sub")
        except Exception:
            return None

    @staticmethod
    def refresh_access_token(refresh_token: str):
        email = refresh_token_store.get(refresh_token)
        if not email:
            return None, None
        return TokenManager.generate_tokens(email)
