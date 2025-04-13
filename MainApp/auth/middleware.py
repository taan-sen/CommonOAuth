from fastapi.responses import RedirectResponse
from jose import ExpiredSignatureError
import jwt
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse
from jwt import DecodeError, ExpiredSignatureError


from auth.token_handler import ALGORITHM, SECRET_KEY, TokenManager

# Middleware to validate token
class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path.startswith("/ua/") or path.startswith("/oauth/callback") or path.startswith("/refresh"):
            return await call_next(request)

        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                print(payload)
                request.state.user = payload.get("sub")  # or "name" if you prefer
                return await call_next(request)
            except (DecodeError, ExpiredSignatureError):
                pass  # If token is invalid, fallback to session

        # Check session fallback
        session = request.session
        internal_access_token = session.get("internal_access_token")
        user = session.get("user")

        if internal_access_token and user:
            request.state.user = user
            return await call_next(request)
        if path == "/greeting":
            if request.session.get("internal_access_token") and request.session.get("user"):
                return await call_next(request)

        # Redirect to Service B with callback info
        service_b_url = "http://localhost:8080/authenticate/service_a"
        callback_url = "http://localhost:8008/oauth/callback"
        redirect_url = f"{service_b_url}?client_callback={callback_url}"
        return RedirectResponse(url=redirect_url)
    

def register_middlewares(app):
    # The order here is important: SessionMiddleware first, AuthMiddleware second
    app.add_middleware(AuthMiddleware)
    app.add_middleware(SessionMiddleware, secret_key="your-session-secret-key")

