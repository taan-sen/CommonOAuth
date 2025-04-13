from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse
from .token_handler import TokenManager

class CallbackHandler:
    @staticmethod
    async def handle_oauth_callback(request: Request):
        query = request.query_params
        access_token = query.get("access_token")
        refresh_token = query.get("refresh_token")
        name = query.get("name")
        email = query.get("email")

        # Validate required fields; refresh_token is optional.
        if not all([access_token, name, email]):
            return JSONResponse(status_code=400, content={"error": "Missing data from OAuth callback"})

        if not refresh_token:
            # Log a warning if the refresh token is missing
            print("Warning: refresh token missing in OAuth callback. Generating new internal tokens.")

        # Generate internal tokens (JWT access token with 30 mins expiry and new internal refresh token)
        internal_access_token, internal_refresh_token = TokenManager.generate_tokens(email)

        # Store tokens and user info in the session for further requests (e.g. /greeting)
        request.session["internal_access_token"] = internal_access_token
        request.session["internal_refresh_token"] = internal_refresh_token
        request.session["user"] = email

        # Redirect the user to the originally accessed API endpoint (/greeting)
        return RedirectResponse(url="/greeting")
