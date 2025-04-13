from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from auth.callback_handler import CallbackHandler
from auth.middleware import register_middlewares
from auth.token_handler import TokenManager


app = FastAPI()
register_middlewares(app)

@app.get("/greeting")
async def greeting(request: Request):
    # Prefer token-based identity from middleware
    user_email = getattr(request.state, "user", None)

    if user_email:
        response_data = {"message": f"Hello, {user_email}!"}
    else:
        # Should not reach here due to middleware redirect
        response_data = {"message": "Hello, Anonymous!"}

    response = JSONResponse(content=response_data)

    # Only pop session tokens if no Authorization header
    if not request.headers.get("Authorization"):
        access_token = request.session.pop("internal_access_token", None)
        refresh_token = request.session.pop("internal_refresh_token", None)

        if access_token:
            response.headers["X-Access-Token"] = access_token
        if refresh_token:
            response.headers["X-Refresh-Token"] = refresh_token

    return response

@app.get("/oauth/callback")
async def oauth_callback(request: Request):
    return await CallbackHandler.handle_oauth_callback(request)

@app.post("/refresh")
async def refresh_token(request: Request):
    body = await request.json()
    refresh_token = body.get("refresh_token")
    if not refresh_token:
        return JSONResponse(status_code=400, content={"error": "Missing refresh token"})

    new_access_token, new_refresh_token = TokenManager.refresh_access_token(refresh_token)
    if not new_access_token:
        return JSONResponse(status_code=401, content={"error": "Invalid refresh token"})

    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token
    }
