from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from oauth_config import oauth, register_client
from urllib.parse import urlencode
from json import dumps, loads
from urllib.parse import urlencode
import json

# Pre-configured client credentials
CLIENT_CREDENTIALS = {
    'service_a': {
        'google': {
            'client_id': 'YOUR_GOOGLE_CLIENT_ID_FOR_SERVICE_A',
            'client_secret': 'YOUR_GOOGLE_CLIENT_SECRET_FOR_SERVICE_A'
        },
        'facebook': {
            'client_id': 'YOUR_FACEBOOK_CLIENT_ID_FOR_SERVICE_A',
            'client_secret': 'YOUR_FACEBOOK_CLIENT_SECRET_FOR_SERVICE_A'
        },
        'github': {
            'client_id': 'YOUR_GITHUB_CLIENT_ID_FOR_SERVICE_A',
            'client_secret': 'YOUR_GITHUB_CLIENT_SECRET_FOR_SERVICE_A'
        }
    }
}

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="your-secret")

templates = Jinja2Templates(directory="templates")

@app.get("/authenticate/{client_service}", response_class=HTMLResponse)
async def authenticate(request: Request, client_service: str):
    # Check if the client service is valid
    if client_service not in CLIENT_CREDENTIALS:
        return JSONResponse(status_code=400, content={"error": "Invalid client service"})

    # Get credentials for the client service
    client_data = CLIENT_CREDENTIALS[client_service]

    # Save client service info in session for callback use
    request.session["client_service"] = client_service
    request.session["client_callback"] = request.query_params.get('client_callback')
    
    # Register OAuth clients dynamically for each provider (Google, Facebook, GitHub)
    for provider, creds in CLIENT_CREDENTIALS[client_service].items():
        if provider == "google":
            register_client(
                service_name="google",
                client_id=creds['client_id'],
                client_secret=creds['client_secret'],
                server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
                client_kwargs={
                    "scope": "openid email profile",
                    "access_type": "offline",    # request offline access (for refresh token)
                    "prompt": "consent"          # force consent so refresh token is returned
                }
            )
        else:
            # For example, for Facebook or GitHub – adjust URLs accordingly.
            register_client(
                service_name=provider,
                client_id=creds['client_id'],
                client_secret=creds['client_secret'],
                authorize_url=f"https://{provider}.com/oauth/authorize",
                access_token_url=f"https://{provider}.com/oauth/access_token",
                api_base_url="",
                client_kwargs={"scope": "email"}
            )

    # List login options dynamically based on client service
    login_urls = {provider: f"/login/{provider}" for provider in client_data}

    return templates.TemplateResponse("login.html", {
        "request": request,
        "login_urls": login_urls,
        "client_service": client_service
    })

@app.get("/login/{provider}")
async def login(request: Request, provider: str):
    # Retrieve the client_callback from session (set on /authenticate)
    client_callback = request.session.get("client_callback")
    if not client_callback:
        return JSONResponse(status_code=400, content={"error": "Missing client callback in session"})

    # Prepare the state as a JSON string
    state = dumps({"client_callback": client_callback})
    
    # Build the redirect URI for OAuth callback in Service B (e.g. /auth/callback/google)
    redirect_uri = request.url_for("auth_callback", provider=provider)
    
    return await oauth.create_client(provider).authorize_redirect(
        request, redirect_uri, state=state
    )

@app.get("/auth/callback/{provider}")
async def auth_callback(request: Request, provider: str):
    client_service = request.session.get("client_service")
    if not client_service:
        return JSONResponse(status_code=400, content={"error": "Client service not found in session"})

    client = oauth.create_client(provider)
    token = await client.authorize_access_token(request)
    
    # Use userinfo() to fetch user details based on metadata.
    user = await client.userinfo(token=token)
    
    # Retrieve state from the OAuth flow
    state_str = request.query_params.get("state")
    if not state_str:
        return JSONResponse(status_code=400, content={"error": "Missing state parameter"})
    
    try:
        state = json.loads(state_str)
    except Exception:
        state = {}
    
    client_callback = state.get("client_callback")
    if not client_callback:
        return JSONResponse(status_code=400, content={"error": "Missing client callback in state"})

    # Build the redirect URL with tokens in the query params (for Service A to pick up)
    redirect_with_token = (
        f"{client_callback}?"
        + urlencode({
            'access_token': token.get('access_token'),
            'refresh_token': token.get('refresh_token', ''),
            'name': user.get('name'),
            'email': user.get('email')
        })
    )
    return RedirectResponse(redirect_with_token)

