

import os
from fastapi import FastAPI, Request, Depends
from fastapi.responses import RedirectResponse, HTMLResponse
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
from typing import Dict, Any

import os
from dotenv import load_dotenv

load_dotenv()

COGNITO_DOMAIN = os.environ.get("COGNITO_DOMAIN")
APP_CLIENT_ID = os.environ.get("APP_CLIENT_ID")
USER_POOL_ID = os.environ.get("USER_POOL_ID")
AWS_REGION = os.environ.get("AWS_REGION")
CLIENT_SECRET = os.environ.get("client_secret")
# --- FastAPI App Initialization ---
app = FastAPI()

# Add session middleware to store the user's login state in a secure cookie.
# IMPORTANT: Use a strong, randomly generated secret key in a real application.
app.add_middleware(SessionMiddleware, secret_key=os.urandom(24))

# --- Authlib OAuth Client Setup ---
oauth = OAuth()

oauth.register(
  name='cognito',
  authority='https://cognito-idp.eu-north-1.amazonaws.com/eu-north-1_IQDEBSH0v',
  client_id= APP_CLIENT_ID,
  client_secret= CLIENT_SECRET,
  server_metadata_url='https://cognito-idp.eu-north-1.amazonaws.com/eu-north-1_IQDEBSH0v/.well-known/openid-configuration',
  client_kwargs={'scope': 'email openid phone'}
)

# --- Dependency ---
def get_current_user(request: Request) -> Dict[str, Any] | None:
    """
    Dependency to get the current user from the session.
    Returns the user dictionary if logged in, otherwise None.
    """
    return request.session.get('user')

# --- API Endpoints ---
@app.get("/", response_class=HTMLResponse)
async def homepage(user: Dict[str, Any] = Depends(get_current_user)):
    """
    Displays the user's email and details if they are logged in,
    otherwise, it shows a "Login" link.
    """
    if user:
        return f"""
        <h1>Hello, {user['email']}!</h1>
        <p>You are logged in. Here is your user information:</p>
        <pre>{user}</pre>
        <a href="/logout">Logout</a>
        """
    return '<h1>Welcome!</h1><p>You are not logged in.</p><a href="/login">Login</a>'

@app.get('/login')
async def login(request: Request):
    """
    This endpoint initiates the login process by redirecting the
    user to the Cognito Hosted UI.
    """
    # The URL that Cognito will redirect back to after login
    redirect_uri = request.url_for('auth')
    return await oauth.cognito.authorize_redirect(request, redirect_uri)

@app.get('/auth')
async def auth(request: Request):
    """
    This is the callback endpoint. Cognito redirects here after a
    successful login. The code exchanges the authorization token
    for an access token and stores the user info in the session.
    """
    token = await oauth.cognito.authorize_access_token(request)
    request.session['user'] = token['userinfo'] # OIDC-compliant user info
    return RedirectResponse(url='/')

@app.get('/logout')
async def logout(request: Request):
    """
    Logs the user out by clearing the session cookie and redirecting
    to the homepage.
    """
    request.session.pop('user', None)
    return RedirectResponse(url='/')