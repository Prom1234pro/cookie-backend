from fastapi import FastAPI, Depends, HTTPException, status, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta
import jwt
import os

app = FastAPI()

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-super-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

ALLOWED_ORIGINS = [
    "https://cookie-frontend-pi.vercel.app",
    "http://localhost:5173", # For local development
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class LoginData(BaseModel):
    username: str
    password: str

# Dummy user database
users_db = {
    "user1": {
        "username": "user1",
        "password": "password123", # In production, use hashed passwords!
        "id": 1
    }
}

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication credentials")
        if username not in users_db:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        return users_db[username]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")


@app.post("/login")
async def login(response: Response, login_data: LoginData):
    # Verify user
    user = users_db.get(login_data.username)
    if not user or user["password"] != login_data.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    
    # Create JWT
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    
    # Cookie Configuration (MANDATORY)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,          # MUST be True for SameSite="none"
        samesite="none",      # Required for cross-site cookies
        max_age=60 * 60 * 24 * 7, # 7 days in seconds
        path="/"
    )
    
    return {"message": "Successfully logged in", "user": {"username": user["username"], "id": user["id"]}}


@app.get("/me")
async def read_users_me(current_user: dict = Depends(get_current_user)):
    # Returns the current user info if the cookie is valid
    return {
        "username": current_user["username"],
        "id": current_user["id"]
    }


@app.post("/logout")
async def logout(response: Response):
    # Clear the cookie
    response.delete_cookie(
        key="access_token",
        httponly=True,
        secure=True,          # Secure and SameSite are needed when deleting cross-domain cookies too
        samesite="none",
        path="/"
    )
    return {"message": "Successfully logged out"}
