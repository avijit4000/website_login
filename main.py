from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated
from uuid import uuid4

import jwt
from authlib.integrations.starlette_client import OAuth
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from pwdlib import PasswordHash
from pydantic import BaseModel, EmailStr, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import Boolean, DateTime, ForeignKey, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker
from starlette.middleware.sessions import SessionMiddleware


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "FastAPI Auth API"
    secret_key: str = "change-this-secret-in-production"
    database_url: str = "sqlite:///./auth.db"
    access_token_minutes: int = 30
    reset_token_minutes: int = 30
    session_secret: str = "change-this-session-secret-in-production"
    debug: bool = False
    google_client_id: str = ""
    google_client_secret: str = ""
    google_redirect_uri: str = "http://localhost:8000/auth/google/callback"


settings = Settings()


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    google_sub: Mapped[str | None] = mapped_column(String(255), unique=True, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    reset_tokens: Mapped[list[PasswordResetToken]] = relationship(back_populates="user", cascade="all, delete-orphan")


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"

    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    user: Mapped[User] = relationship(back_populates="reset_tokens")


connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
Base.metadata.create_all(engine)

password_context = PasswordHash.recommended()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
oauth = OAuth()
if settings.google_client_id and settings.google_client_secret:
    oauth.register(
        name="google",
        client_id=settings.google_client_id,
        client_secret=settings.google_client_secret,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )

app = FastAPI(title=settings.app_name)
app.add_middleware(SessionMiddleware, secret_key=settings.session_secret)


class UserResponse(BaseModel):
    id: int
    email: EmailStr
    is_active: bool


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=20)
    new_password: str = Field(min_length=8, max_length=128)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def user_response(user: User) -> UserResponse:
    return UserResponse(id=user.id, email=user.email, is_active=user.is_active)


def hash_reset_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_access_token(user: User) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "jti": uuid4().hex,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_minutes),
    }
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")


def issue_token_response(user: User) -> TokenResponse:
    return TokenResponse(access_token=create_access_token(user), user=user_response(user))


def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    credentials_error = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
        if payload.get("type") != "access":
            raise credentials_error
        jti = payload.get("jti")
        user_id = int(payload["sub"])
    except (jwt.PyJWTError, KeyError, TypeError, ValueError) as exc:
        raise credentials_error from exc

    if db.get(RevokedToken, jti):
        raise credentials_error
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise credentials_error
    return user


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/auth/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(data: RegisterRequest, db: Annotated[Session, Depends(get_db)]) -> TokenResponse:
    email = data.email.lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email is already registered")
    user = User(email=email, password_hash=password_context.hash(data.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return issue_token_response(user)


@app.post("/auth/login", response_model=TokenResponse)
def login(data: LoginRequest, db: Annotated[Session, Depends(get_db)]) -> TokenResponse:
    user = db.scalar(select(User).where(User.email == data.email.lower()))
    if user is None or user.password_hash is None or not password_context.verify(data.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is inactive")
    return issue_token_response(user)


@app.post("/auth/logout")
def logout(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, str]:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
        expires_at = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        db.merge(RevokedToken(jti=payload["jti"], expires_at=expires_at))
        db.commit()
    except (jwt.PyJWTError, KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc
    return {"message": "Logged out successfully"}


@app.get("/auth/me", response_model=UserResponse)
def me(current_user: Annotated[User, Depends(get_current_user)]) -> UserResponse:
    return user_response(current_user)


@app.get("/auth/google/login", name="google_login")
async def google_login(request: Request):
    if not settings.google_client_id or not settings.google_client_secret:
        raise HTTPException(status_code=503, detail="Google OAuth is not configured")
    redirect_uri = settings.google_redirect_uri or str(request.url_for("google_callback"))
    return await oauth.google.authorize_redirect(request, redirect_uri)


@app.get("/auth/google/callback", name="google_callback", response_model=TokenResponse)
async def google_callback(request: Request, db: Annotated[Session, Depends(get_db)]) -> TokenResponse:
    if not settings.google_client_id or not settings.google_client_secret:
        raise HTTPException(status_code=503, detail="Google OAuth is not configured")
    try:
        token = await oauth.google.authorize_access_token(request)
        profile = token.get("userinfo")
        if not profile or not profile.get("email") or not profile.get("sub"):
            raise ValueError("Google did not return a usable profile")
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Google authentication failed") from exc

    email = str(profile["email"]).lower()
    user = db.scalar(select(User).where(User.email == email))
    if user is None:
        user = User(email=email, google_sub=str(profile["sub"]))
        db.add(user)
    elif user.google_sub is None:
        user.google_sub = str(profile["sub"])
    db.commit()
    db.refresh(user)
    return issue_token_response(user)


@app.post("/auth/forgot-password")
def forgot_password(data: ForgotPasswordRequest, db: Annotated[Session, Depends(get_db)]) -> dict[str, str]:
    user = db.scalar(select(User).where(User.email == data.email.lower()))
    response = {"message": "If that email exists, a reset link has been created"}
    if user is None:
        return response

    raw_token = secrets.token_urlsafe(32)
    reset_token = PasswordResetToken(
        token_hash=hash_reset_token(raw_token),
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=settings.reset_token_minutes),
    )
    db.add(reset_token)
    db.commit()
    if settings.debug:
        response["reset_token"] = raw_token
    return response


@app.post("/auth/reset-password")
def reset_password(data: ResetPasswordRequest, db: Annotated[Session, Depends(get_db)]) -> dict[str, str]:
    reset_token = db.get(PasswordResetToken, hash_reset_token(data.token))
    now = datetime.now(timezone.utc)
    if reset_token is None or reset_token.used or reset_token.expires_at < now:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    reset_token.user.password_hash = password_context.hash(data.new_password)
    reset_token.used = True
    db.commit()
    return {"message": "Password reset successfully"}