from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from ..config import settings
from ..services.admin_auth import (
    create_admin_token,
    require_admin,
    verify_admin_password,
    verify_totp,
)

router = APIRouter(prefix="/api/admin/auth", tags=["admin-auth"])


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=500)
    totp_code: str | None = Field(default=None, max_length=16)


@router.post("/login")
def admin_login(data: LoginRequest):
    if not settings.admin_auth_enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin auth is disabled")

    # Hard fail when no credential is configured.
    if not settings.admin_password_hash:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin credentials are not configured",
        )

    if data.username != settings.admin_username or not verify_admin_password(data.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    mfa_enabled = bool(settings.admin_totp_secret)
    mfa_verified = False
    if mfa_enabled:
        if not verify_totp(settings.admin_totp_secret, data.totp_code or ""):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA code")
        mfa_verified = True

    token = create_admin_token(username=data.username, mfa_verified=mfa_verified)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": max(1, settings.admin_token_ttl_minutes) * 60,
        "user": {
            "username": data.username,
            "role": "admin",
            "mfa_enabled": mfa_enabled,
            "mfa_verified": mfa_verified,
        },
    }


@router.get("/me")
def admin_me(claims: dict = Depends(require_admin)):
    return {
        "username": claims.get("sub"),
        "role": claims.get("role"),
        "mfa_verified": bool(claims.get("mfa")),
    }
