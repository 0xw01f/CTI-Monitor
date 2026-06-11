import base64
import hashlib
import hmac
import json
import os
import struct
import time
from typing import Any

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ..config import settings

_bearer = HTTPBearer(auto_error=False)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(raw: str) -> bytes:
    pad = "=" * ((4 - len(raw) % 4) % 4)
    return base64.urlsafe_b64decode(raw + pad)


def _effective_token_secret() -> str:
    secret = settings.admin_token_secret
    if not secret:
        raise RuntimeError(
            "ADMIN_TOKEN_SECRET is not configured. Set a strong random secret in your .env before starting the server."
        )
    return secret


def _scrypt_verify(password: str, encoded: str) -> bool:
    """
    Verify format:
      scrypt$N$r$p$<salt_b64>$<dk_b64>
    """
    try:
        algo, n_raw, r_raw, p_raw, salt_b64, dk_b64 = encoded.split("$", 5)
        if algo != "scrypt":
            return False
        n = int(n_raw)
        r = int(r_raw)
        p = int(p_raw)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        got = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=len(expected),
        )
        return hmac.compare_digest(got, expected)
    except Exception:
        return False


def hash_password_scrypt(password: str, n: int = 2**14, r: int = 8, p: int = 1) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32)
    return f"scrypt${n}${r}${p}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_admin_password(password: str) -> bool:
    if settings.admin_password_hash:
        return _scrypt_verify(password, settings.admin_password_hash)
    return False


def _totp_code(secret_b32: str, timestep: int) -> str:
    key = base64.b32decode(secret_b32.strip().upper(), casefold=True)
    msg = struct.pack(">Q", timestep)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{code_int % 1_000_000:06d}"


def verify_totp(secret_b32: str, code: str, window: int = 1) -> bool:
    if not secret_b32:
        return True
    if not (code and code.isdigit()):
        return False
    now_step = int(time.time()) // 30
    for shift in range(-window, window + 1):
        if hmac.compare_digest(_totp_code(secret_b32, now_step + shift), code):
            return True
    return False


def create_admin_token(username: str, mfa_verified: bool) -> str:
    now = int(time.time())
    exp = now + max(1, settings.admin_token_ttl_minutes) * 60
    payload: dict[str, Any] = {
        "sub": username,
        "role": "admin",
        "iat": now,
        "exp": exp,
        "mfa": bool(mfa_verified),
    }
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = hmac.new(
        _effective_token_secret().encode("utf-8"),
        payload_b64.encode("ascii"),
        hashlib.sha256,
    ).digest()
    return f"adm1.{payload_b64}.{_b64url_encode(sig)}"


def decode_admin_token(token: str) -> dict[str, Any]:
    try:
        prefix, payload_b64, sig_b64 = token.split(".", 2)
        if prefix != "adm1":
            raise ValueError("bad prefix")
        expected_sig = hmac.new(
            _effective_token_secret().encode("utf-8"),
            payload_b64.encode("ascii"),
            hashlib.sha256,
        ).digest()
        got_sig = _b64url_decode(sig_b64)
        if not hmac.compare_digest(expected_sig, got_sig):
            raise ValueError("bad signature")
        payload = json.loads(_b64url_decode(payload_b64))
        if int(payload.get("exp", 0)) < int(time.time()):
            raise ValueError("expired")
        if payload.get("role") != "admin":
            raise ValueError("bad role")
        return payload
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired admin token",
        ) from exc


def require_admin(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict[str, Any]:
    if not settings.admin_auth_enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin auth is disabled")
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing admin token")
    return decode_admin_token(credentials.credentials)


def get_optional_admin(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict[str, Any] | None:
    if not settings.admin_auth_enabled:
        return None
    if not credentials:
        return None
    if credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid auth scheme")
    return decode_admin_token(credentials.credentials)
