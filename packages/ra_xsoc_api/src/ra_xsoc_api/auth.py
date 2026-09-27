from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from uuid import UUID, uuid4

from fastapi import Header, HTTPException, status

from ra_xsoc_engine.domain.enums import UserRole

@dataclass(frozen=True, slots=True)
class AuthenticatedUser:
    user_id: UUID
    username: str
    role: UserRole

def _token_map() -> dict[str, AuthenticatedUser]:
    raw = os.getenv("RA_XSOC_AUTH_TOKENS", "")
    result: dict[str, AuthenticatedUser] = {}
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        parts = item.split(":", 3)
        if len(parts) != 4:
            continue
        token, user_id, username, role = parts
        try:
            result[token] = AuthenticatedUser(UUID(user_id), username, UserRole(role))
        except (ValueError, KeyError):
            continue
    return result

def get_current_user(authorization: str | None = Header(default=None)) -> AuthenticatedUser:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.")
    token = authorization.removeprefix("Bearer ").strip()
    # Constant-time token lookup over configured credentials.
    for configured, user in _token_map().items():
        if hmac.compare_digest(token, configured):
            return user
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token.")

def require_roles(*roles: UserRole):
    def dependency(user: AuthenticatedUser = __import__("fastapi").Depends(get_current_user)) -> AuthenticatedUser:
        if user.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role permissions.")
        return user
    return dependency
