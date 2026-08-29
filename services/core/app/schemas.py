"""Request/response shapes for the auth + admin API."""
from __future__ import annotations

from pydantic import BaseModel, Field


class LoginIn(BaseModel):
    username: str
    password: str
    otp: str | None = None


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str


class MeOut(BaseModel):
    username: str
    full_name: str
    role: str
    team: str
    grade: str
    capabilities: list[str]
    allowed_customer_ids: list[str]
    all_tenants: bool
    must_change_password: bool
    mfa_enrolled: bool


class UserCreateIn(BaseModel):
    username: str = Field(min_length=2, max_length=64)
    full_name: str = Field(min_length=1)
    email: str = ""
    phone: str = ""
    chat_handle: str = ""
    role: str
    team: str = ""
    grade: str = ""
    grants: list[str] = []
    allowed_customer_ids: list[str] = []
    temporary_password: str = Field(min_length=8)
    require_otp: bool = True


class UserUpdateIn(BaseModel):
    full_name: str | None = None
    email: str | None = None
    phone: str | None = None
    chat_handle: str | None = None
    role: str | None = None
    team: str | None = None
    grade: str | None = None
    grants: list[str] | None = None
    allowed_customer_ids: list[str] | None = None
    state: str | None = None          # active|disabled


class UserOut(BaseModel):
    id: int
    username: str
    full_name: str
    email: str
    phone: str
    chat_handle: str
    role: str
    team: str
    grade: str
    grants: list[str]
    allowed_customer_ids: list[str]
    all_tenants: bool
    state: str
    mfa_enrolled: bool
    last_login_at: str | None


class TenantCreateIn(BaseModel):
    id: str = Field(min_length=2, max_length=64)          # customer id (usually = SOAR label)
    name: str = Field(min_length=1)
    label: str = ""
    contact: str = ""
    phone: str = ""
    tier: str = ""
    modules: list[str] = []
    onboarded: str = ""


class TenantUpdateIn(BaseModel):
    name: str | None = None
    label: str | None = None
    contact: str | None = None
    phone: str | None = None
    tier: str | None = None
    modules: list[str] | None = None
    onboarded: str | None = None
    state: str | None = None          # active|archived


class TenantOut(BaseModel):
    id: str
    name: str
    label: str
    contact: str
    phone: str
    tier: str
    modules: list[str]
    onboarded: str
    state: str
