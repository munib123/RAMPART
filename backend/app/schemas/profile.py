"""Pydantic request models for profile / password / billing endpoints."""
from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field


class UpdateNameReq(BaseModel):
    name: str = Field(min_length=1, max_length=80)


class ChangePasswordReq(BaseModel):
    old_password: str
    new_password: str = Field(min_length=8, max_length=128)


class UpgradeReq(BaseModel):
    plan: str