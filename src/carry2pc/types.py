"""Shared protocol enums."""

from __future__ import annotations

from enum import Enum


class Decision(str, Enum):
    COMMIT = "commit"
    ABORT = "abort"


class OwnerMode(str, Enum):
    ACTIVE = "active"
    FROZEN = "frozen"
    STAGING = "staging"
    FENCED = "fenced"
    DISCARDED = "discarded"


class OutboxStatus(str, Enum):
    PENDING = "pending"
    ACKNOWLEDGED = "acknowledged"
