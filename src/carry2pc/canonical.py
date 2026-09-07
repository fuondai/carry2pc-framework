"""Canonical serialization and domain-separated hashing."""

from __future__ import annotations

from dataclasses import fields, is_dataclass
from enum import Enum
import hashlib
import json
from typing import Any, Mapping


def canonical_data(value: Any) -> Any:
    if is_dataclass(value):
        return {
            field.name: canonical_data(getattr(value, field.name))
            for field in fields(value)
        }
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {
            str(key): canonical_data(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (tuple, list)):
        return [canonical_data(item) for item in value]
    if isinstance(value, (set, frozenset)):
        normalized = [canonical_data(item) for item in value]
        return sorted(normalized, key=canonical_json)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise TypeError(f"unsupported canonical value: {type(value).__name__}")


def canonical_json(value: Any) -> str:
    return json.dumps(
        canonical_data(value),
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def stable_hash(domain: str, value: Any) -> str:
    if not domain:
        raise ValueError("hash domain must not be empty")
    envelope = {"domain": domain, "value": canonical_data(value)}
    return hashlib.sha256(canonical_json(envelope).encode("utf-8")).hexdigest()
