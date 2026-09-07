"""Strict deterministic verification configuration."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Mapping

import yaml

from carry2pc.canonical import stable_hash
from carry2pc.modelcheck import Mutant
from carry2pc.schemas import stable_command_id


class ConfigError(ValueError):
    pass


MAX_CONFIG_BYTES = 1_048_576


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: yaml.nodes.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise ConfigError("configuration keys must be scalar") from exc
        if duplicate:
            raise ConfigError(f"duplicate configuration key: {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _strict_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ConfigError(f"{label} must be a non-empty trimmed string")
    return value


def _strict_integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ConfigError(f"{label} must be an integer >= {minimum}")
    return value


def _strict_boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{label} must be a boolean")
    return value


def _validate_json_text(value: Any, label: str) -> str:
    text = _strict_string(value, label)

    def reject_constant(constant: str) -> None:
        raise ValueError(f"non-standard numeric constant {constant!r}")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}")
            result[key] = item
        return result

    try:
        json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise ConfigError(f"{label} must contain standard JSON: {exc}") from exc
    return text


@dataclass(frozen=True)
class ScenarioConfig:
    twin_id: str
    tx_id: str
    source: str
    target: str
    initial_value_json: str
    intent_value_json: str
    command_payload_json: str

    @property
    def command_id(self) -> str:
        return stable_command_id(self.twin_id, self.tx_id, 0)


@dataclass(frozen=True)
class BoundsConfig:
    max_depth: int
    max_states: int
    decision_outcomes: tuple[str, ...]
    allow_resume: bool
    allow_duplicate_delivery: bool


@dataclass(frozen=True)
class VerificationConfig:
    schema_version: int
    scenario: ScenarioConfig
    bounds: BoundsConfig
    mutants: tuple[Mutant, ...]

    @property
    def digest(self) -> str:
        return stable_hash("carry2pc.verification_config.v1", self)


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ConfigError(f"{label} must be a mapping")
    return value


def _exact_keys(mapping: Mapping[str, Any], allowed: set[str], label: str) -> None:
    unknown = set(mapping) - allowed
    missing = allowed - set(mapping)
    if unknown:
        raise ConfigError(f"unknown {label} fields: {sorted(unknown)}")
    if missing:
        raise ConfigError(f"missing {label} fields: {sorted(missing)}")


def load_config(path: str | Path) -> VerificationConfig:
    config_path = Path(path)
    try:
        encoded = config_path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"unable to read config: {config_path}") from exc
    if len(encoded) > MAX_CONFIG_BYTES:
        raise ConfigError(f"configuration exceeds {MAX_CONFIG_BYTES} bytes")
    try:
        text = encoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigError(f"configuration is not UTF-8: {config_path}") from exc
    try:
        raw = yaml.load(text, Loader=_UniqueKeyLoader)
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML: {config_path}") from exc
    root = _mapping(raw, "config")
    _exact_keys(root, {"schema_version", "scenario", "bounds", "mutants"}, "config")
    if _strict_integer(root["schema_version"], "schema_version", minimum=1) != 1:
        raise ConfigError("schema_version must be 1")

    scenario_raw = _mapping(root["scenario"], "scenario")
    scenario_fields = (
        "twin_id",
        "tx_id",
        "source",
        "target",
        "initial_value_json",
        "intent_value_json",
        "command_payload_json",
    )
    _exact_keys(scenario_raw, set(scenario_fields), "scenario")
    scenario = ScenarioConfig(
        twin_id=_strict_string(scenario_raw["twin_id"], "scenario.twin_id"),
        tx_id=_strict_string(scenario_raw["tx_id"], "scenario.tx_id"),
        source=_strict_string(scenario_raw["source"], "scenario.source"),
        target=_strict_string(scenario_raw["target"], "scenario.target"),
        initial_value_json=_validate_json_text(
            scenario_raw["initial_value_json"], "scenario.initial_value_json"
        ),
        intent_value_json=_validate_json_text(
            scenario_raw["intent_value_json"], "scenario.intent_value_json"
        ),
        command_payload_json=_validate_json_text(
            scenario_raw["command_payload_json"], "scenario.command_payload_json"
        ),
    )
    if scenario.source == scenario.target:
        raise ConfigError("source and target must differ")

    bounds_raw = _mapping(root["bounds"], "bounds")
    bounds_fields = {
        "max_depth",
        "max_states",
        "decision_outcomes",
        "allow_resume",
        "allow_duplicate_delivery",
    }
    _exact_keys(bounds_raw, bounds_fields, "bounds")
    if not isinstance(bounds_raw["decision_outcomes"], list):
        raise ConfigError("bounds.decision_outcomes must be a list")
    decision_outcomes = tuple(
        _strict_string(item, f"bounds.decision_outcomes[{index}]")
        for index, item in enumerate(bounds_raw["decision_outcomes"])
    )
    if not decision_outcomes or not set(decision_outcomes).issubset(
        {"commit", "abort"}
    ):
        raise ConfigError("decision_outcomes must contain commit and/or abort")
    if len(set(decision_outcomes)) != len(decision_outcomes):
        raise ConfigError("decision_outcomes must be unique")
    bounds = BoundsConfig(
        max_depth=_strict_integer(
            bounds_raw["max_depth"], "bounds.max_depth", minimum=1
        ),
        max_states=_strict_integer(
            bounds_raw["max_states"], "bounds.max_states", minimum=1
        ),
        decision_outcomes=decision_outcomes,
        allow_resume=_strict_boolean(bounds_raw["allow_resume"], "bounds.allow_resume"),
        allow_duplicate_delivery=_strict_boolean(
            bounds_raw["allow_duplicate_delivery"],
            "bounds.allow_duplicate_delivery",
        ),
    )

    if not isinstance(root["mutants"], list):
        raise ConfigError("mutants must be a list")
    try:
        mutants = tuple(
            Mutant(_strict_string(item, f"mutants[{index}]"))
            for index, item in enumerate(root["mutants"])
        )
    except ValueError as exc:
        raise ConfigError(f"unknown mutant: {exc}") from exc
    expected_mutants = tuple(Mutant)
    if mutants != expected_mutants:
        raise ConfigError(
            "mutants must list every registered variant once in canonical order: "
            + ", ".join(item.value for item in expected_mutants)
        )
    return VerificationConfig(
        schema_version=1,
        scenario=scenario,
        bounds=bounds,
        mutants=mutants,
    )
