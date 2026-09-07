"""Bounded verification orchestration and result export."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from time import perf_counter
from typing import Any

from carry2pc.canonical import canonical_data
from carry2pc.config import VerificationConfig
from carry2pc.modelcheck import Invariant, Mutant, explore


EXPECTED_MUTANT_INVARIANT = {
    Mutant.OMIT_OBLIGATION_ON_INSTALL: Invariant.OBLIGATION_PERSISTENCE,
    Mutant.DUAL_ACTIVE_ON_ACTIVATE: Invariant.OWNERSHIP_UNIQUENESS,
    Mutant.EPOCH_GUARD_CONVERTS_COMMIT_TO_ABORT: Invariant.DECISION_CONSISTENCY,
    Mutant.REWRITE_INTENT_ON_INSTALL: Invariant.INTENT_FIDELITY,
    Mutant.DUPLICATE_OUTBOX_ENQUEUE: Invariant.DURABLE_ENQUEUE_INTEGRITY,
}


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(canonical_data(payload), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def check_expected_vector(summary: dict[str, object], path: str | Path) -> None:
    """Check deterministic semantic fields against a repository reference vector.

    Timestamps and runtimes are deliberately excluded from the vector.  This
    keeps the check useful across machines while still detecting changes to the
    explored graph, overlap witness, and mutant witnesses.
    """
    vector_path = Path(path)
    try:
        expected = json.loads(vector_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"unable to read expected vector: {vector_path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid expected vector: {vector_path}") from exc
    if not isinstance(expected, dict) or expected.get("schema_version") != 2:
        raise ValueError("expected vector schema_version must be 2")

    mismatches: list[str] = []

    def compare(label: str, actual: object, wanted: object) -> None:
        if isinstance(actual, tuple):
            actual = list(actual)
        if actual != wanted:
            mismatches.append(f"{label}: expected {wanted!r}, got {actual!r}")

    compare(
        "config_digest", summary.get("config_digest"), expected.get("config_digest")
    )
    compliant = summary.get("compliant")
    expected_compliant = expected.get("compliant")
    if not isinstance(compliant, dict) or not isinstance(expected_compliant, dict):
        raise ValueError("expected vector must contain a compliant mapping")
    for field in (
        "bounded_complete",
        "states_discovered",
        "protocol_states_discovered",
        "states_explored",
        "transitions_considered",
        "states_at_depth_cut",
        "max_states_reached",
    ):
        compare(
            f"compliant.{field}", compliant.get(field), expected_compliant.get(field)
        )
    overlap = compliant.get("true_overlap_witness")
    wanted_overlap = expected_compliant.get("true_overlap_actions")
    compare(
        "compliant.true_overlap_actions",
        overlap.get("actions") if isinstance(overlap, dict) else None,
        wanted_overlap,
    )
    compare(
        "compliant.true_overlap_state_sha256",
        overlap.get("state_sha256") if isinstance(overlap, dict) else None,
        expected_compliant.get("true_overlap_state_sha256"),
    )
    compare("compliant.violation_witness", compliant.get("violation_witness"), None)

    actual_mutants = {
        item.get("variant"): item
        for item in summary.get("mutants", [])
        if isinstance(item, dict)
    }
    expected_mutants = expected.get("mutants")
    if not isinstance(expected_mutants, dict):
        raise ValueError("expected vector must contain a mutants mapping")
    for variant, wanted in expected_mutants.items():
        if not isinstance(wanted, dict):
            raise ValueError(f"expected vector mutant {variant!r} must be a mapping")
        actual = actual_mutants.get(variant)
        if not isinstance(actual, dict):
            mismatches.append(f"mutant {variant!r} missing from summary")
            continue
        for field in (
            "bounded_complete",
            "states_discovered",
            "protocol_states_discovered",
            "states_explored",
            "transitions_considered",
            "states_at_depth_cut",
            "max_states_reached",
            "expected_invariant",
        ):
            compare(f"mutants.{variant}.{field}", actual.get(field), wanted.get(field))
        witness = actual.get("violation_witness")
        compare(
            f"mutants.{variant}.witness_actions",
            witness.get("actions") if isinstance(witness, dict) else None,
            wanted.get("witness_actions"),
        )
        compare(
            f"mutants.{variant}.witness_state_sha256",
            witness.get("state_sha256") if isinstance(witness, dict) else None,
            wanted.get("witness_state_sha256"),
        )
    if mismatches:
        raise ValueError("expected vector mismatch:\n" + "\n".join(mismatches))


def _explore_config(
    config: VerificationConfig, mutant: Mutant | None
) -> dict[str, object]:
    scenario = config.scenario
    bounds = config.bounds
    started = perf_counter()
    result = explore(
        source=scenario.source,
        target=scenario.target,
        initial_value=scenario.initial_value_json,
        intent_value=scenario.intent_value_json,
        twin_id=scenario.twin_id,
        tx_id=scenario.tx_id,
        command_id=scenario.command_id,
        command_index=0,
        command_payload=scenario.command_payload_json,
        max_depth=bounds.max_depth,
        max_states=bounds.max_states,
        decision_outcomes=bounds.decision_outcomes,
        allow_resume=bounds.allow_resume,
        allow_duplicate_delivery=bounds.allow_duplicate_delivery,
        mutant=mutant,
    )
    result["runtime_seconds"] = round(perf_counter() - started, 9)
    return result


def run_verification(
    config: VerificationConfig, output_dir: str | Path
) -> dict[str, object]:
    output = Path(output_dir)
    started_at = datetime.now(timezone.utc)
    suite_started = perf_counter()

    compliant = _explore_config(config, None)
    _write_json(output / "compliant.json", compliant)
    mutant_results: list[dict[str, object]] = []
    gates: list[dict[str, object]] = []

    compliant_gate = (
        compliant["bounded_complete"] is True
        and compliant["violation_witness"] is None
        and compliant["true_overlap_witness"] is not None
    )
    gates.append(
        {
            "gate": "compliant_bounded_safety_and_true_overlap",
            "passed": compliant_gate,
        }
    )

    for mutant in config.mutants:
        result = _explore_config(config, mutant)
        witness = result["violation_witness"]
        expected = EXPECTED_MUTANT_INVARIANT[mutant].value
        witnessed = (
            result["bounded_complete"] is True
            and isinstance(witness, dict)
            and expected in witness["violated_invariants"]
        )
        result["expected_invariant"] = expected
        result["expected_witness_found"] = witnessed
        mutant_results.append(result)
        _write_json(output / f"mutant_{mutant.value}.json", result)
        gates.append(
            {
                "gate": f"mutant_witness:{mutant.value}",
                "expected_invariant": expected,
                "passed": witnessed,
            }
        )

    finished_at = datetime.now(timezone.utc)
    summary: dict[str, object] = {
        "artifact_class": "bounded_state_exploration",
        "schema_version": 1,
        "config_digest": config.digest,
        "config": canonical_data(config),
        "started_at_utc": started_at.isoformat(),
        "finished_at_utc": finished_at.isoformat(),
        "runtime_seconds": round(perf_counter() - suite_started, 9),
        "compliant": {
            "states_discovered": compliant["states_discovered"],
            "protocol_states_discovered": compliant["protocol_states_discovered"],
            "states_explored": compliant["states_explored"],
            "transitions_considered": compliant["transitions_considered"],
            "bounded_complete": compliant["bounded_complete"],
            "max_states_reached": compliant["max_states_reached"],
            "states_at_depth_cut": compliant["states_at_depth_cut"],
            "violation_witness": compliant["violation_witness"],
            "true_overlap_witness": compliant["true_overlap_witness"],
        },
        "mutants": [
            {
                "variant": result["variant"],
                "states_discovered": result["states_discovered"],
                "protocol_states_discovered": result["protocol_states_discovered"],
                "states_explored": result["states_explored"],
                "transitions_considered": result["transitions_considered"],
                "bounded_complete": result["bounded_complete"],
                "max_states_reached": result["max_states_reached"],
                "states_at_depth_cut": result["states_at_depth_cut"],
                "expected_invariant": result["expected_invariant"],
                "violation_witness": result["violation_witness"],
            }
            for result in mutant_results
        ],
        "gates": gates,
        "passed": all(bool(gate["passed"]) for gate in gates),
    }
    _write_json(output / "summary.json", summary)
    return summary
